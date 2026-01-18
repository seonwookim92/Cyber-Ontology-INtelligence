"""
FastAPI Server for File Language Detection
Provides REST API endpoints for file upload and language detection.
Supports MCP through fastapi-mcp integration.
"""
import os
# API Configuration
OPENAI_API_KEY = os.environ['OPENAI_API_KEY'] if 'OPENAI_API_KEY' in os.environ else ""
CUSTOM_AI_ENDPOINT = ""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import uuid

import shutil
import json
import asyncio
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from detector import LanguageDetector
import iocsearcher
from iocsearcher.searcher import Searcher

# Import binary classifier for threat actor analysis
import sys
BINARY_DIR = Path(__file__).parent / "Binary"
sys.path.insert(0, str(BINARY_DIR))
from binary_classifier import classify_binary

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("⚠ openai package not installed. AI-powered deobfuscation will be disabled.")

# Initialize FastAPI app
app = FastAPI(
    title="File Language Detector API",
    description="API for detecting programming language of binary and script files",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create temp directory for uploaded files
TEMP_DIR = Path("temp")
TEMP_DIR.mkdir(exist_ok=True)

# Store file metadata
file_metadata: Dict[str, Dict] = {}

# Initialize detector
detector = LanguageDetector()


def call_ai_api(prompt: str, code: str) -> str:
    """Call AI API with prompt and code"""
    if not OPENAI_AVAILABLE:
        return ""

    try:
        if CUSTOM_AI_ENDPOINT:
            client = OpenAI(api_key="dummy", base_url=CUSTOM_AI_ENDPOINT)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a code analysis assistant."},
                    {"role": "user", "content": f"{prompt}\n\n{code}"}
                ]
            )
            return response.choices[0].message.content
        elif OPENAI_API_KEY:
            client = OpenAI(api_key=OPENAI_API_KEY)
            response = client.chat.completions.create(
                model="o4-mini",
                messages=[
                    {"role": "system", "content": "You are a code analysis assistant."},
                    {"role": "user", "content": f"{prompt}\n\n{code}"}
                ]
            )
            return response.choices[0].message.content
        else:
            return ""
    except Exception as e:
        print(f"AI API error: {e}")
        return ""


def compare_codes_with_ai(code1: str, code2: str) -> str:
    """Compare two codes and return which is better (1 or 2)"""
    prompt = "주어진 두개의 코드를 비교하여, 어떤 코드가 더 정보가 유실되지 않는 코드인지 얘기해주세요. 답변은 숫자로 앞에서부터 1, 2로 매겨서 알려주시고 그 이외 설명은 불허합니다."
    combined = f"Code 1:\n{code1}\n\nCode 2:\n{code2}"

    result = call_ai_api(prompt, combined)

    # Parse result - prefer option 2 (sed version) as default
    if "1" in result and "2" not in result:
        return "1"
    else:
        return "2"  # Default to 2 (sed version)


def refine_code_with_ai(code: str) -> str:
    """Refine code with AI"""
    prompt = "주어진 코드의 변수와 함수 이름을 더 이해하기 쉬운 이름으로 바꾸고, 불필요한 공백이나 주석을 제거하여 가독성을 높여주세요. 가능한 경우 코드 구조를 개선하여 논리적인 흐름을 명확히 해주세요. 최종 결과물은 원본 코드의 기능을 유지하면서도 읽기 쉽고 이해하기 쉽게 만들어주세요. 단, 정보의 보존이 코드 구조 개선보다 더 중요합니다. 답변은 코드로만 돌려주시고, 언어를 나타내는 마크다운 스타일의 백틱 표시는 하지 말아주세요. 이유는 주지 마세요."

    result = call_ai_api(prompt, code)
    return result if result else code


class FileIdRequest(BaseModel):
    """Request model for file_id based endpoints."""
    file_id: str
    language: Optional[str] = None


class FinalizeRequest(BaseModel):
    """Request model for finalize endpoint."""
    file_id: str
    type: str
    language: str
    ioc_list: Optional[Dict] = None
    threat_actor: Optional[str] = None
    threat_actor_probability: Optional[float] = None
    malware_family: Optional[str] = None
    malware_probability: Optional[float] = None


class DetectionResult(BaseModel):
    """Response model for detection results."""
    file_id: str
    filename: str
    detected_type: str
    detected_language: str
    category: str


class DeobfuscationResult(BaseModel):
    """Response model for deobfuscation results."""
    file_id: str
    filename: str
    original_code: str
    deobfuscated_code: str
    aggressively_deobfuscated_code: str
    aggressively_deobfuscated_code2: str
    ioc_list: Dict


class ThreatActorResult(BaseModel):
    """Response model for threat actor analysis."""
    file_id: str
    filename: str
    threat_actor: Optional[str] = None
    probability: float = 0.0
    apt_top3: Optional[List[Dict]] = []
    malware_family: Optional[str] = None
    malware_probability: float = 0.0
    malware_top3: Optional[List[Dict]] = []


class FinalResult(BaseModel):
    """Final result model."""
    file_id: str
    filename: str
    final_type: str
    final_language: str
    final_category: str
    ioc_list: Optional[Dict] = None
    threat_actor: Optional[str] = None
    threat_actor_probability: Optional[float] = None
    malware_family: Optional[str] = None
    malware_probability: Optional[float] = None


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "File Language Detector & Malware Analysis API",
        "endpoints": {
            "/upload": "POST - Upload a file for language detection",
            "/deobfuscate": "POST - Deobfuscate PowerShell/VBScript files",
            "/analyze-threat-actor": "POST - Analyze file for threat actor attribution",
            "/finalize": "POST - Finalize analysis with user confirmation",
            "/health": "GET - Health check"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/upload", response_model=DetectionResult)
async def upload_file(file: UploadFile = File(...)):
    """
    Upload a file for language detection.

    Args:
        file: The file to upload and analyze

    Returns:
        Detection result with file_id, detected type, and language
    """
    try:
        # Generate unique ID for this file
        file_id = str(uuid.uuid4())

        # Save file to temp directory
        file_path = TEMP_DIR / f"{file_id}_{file.filename}"
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Detect language
        detection = detector.detect(str(file_path))

        # Create category string
        category = f"{detection['type']} ({detection['language']})"

        # Store metadata
        file_metadata[file_id] = {
            "filename": file.filename,
            "file_path": str(file_path),
            "detected_type": detection['type'],
            "detected_language": detection['language'],
            "category": category
        }

        return DetectionResult(
            file_id=file_id,
            filename=file.filename,
            detected_type=detection['type'],
            detected_language=detection['language'],
            category=category
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")


@app.post("/deobfuscate", response_model=DeobfuscationResult)
async def deobfuscate_file(request: FileIdRequest):
    """
    Deobfuscate a VBScript or PowerShell file.

    Args:
        request: Contains file_id

    Returns:
        Deobfuscation result with original, deobfuscated, and aggressively deobfuscated code + IoC list
    """
    import time
    try:
        # Get file metadata
        if request.file_id not in file_metadata:
            raise HTTPException(status_code=404, detail="File not found")

        metadata = file_metadata[request.file_id]
        # Use user-selected language if provided, otherwise use detected language
        language = request.language if request.language else metadata["detected_language"]

        print(f"\n[DEBUG] ========== Deobfuscation Started ==========")
        print(f"[DEBUG] File ID: {request.file_id}")
        print(f"[DEBUG] File name: {metadata['filename']}")
        print(f"[DEBUG] Language: {language}")
        print(f"[DEBUG] Current time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        start_time = time.time()

        # Check if language supports deobfuscation
        if language not in ["PowerShell", "VBScript"]:
            raise HTTPException(status_code=400, detail=f"Deobfuscation not supported for {language}")

        # Read original file
        print(f"[DEBUG] Reading original file...")
        with open(metadata["file_path"], "r", encoding="utf-8", errors="ignore") as f:
            original_code = f.read()
        print(f"[DEBUG] Original file size: {len(original_code)} characters")

        # PowerShell deobfuscation - Real implementation
        if language == "PowerShell":
            try:
                print(f"[DEBUG] Starting PowerShell deobfuscation...")
                ps_start = time.time()

                # Create temporary directory
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_path = Path(temp_dir)

                    # Copy file twice
                    print(f"[DEBUG] Creating temporary files...")
                    file1 = temp_path / "original.ps1"
                    file2 = temp_path / "no_backtick.ps1"

                    shutil.copy(metadata["file_path"], file1)
                    shutil.copy(metadata["file_path"], file2)

                    # Remove backticks from second file using Python
                    print(f"[DEBUG] Removing backticks from second file...")
                    with open(file2, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    content = content.replace("`", "")
                    with open(file2, "w", encoding="utf-8", errors="ignore") as f:
                        f.write(content)

                    # Paths to PowerShell scripts
                    invoke_deobf_path = Path("Powershell/invoke-deobfuscation/Code/Invoke-DeObfuscation.psd1").absolute()
                    deobf_script_path = Path("Powershell/Deobfuscator.ps1").absolute()

                    # Run DeobfuscatedMain on both files
                    file1_deobf1 = temp_path / "original_deobf1.ps1"
                    file2_deobf1 = temp_path / "no_backtick_deobf1.ps1"

                    # Process file1 with Invoke-Deobfuscation
                    print(f"[DEBUG] Running Invoke-Deobfuscation on file1 (original)...")
                    step_start = time.time()
                    cmd1 = f"pwsh -Command \"Import-Module '{invoke_deobf_path}'; DeobfuscatedMain -scriptpath0 '{file1}' | Out-File -FilePath '{file1_deobf1}' -Encoding UTF8\""
                    subprocess.run(cmd1, shell=True, check=False, capture_output=True)
                    print(f"[DEBUG] ✓ Invoke-Deobfuscation (file1) completed in {time.time() - step_start:.2f}s")

                    # Process file2 with Invoke-Deobfuscation
                    print(f"[DEBUG] Running Invoke-Deobfuscation on file2 (no backtick)...")
                    step_start = time.time()
                    cmd2 = f"pwsh -Command \"Import-Module '{invoke_deobf_path}'; DeobfuscatedMain -scriptpath0 '{file2}' | Out-File -FilePath '{file2_deobf1}' -Encoding UTF8\""
                    subprocess.run(cmd2, shell=True, check=False, capture_output=True)
                    print(f"[DEBUG] ✓ Invoke-Deobfuscation (file2) completed in {time.time() - step_start:.2f}s")

                    # Run Deobfuscator.ps1 on both
                    # Process file1_deobf1
                    print(f"[DEBUG] Running Deobfuscator.ps1 on file1...")
                    step_start = time.time()
                    cmd3 = f"pwsh -Command \". '{deobf_script_path}'; deobfuscate-script -Filepath '{file1_deobf1}'\""
                    subprocess.run(cmd3, shell=True, check=False, capture_output=True)
                    print(f"[DEBUG] ✓ Deobfuscator.ps1 (file1) completed in {time.time() - step_start:.2f}s")

                    # Process file2_deobf1
                    print(f"[DEBUG] Running Deobfuscator.ps1 on file2...")
                    step_start = time.time()
                    cmd4 = f"pwsh -Command \". '{deobf_script_path}'; deobfuscate-script -Filepath '{file2_deobf1}'\""
                    subprocess.run(cmd4, shell=True, check=False, capture_output=True)
                    print(f"[DEBUG] ✓ Deobfuscator.ps1 (file2) completed in {time.time() - step_start:.2f}s")

                    # Read the final deobfuscated files
                    print(f"[DEBUG] Reading final deobfuscated files...")
                    file1_final = temp_path / "original_deobf1_deobfuscated.ps1"
                    file2_final = temp_path / "no_backtick_deobf1_deobfuscated.ps1"

                    # Read both files (up to 10000 chars each)
                    code1 = ""
                    code2 = ""

                    if file1_final.exists():
                        with open(file1_final, "r", encoding="utf-8", errors="ignore") as f:
                            code1 = f.read()[:10000]
                        print(f"[DEBUG] File1 final: {len(code1)} characters")

                    if file2_final.exists():
                        with open(file2_final, "r", encoding="utf-8", errors="ignore") as f:
                            code2 = f.read()[:10000]
                        print(f"[DEBUG] File2 final: {len(code2)} characters")

                    # If both failed, use original code
                    if not code1 and not code2:
                        print(f"[DEBUG] Both deobfuscation attempts failed, using original code")
                        deobfuscated_code = original_code
                        aggressively_deobfuscated_code = original_code
                        aggressively_deobfuscated_code2 = original_code
                    else:
                        # Call AI to compare (if both exist)
                        choice = "2"  # Default to sed version
                        if code1 and code2:
                            print(f"[DEBUG] Comparing both results with AI...")
                            step_start = time.time()
                            choice = compare_codes_with_ai(code1, code2)
                            print(f"[DEBUG] ✓ AI comparison completed in {time.time() - step_start:.2f}s, choice: {choice}")
                        elif code1:
                            choice = "1"
                            print(f"[DEBUG] Only file1 exists, using choice: {choice}")
                        else:
                            print(f"[DEBUG] Only file2 exists, using choice: {choice}")

                        # Select better one
                        if choice == "2" and file2_final.exists():
                            selected_file = file2_final
                            selected_deobf1 = file2_deobf1
                        elif file1_final.exists():
                            selected_file = file1_final
                            selected_deobf1 = file1_deobf1
                        else:
                            # Fallback
                            selected_file = file2_final if file2_final.exists() else file1_final
                            selected_deobf1 = file2_deobf1 if file2_deobf1.exists() else file1_deobf1

                        print(f"[DEBUG] Selected file: {selected_file.name}")

                        # Read selected file (this is pre-LLM, post-Deobfuscator.ps1)
                        with open(selected_file, "r", encoding="utf-8", errors="ignore") as f:
                            selected_code = f.read()[:100000]

                        # This is the pre-LLM version (Deobfuscator.ps1 output)
                        aggressively_deobfuscated_code = selected_code

                        # Call AI for LLM refinement
                        print(f"[DEBUG] Running AI refinement (refine_code_with_ai)...")
                        step_start = time.time()
                        aggressively_deobfuscated_code2 = refine_code_with_ai(selected_code)
                        print(f"[DEBUG] ✓ AI refinement completed in {time.time() - step_start:.2f}s")

                        # Read deobfuscated_code (DeobfuscatedMain only)
                        if selected_deobf1.exists():
                            with open(selected_deobf1, "r", encoding="utf-8", errors="ignore") as f:
                                deobfuscated_code = f.read()
                        else:
                            deobfuscated_code = original_code

                    # Extract IoC from aggressively_deobfuscated_code using iocsearcher
                    print(f"[DEBUG] Extracting IoCs...")
                    step_start = time.time()
                    searcher = Searcher()
                    ioc_results = searcher.search_data(aggressively_deobfuscated_code)
                    print(f"[DEBUG] ✓ IoC extraction completed in {time.time() - step_start:.2f}s")

                    # Convert to desired format (Pass = 1 for all)
                    ioc_list = {"urls": [], "ips": [], "emails": []}
                    
                    for ioc in list(ioc_results):
                        ioc_type = ioc.name
                        ioc_value = ioc.value
                        if ioc_type == "url" or ioc_type == "fqdn":
                            ioc_list["urls"].append({"Pass": 1, "URL": ioc_value})
                        elif ioc_type == "ip4" or ioc_type == "ip6":
                            ioc_list["ips"].append({"Pass": 1, "IP": ioc_value})
                        elif ioc_type == "email":
                            ioc_list["emails"].append({"Pass": 1, "Email": ioc_value})

                    print(f"[DEBUG] Found {len(ioc_list['urls'])} URLs, {len(ioc_list['ips'])} IPs, {len(ioc_list['emails'])} emails")
                    elapsed_time = time.time() - ps_start
                    print(f"[DEBUG] ✓ PowerShell deobfuscation completed in {elapsed_time:.2f}s")
                    print(f"[DEBUG] ========== Deobfuscation Finished ==========\n")

                    return DeobfuscationResult(
                        file_id=request.file_id,
                        filename=metadata["filename"],
                        original_code=original_code,
                        deobfuscated_code=deobfuscated_code,
                        aggressively_deobfuscated_code=aggressively_deobfuscated_code,
                        aggressively_deobfuscated_code2=aggressively_deobfuscated_code2,
                        ioc_list=ioc_list
                    )

            except Exception as e:
                print(f"PowerShell deobfuscation error: {e}")
                # Return original code on error (partial success)
                return DeobfuscationResult(
                    file_id=request.file_id,
                    filename=metadata["filename"],
                    original_code=original_code,
                    deobfuscated_code=original_code,
                    aggressively_deobfuscated_code=original_code,
                    aggressively_deobfuscated_code2=original_code,
                    ioc_list={}
                )

        else:  # VBScript - Real implementation using vbSparkle.CLI
            try:
                print(f"[DEBUG] Starting VBScript deobfuscation...")
                vbs_start = time.time()

                # Path to vbSparkle.CLI
                vbsparkle_cli_path = Path("VBS/vbSparkle.CLI").absolute()

                # Create temporary directory
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_path = Path(temp_dir)

                    # Copy original file
                    print(f"[DEBUG] Creating temporary file...")
                    temp_file = temp_path / "original.vbs"
                    shutil.copy(metadata["file_path"], temp_file)

                    # Run vbSparkle.CLI for 1st stage deobfuscation
                    print(f"[DEBUG] Running vbSparkle.CLI...")
                    step_start = time.time()
                    cmd = f"{vbsparkle_cli_path} -p '{temp_file}'"
                    result = subprocess.run(cmd, shell=True, check=False, capture_output=True, text=True, encoding="utf-8", errors="ignore")
                    print(f"[DEBUG] ✓ vbSparkle.CLI completed in {time.time() - step_start:.2f}s")

                    # Read 1st stage deobfuscated code
                    if result.returncode == 0 and result.stdout:
                        deobfuscated_code = result.stdout[:100000]
                        print(f"[DEBUG] vbSparkle.CLI output: {len(deobfuscated_code)} characters")
                    else:
                        # If vbSparkle.CLI fails, use original code
                        print(f"[DEBUG] vbSparkle.CLI failed (return code: {result.returncode}), using original code")
                        if result.stderr:
                            print(f"[DEBUG] Error: {result.stderr[:500]}")
                        deobfuscated_code = original_code

                    # Set aggressively_deobfuscated_code to 'Not Supported'
                    aggressively_deobfuscated_code = "Not Supported"

                    # Run 2nd stage deobfuscation using AI
                    print(f"[DEBUG] Running AI refinement (refine_code_with_ai)...")
                    step_start = time.time()
                    aggressively_deobfuscated_code2 = refine_code_with_ai(deobfuscated_code)
                    print(f"[DEBUG] ✓ AI refinement completed in {time.time() - step_start:.2f}s")

                    # Extract IoC from deobfuscated_code using iocsearcher
                    print(f"[DEBUG] Extracting IoCs...")
                    step_start = time.time()
                    searcher = Searcher()
                    ioc_results = searcher.search_data(deobfuscated_code)
                    print(f"[DEBUG] ✓ IoC extraction completed in {time.time() - step_start:.2f}s")

                    # Convert to desired format (Pass = 1 for all)
                    ioc_list = {"urls": [], "ips": [], "emails": []}

                    for ioc in list(ioc_results):
                        ioc_type = ioc.name
                        ioc_value = ioc.value
                        if ioc_type == "url" or ioc_type == "fqdn":
                            ioc_list["urls"].append({"Pass": 1, "URL": ioc_value})
                        elif ioc_type == "ip4" or ioc_type == "ip6":
                            ioc_list["ips"].append({"Pass": 1, "IP": ioc_value})
                        elif ioc_type == "email":
                            ioc_list["emails"].append({"Pass": 1, "Email": ioc_value})

                    print(f"[DEBUG] Found {len(ioc_list['urls'])} URLs, {len(ioc_list['ips'])} IPs, {len(ioc_list['emails'])} emails")
                    elapsed_time = time.time() - vbs_start
                    print(f"[DEBUG] ✓ VBScript deobfuscation completed in {elapsed_time:.2f}s")
                    print(f"[DEBUG] ========== Deobfuscation Finished ==========\n")

                    return DeobfuscationResult(
                        file_id=request.file_id,
                        filename=metadata["filename"],
                        original_code=original_code,
                        deobfuscated_code=deobfuscated_code,
                        aggressively_deobfuscated_code=aggressively_deobfuscated_code,
                        aggressively_deobfuscated_code2=aggressively_deobfuscated_code2,
                        ioc_list=ioc_list
                    )

            except Exception as e:
                print(f"VBScript deobfuscation error: {e}")
                # Return original code on error (partial success)
                return DeobfuscationResult(
                    file_id=request.file_id,
                    filename=metadata["filename"],
                    original_code=original_code,
                    deobfuscated_code=original_code,
                    aggressively_deobfuscated_code="Not Supported",
                    aggressively_deobfuscated_code2=original_code,
                    ioc_list={}
                )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deobfuscating file: {str(e)}")


@app.post("/analyze-threat-actor", response_model=ThreatActorResult)
async def analyze_threat_actor(request: FileIdRequest):
    """
    Analyze file to identify potential threat actor.

    Args:
        request: Contains file_id

    Returns:
        Threat actor analysis result with APT group and Malware family
    """
    try:
        # Get file metadata
        if request.file_id not in file_metadata:
            raise HTTPException(status_code=404, detail="File not found")

        metadata = file_metadata[request.file_id]
        file_path = metadata["file_path"]

        print(f"[DEBUG] ========== Server: analyze_threat_actor ==========")
        print(f"[DEBUG] File ID: {request.file_id}")
        print(f"[DEBUG] File name: {metadata['filename']}")
        print(f"[DEBUG] File path: {file_path}")
        print(f"[DEBUG] Detected type: {metadata.get('detected_type')}")

        # Check if file type is Binary
        if metadata.get("detected_type") != "Binary":
            # Return None values for non-binary files
            print(f"[DEBUG] Not a binary file, returning None values")
            return ThreatActorResult(
                file_id=request.file_id,
                filename=metadata["filename"],
                threat_actor=None,
                probability=0.0,
                apt_top3=[],
                malware_family=None,
                malware_probability=0.0,
                malware_top3=[]
            )

        # Run binary classification in a separate thread
        import time
        print(f"\n[DEBUG] Starting binary classification in separate thread...")
        print(f"[DEBUG] Analyzing binary: {metadata['filename']}")
        print(f"[DEBUG] Current time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        start_time = time.time()

        print(f"[DEBUG] Calling asyncio.to_thread(classify_binary, {file_path})...")
        import sys
        sys.stdout.flush()

        # Add timeout to prevent infinite hanging
        # Subprocess has 300s timeout, so give it 360s here (6 minutes)
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(classify_binary, file_path),
                timeout=360.0  # 6 minutes timeout (subprocess has 5 min)
            )
            elapsed_time = time.time() - start_time
            print(f"[DEBUG] ✓ Classification completed in {elapsed_time:.2f} seconds")
            sys.stdout.flush()
        except asyncio.TimeoutError:
            print(f"[DEBUG] ✗ Classification timed out after 360 seconds")
            raise HTTPException(status_code=504, detail="Binary analysis timed out after 6 minutes")

        # Convert top3 tuples to dicts for JSON serialization
        print(f"[DEBUG] Converting top3 results to dicts...")
        apt_top3_dicts = [{"label": label, "probability": prob} for label, prob in result['apt_top3']]
        malware_top3_dicts = [{"label": label, "probability": prob} for label, prob in result['malware_top3']]

        print(f"[DEBUG] Creating response...")
        print(f"[DEBUG] APT Group: {result['apt_group']} ({result['apt_probability']:.2%})")
        print(f"[DEBUG] Malware Family: {result['malware_family']} ({result['malware_probability']:.2%})")

        return ThreatActorResult(
            file_id=request.file_id,
            filename=metadata["filename"],
            threat_actor=result['apt_group'],
            probability=result['apt_probability'],
            apt_top3=apt_top3_dicts,
            malware_family=result['malware_family'],
            malware_probability=result['malware_probability'],
            malware_top3=malware_top3_dicts
        )

    except HTTPException:
        raise
    except Exception as e:
        print(f"[DEBUG] ✗ Error analyzing threat actor: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error analyzing threat actor: {str(e)}")


@app.post("/finalize", response_model=FinalResult)
async def finalize_detection(request: FinalizeRequest):
    """
    Finalize the detection with user-confirmed values.

    Args:
        request: Contains file_id, final type, and final language

    Returns:
        Final result in JSON format
    """
    try:
        # Get file metadata
        if request.file_id not in file_metadata:
            raise HTTPException(status_code=404, detail="File not found")

        metadata = file_metadata[request.file_id]

        # Create final category
        final_category = f"{request.type} ({request.language})"

        # Create final result
        result = {
            "file_id": request.file_id,
            "filename": metadata["filename"],
            "final_type": request.type,
            "final_language": request.language,
            "final_category": final_category,
            "ioc_list": request.ioc_list,
            "threat_actor": request.threat_actor,
            "threat_actor_probability": request.threat_actor_probability,
            "malware_family": request.malware_family,
            "malware_probability": request.malware_probability
        }

        # Print to stdout as requested
        print("\n" + "="*50)
        print("FINAL ANALYSIS RESULT")
        print("="*50)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        print("="*50 + "\n")

        # Clean up file
        try:
            os.remove(metadata["file_path"])
            del file_metadata[request.file_id]
        except Exception as e:
            print(f"Warning: Could not clean up file: {e}")

        return FinalResult(**result)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error finalizing detection: {str(e)}")


# MCP Integration
try:
    from fastapi_mcp import FastapiMCP

    # Initialize MCP
    mcp = FastapiMCP(app)

    @mcp.tool()
    async def detect_file_language(file_path: str) -> dict:
        """
        Detect the programming language of a file.

        Args:
            file_path: Path to the file to analyze

        Returns:
            Dictionary with detection results including type and language
        """
        if not os.path.exists(file_path):
            return {"error": "File not found", "type": "ETC", "language": "ETC"}

        try:
            detection = detector.detect(file_path)
            category = f"{detection['type']} ({detection['language']})"

            return {
                "file_path": file_path,
                "type": detection['type'],
                "language": detection['language'],
                "category": category,
                "success": True
            }
        except Exception as e:
            return {
                "error": str(e),
                "type": "ETC",
                "language": "ETC",
                "success": False
            }

    @mcp.tool()
    async def deobfuscate_script(file_id: str) -> dict:
        """
        Deobfuscate a PowerShell or VBScript file.

        Args:
            file_id: File ID from upload

        Returns:
            Dictionary with original, deobfuscated, and aggressively deobfuscated code + IoC list
        """
        try:
            request = FileIdRequest(file_id=file_id)
            result = await deobfuscate_file(request)
            return result.dict()
        except Exception as e:
            return {"error": str(e), "success": False}

    @mcp.tool()
    async def analyze_threat(file_id: str) -> dict:
        """
        Analyze file to identify potential threat actor.

        Args:
            file_id: File ID from upload

        Returns:
            Dictionary with threat actor and probability
        """
        try:
            request = FileIdRequest(file_id=file_id)
            result = await analyze_threat_actor(request)
            return result.dict()
        except Exception as e:
            return {"error": str(e), "success": False}

    mcp.mount()
    print("✓ MCP integration enabled with deobfuscation and threat actor analysis")



except ImportError:
    print("⚠ fastapi-mcp not installed. MCP support disabled.")
    print("  Install with: pip install fastapi-mcp")


if __name__ == "__main__":
    print("Starting File Language Detector API...")
    print(f"Temp directory: {TEMP_DIR.absolute()}")
    uvicorn.run(app, host="0.0.0.0", port=8000)
