import sys
import os
import shutil
import tempfile
import subprocess
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

# Import project-wide LLM client
from src.core.llm import chat

# Setup logging
logger = logging.getLogger(__name__)

# =============================================================================
# Path Configuration
# =============================================================================
# Assuming this file is in src/services/
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CODE_CAT_DIR = PROJECT_ROOT / "codeCategorize_min"
BINARY_DIR = CODE_CAT_DIR / "Binary"

# Add codeCategorize_min to sys.path to allow imports
if str(CODE_CAT_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_CAT_DIR))

# Add Binary dir to sys.path for binary_classifier dependencies
if str(BINARY_DIR) not in sys.path:
    sys.path.insert(0, str(BINARY_DIR))

# Import codeCategorize_min modules
try:
    from detector import LanguageDetector
    # We defer importing binary_classifier to inside the function or wrapped in try/except 
    # to avoid breaking if dependencies are missing, though they should be present.
except ImportError as e:
    logger.error(f"Failed to import codeCategorize_min modules: {e}")
    LanguageDetector = None

# =============================================================================
# Service Class
# =============================================================================

class BinaryAnalysisService:
    def __init__(self):
        if LanguageDetector:
            self.detector = LanguageDetector()
        else:
            self.detector = None
            
        self.temp_dir = Path(tempfile.gettempdir()) / "gemini_analysis"
        self.temp_dir.mkdir(exist_ok=True)
        logger.info(f"BinaryAnalysisService initialized. Temp dir: {self.temp_dir}")

    def detect_file_type(self, file_path: str) -> Dict[str, str]:
        """
        Detect file type and language.
        """
        logger.debug(f"Detecting file type for: {file_path}")
        if not self.detector:
            return {"type": "Error", "language": "Module not loaded"}
            
        result = self.detector.detect(file_path)
        logger.debug(f"Detection result: {result}")
        return result

    async def analyze_binary(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a binary file using the GAT model.
        """
        logger.info(f"Starting binary analysis for: {file_path}")
        try:
            # Import here to avoid circular imports or initialization issues
            from binary_classifier import classify_binary
            
            logger.debug("Calling classify_binary...")
            result = classify_binary(file_path)
            logger.debug(f"Binary analysis result: {result}")
            return result
        except Exception as e:
            logger.error(f"Binary analysis failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {
                "error": str(e),
                "apt_group": None,
                "malware_family": None
            }

    def deobfuscate_script(self, file_path: str, language: str) -> Dict[str, Any]:
        """
        Deobfuscate PowerShell or VBScript and extract IoCs.
        """
        logger.info(f"Starting deobfuscation for {language} file: {file_path}")
        
        try:
            from iocsearcher.searcher import Searcher
        except ImportError:
            logger.warning("iocsearcher not found. IoC extraction disabled.")
            Searcher = None

        if language not in ["PowerShell", "VBScript"]:
            return {"error": "Unsupported language for deobfuscation"}

        # Read original code
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                original_code = f.read()
            logger.debug(f"Read original code ({len(original_code)} chars)")
        except Exception as e:
            return {"error": f"Failed to read file: {e}"}

        deobfuscated_code = original_code
        
        extracted_iocs = {"urls": [], "ips": [], "emails": []}
        
        try:
            if language == "PowerShell":
                logger.info("Running PowerShell specific deobfuscation pipeline")
                deobfuscated_code = self._deobfuscate_powershell(file_path)
            elif language == "VBScript":
                logger.info("Running VBScript specific deobfuscation pipeline")
                deobfuscated_code = self._deobfuscate_vbscript(file_path)
        except Exception as e:
            logger.error(f"Deobfuscation pipeline failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            # Fallback to original code
            deobfuscated_code = original_code

        # Extract IoCs
        if Searcher:
            try:
                logger.info("Extracting IoCs from deobfuscated code...")
                searcher = Searcher()
                # Search in deobfuscated code
                ioc_results = searcher.search_data(deobfuscated_code)
                
                count = 0
                for ioc in list(ioc_results):
                    count += 1
                    if ioc.name in ["url", "fqdn"]:
                        extracted_iocs["urls"].append(ioc.value)
                    elif ioc.name in ["ip4", "ip6"]:
                        extracted_iocs["ips"].append(ioc.value)
                    elif ioc.name == "email":
                        extracted_iocs["emails"].append(ioc.value)
                logger.info(f"Extracted {count} IoCs")
                        
            except Exception as e:
                logger.error(f"IoC extraction failed: {e}")

        return {
            "original_code": original_code,
            "deobfuscated_code": deobfuscated_code,
            "ioc_list": extracted_iocs
        }

    def _call_ai_comparison(self, code1: str, code2: str) -> str:
        """
        Compare two codes and return which is better (1 or 2).
        Uses src.core.llm.chat
        """
        logger.debug("Calling AI for code comparison...")
        prompt = "주어진 두개의 코드를 비교하여, 어떤 코드가 더 정보가 유실되지 않는 코드인지 얘기해주세요. 답변은 숫자로 앞에서부터 1, 2로 매겨서 알려주시고 그 이외 설명은 불허합니다."
        
        # Truncate codes if too long to fit context
        c1_trunc = code1[:8000]
        c2_trunc = code2[:8000]
        
        content = f"{prompt}\n\nCode 1:\n{c1_trunc}\n\nCode 2:\n{c2_trunc}"
        
        messages = [{"role": "user", "content": content}]
        
        try:
            result = chat(messages)
            logger.debug(f"AI Comparison result: {result}")
            
            if "1" in result and "2" not in result:
                return "1"
            else:
                return "2" # Default to 2
        except Exception as e:
            logger.error(f"AI Comparison failed: {e}")
            return "2"

    def _deobfuscate_powershell(self, file_path: str) -> str:
        """
        Run detailed PowerShell deobfuscation logic:
        1. Create two versions: Original and No-Backticks
        2. Run Invoke-Deobfuscation on both
        3. Run Deobfuscator.ps1 on both results
        4. Compare results using LLM
        """
        # Paths relative to project root
        invoke_deobf_path = CODE_CAT_DIR / "Powershell/invoke-deobfuscation/Code/Invoke-DeObfuscation.psd1"
        deobf_script_path = CODE_CAT_DIR / "Powershell/Deobfuscator.ps1"
        
        if not invoke_deobf_path.exists():
            logger.error(f"Invoke-Deobfuscation not found at {invoke_deobf_path}")
        if not deobf_script_path.exists():
            logger.error(f"Deobfuscator.ps1 not found at {deobf_script_path}")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            logger.debug(f"Working in temp dir: {temp_path}")

            # 1. Prepare files
            file1 = temp_path / "original.ps1"
            file2 = temp_path / "no_backtick.ps1"

            shutil.copy(file_path, file1)
            
            # Create no-backtick version
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            with open(file2, "w", encoding="utf-8", errors="ignore") as f:
                f.write(content.replace("`", ""))
            
            logger.debug("Created original.ps1 and no_backtick.ps1")

            # 2. Run Invoke-Deobfuscation
            file1_deobf1 = temp_path / "original_deobf1.ps1"
            file2_deobf1 = temp_path / "no_backtick_deobf1.ps1"

            logger.info("Running Invoke-Deobfuscation on both files...")
            
            # Cmd 1
            cmd1 = f"pwsh -Command \"Import-Module '{invoke_deobf_path}'; DeobfuscatedMain -scriptpath0 '{file1}' | Out-File -FilePath '{file1_deobf1}' -Encoding UTF8\""
            subprocess.run(cmd1, shell=True, check=False, capture_output=True)
            
            # Cmd 2
            cmd2 = f"pwsh -Command \"Import-Module '{invoke_deobf_path}'; DeobfuscatedMain -scriptpath0 '{file2}' | Out-File -FilePath '{file2_deobf1}' -Encoding UTF8\""
            subprocess.run(cmd2, shell=True, check=False, capture_output=True)
            
            logger.debug("Invoke-Deobfuscation complete.")

            # 3. Run Deobfuscator.ps1
            # Note: Deobfuscator.ps1 usually runs explicitly on the output of previous step
            logger.info("Running Deobfuscator.ps1 on both files...")
            
            # Run on file 1 result
            # Assuming deobfuscate-script outputs or modifies. Based on server.py, it seems to modify or print?
            # server.py command: deobfuscate-script -Filepath '{file1_deobf1}'
            # Then it reads file1_final = temp_path / "original_deobf1_deobfuscated.ps1"
            # So Deobfuscator.ps1 likely creates a file with _deobfuscated suffix.
            
            cmd3 = f"pwsh -Command \". '{deobf_script_path}'; deobfuscate-script -Filepath '{file1_deobf1}'\""
            subprocess.run(cmd3, shell=True, check=False, capture_output=True)
            
            cmd4 = f"pwsh -Command \". '{deobf_script_path}'; deobfuscate-script -Filepath '{file2_deobf1}'\""
            subprocess.run(cmd4, shell=True, check=False, capture_output=True)
            
            # 4. Check results
            # The script seems to append _deobfuscated.ps1 (inferred from server.py logic)
            # Actually server.py manually constructs the path name to read.
            # Let's assume the script convention holds.
            
            # Wait a bit for filesystem (just in case)
            time.sleep(0.5)

            # Files expected
            # Note: server.py logic implies the output name is derived from input name.
            # But wait, looking at server.py:
            # file1_final = temp_path / "original_deobf1_deobfuscated.ps1"
            # So yes, it appends _deobfuscated.
            
            # However, if the file extension was .ps1, it might insert it before extension or append.
            # Let's check directory content to be sure.
            generated_files = list(temp_path.glob("*_deobfuscated.ps1"))
            logger.debug(f"Generated deobfuscated files: {[f.name for f in generated_files]}")

            # Try to locate specific files
            out1 = temp_path / "original_deobf1_deobfuscated.ps1"
            out2 = temp_path / "no_backtick_deobf1_deobfuscated.ps1"
            
            code1 = ""
            code2 = ""
            
            if out1.exists():
                with open(out1, "r", encoding="utf-8", errors="ignore") as f: code1 = f.read()
            if out2.exists():
                with open(out2, "r", encoding="utf-8", errors="ignore") as f: code2 = f.read()

            logger.info(f"Code 1 length: {len(code1)}, Code 2 length: {len(code2)}")

            selected_code = ""

            if not code1 and not code2:
                logger.warning("Both deobfuscation attempts failed. Returning original.")
                with open(file_path, "r", errors="ignore") as f: return f.read()
            
            elif code1 and code2:
                # LLM Comparison
                logger.info("Both versions exist. Comparing with AI...")
                choice = self._call_ai_comparison(code1, code2)
                logger.info(f"AI chose option: {choice}")
                selected_code = code1 if choice == "1" else code2
                
            elif code1:
                logger.info("Only Code 1 exists. Selecting it.")
                selected_code = code1
            else:
                logger.info("Only Code 2 exists. Selecting it.")
                selected_code = code2

            return selected_code

    def _deobfuscate_vbscript(self, file_path: str) -> str:
        """
        Run VBScript deobfuscation logic using vbSparkle.
        """
        vbsparkle_path = CODE_CAT_DIR / "VBS/vbSparkle.CLI"
        
        if not vbsparkle_path.exists():
            logger.warning(f"vbSparkle not found at {vbsparkle_path}")
            # Try to run it anyway? No, return original.
            with open(file_path, 'r', errors='ignore') as f: return f.read()

        logger.info("Running vbSparkle...")
        cmd = f"'{vbsparkle_path}' -p '{file_path}'"
        
        try:
            # vbSparkle prints to stdout
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, errors="ignore", timeout=60)
            
            if result.returncode == 0 and result.stdout:
                logger.debug(f"vbSparkle success. Output length: {len(result.stdout)}")
                return result.stdout
            else:
                logger.warning(f"vbSparkle failed or empty output. RC: {result.returncode}")
                if result.stderr:
                    logger.debug(f"vbSparkle stderr: {result.stderr}")
        except Exception as e:
            logger.error(f"vbSparkle execution error: {e}")
            
        with open(file_path, 'r', errors='ignore') as f: return f.read()