#!/usr/bin/env python3
"""
Binary Feature Extraction for Malware Classification
Extracts function call graphs (nodes and edges) from binaries using pyGhidra
"""

import os
import sys
import shutil
from pathlib import Path
import time
import json

# Set up environment for PyGhidra
SCRIPT_DIR = Path(__file__).parent
GHIDRA_INSTALL_DIR = SCRIPT_DIR / "ghidra_12.0_PUBLIC"
os.environ['GHIDRA_INSTALL_DIR'] = str(GHIDRA_INSTALL_DIR)

# Create temp projects directory
TEMP_PROJECTS_DIR = SCRIPT_DIR / "temp_projects"
TEMP_PROJECTS_DIR.mkdir(exist_ok=True)

import pyghidra
import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModel

# =============================================================================
# Global Variables
# =============================================================================

# PyGhidra initialization flag
_pyghidra_initialized = False

# Embedding model (loaded once)
_embedding_model = None
_tokenizer = None
_device = None


def initialize_pyghidra():
    """Initialize PyGhidra if not already initialized"""
    global _pyghidra_initialized
    if not _pyghidra_initialized:
        try:
            print("[DEBUG] Initializing PyGhidra...")
            print(f"[DEBUG] GHIDRA_INSTALL_DIR: {os.environ.get('GHIDRA_INSTALL_DIR')}")
            print(f"[DEBUG] Current working directory: {os.getcwd()}")
            print(f"[DEBUG] GHIDRA_INSTALL_DIR exists: {Path(os.environ.get('GHIDRA_INSTALL_DIR', '')).exists()}")
            print(f"[DEBUG] Process ID: {os.getpid()}")

            import sys
            sys.stdout.flush()

            print(f"[DEBUG] Calling pyghidra.start()...")
            pyghidra.start()
            _pyghidra_initialized = True
            print("[DEBUG] ✓ PyGhidra initialized successfully")
            sys.stdout.flush()
        except Exception as e:
            print(f"[DEBUG] PyGhidra initialization exception: {e}")
            if "already" in str(e).lower() or "started" in str(e).lower():
                _pyghidra_initialized = True
                print("[DEBUG] ✓ PyGhidra already initialized")
            else:
                print(f"[DEBUG] ✗ PyGhidra initialization failed: {e}")
                import traceback
                traceback.print_exc()
                raise
    else:
        print("[DEBUG] PyGhidra already initialized (skipping)")


def initialize_embedding_model():
    """Initialize the embedding model if not already initialized"""
    global _embedding_model, _tokenizer, _device

    if _embedding_model is None:
        print("[DEBUG] Loading embedding model...")
        try:
            _tokenizer = AutoTokenizer.from_pretrained('jinaai/jina-embeddings-v2-base-code')
            print("[DEBUG] ✓ Tokenizer loaded")
            _embedding_model = AutoModel.from_pretrained(
                'jinaai/jina-embeddings-v2-base-code',
                trust_remote_code=True
            )
            print("[DEBUG] ✓ Model loaded")
            _device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            print(f"[DEBUG] Device: {_device}")
            _embedding_model = _embedding_model.to(_device)
            _embedding_model.eval()
            print(f"[DEBUG] ✓ Embedding model loaded on {_device}")
        except Exception as e:
            print(f"[DEBUG] ✗ Embedding model loading failed: {e}")
            raise
    else:
        print("[DEBUG] Embedding model already loaded (skipping)")


def mean_pooling(model_output, attention_mask):
    """Mean pooling for embeddings"""
    token_embeddings = model_output[0]
    input_mask_expanded = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
    return torch.sum(token_embeddings * input_mask_expanded, 1) / torch.clamp(
        input_mask_expanded.sum(1), min=1e-9
    )


def get_code_embedding(code_text, max_length=512):
    """
    Generate embedding for decompiled code

    Args:
        code_text: Decompiled code as string
        max_length: Maximum token length

    Returns:
        List of floats (768-dim) or zero vector if failed
    """
    try:
        if not code_text or len(code_text.strip()) == 0:
            return [0.0] * 768

        encoded_input = _tokenizer(
            code_text,
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors='pt'
        ).to(_device)

        with torch.no_grad():
            model_output = _embedding_model(**encoded_input)

        embeddings = mean_pooling(model_output, encoded_input['attention_mask'])
        embeddings = F.normalize(embeddings, p=2, dim=1)

        return embeddings.cpu().numpy()[0].tolist()

    except Exception as e:
        print(f"    Warning: Embedding generation failed: {e}")
        return [0.0] * 768


# =============================================================================
# Feature Extraction
# =============================================================================

def extract_features_from_binary(binary_path, family_name="Unknown", timeout=120, output_file=None):
    """
    Extract call graph features from a binary using pyGhidra

    Args:
        binary_path: Path to the binary file
        family_name: Malware family or APT group name
        timeout: Decompilation timeout in seconds
        output_file: Optional path to save JSON output. If None, only returns dict

    Returns:
        dict: Extracted features in JSON format with keys:
            - Family: family name
            - Nodes: list of node dicts
            - Edges: list of edge dicts
        Returns None if extraction failed
    """
    print(f"\n[DEBUG] ========== Feature Extraction Start ==========")
    print(f"[DEBUG] Binary path: {binary_path}")
    print(f"[DEBUG] Family name: {family_name}")

    initialize_pyghidra()
    initialize_embedding_model()

    binary_path = Path(binary_path).resolve()  # Convert to absolute path

    if not binary_path.exists():
        print(f"[DEBUG] ✗ Binary file not found: {binary_path}")
        return None

    print(f"[DEBUG] Binary file exists: {binary_path.name} ({binary_path.stat().st_size} bytes)")
    print(f"[DEBUG] Absolute path: {binary_path}")

    print(f"\n[DEBUG] Processing: {binary_path.name}")
    print(f"[DEBUG] Family: {family_name}")

    # Create unique project name
    project_name = f"temp_{os.getpid()}_{binary_path.stem}_{int(time.time() * 1000)}"
    print(f"[DEBUG] Project name: {project_name}")
    print(f"[DEBUG] Project location: {TEMP_PROJECTS_DIR}")

    # Pre-cleanup: Remove project directory if it exists
    temp_project = TEMP_PROJECTS_DIR / project_name
    if temp_project.exists():
        print(f"[DEBUG] Pre-cleanup: Removing existing project directory: {temp_project}")
        try:
            shutil.rmtree(temp_project, ignore_errors=True)
            print(f"[DEBUG] ✓ Pre-cleanup complete")
        except Exception as e:
            print(f"[DEBUG] ⚠ Pre-cleanup warning: {e}")

    try:
        nodes = []
        edges = []
        address_to_id = {}
        next_node_id = 0

        print(f"[DEBUG] About to call pyghidra.open_program()...")
        print(f"[DEBUG]   - binary_path: {str(binary_path)}")
        print(f"[DEBUG]   - project_location: {str(TEMP_PROJECTS_DIR)}")
        print(f"[DEBUG]   - project_name: {project_name}")
        print(f"[DEBUG]   - analyze: False (skipping auto-analysis to avoid hanging)")
        print(f"[DEBUG] Calling pyghidra.open_program() NOW at {time.strftime('%H:%M:%S')}...")

        import sys
        sys.stdout.flush()  # Force flush to see output immediately

        start_open_time = time.time()

        # Open binary with PyGhidra - analyze=False to avoid hanging
        with pyghidra.open_program(
            str(binary_path),
            project_location=str(TEMP_PROJECTS_DIR),
            project_name=project_name,
            analyze=True  # Changed to False to avoid auto-analysis hanging
        ) as flat_api:
            elapsed_open = time.time() - start_open_time
            print(f"[DEBUG] ✓ Entered 'with' block - flat_api obtained (took {elapsed_open:.2f}s)")
            sys.stdout.flush()
            print(f"[DEBUG] ✓ Binary opened and analyzed successfully")

            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor

            print(f"[DEBUG] Getting program from flat_api...")
            program = flat_api.getCurrentProgram()
            print(f"[DEBUG] Program: {program.getName()}")

            fm = program.getFunctionManager()
            monitor = ConsoleTaskMonitor()

            # Initialize decompiler
            print(f"[DEBUG] Initializing decompiler...")
            decompiler = DecompInterface()
            decompiler.openProgram(program)
            print(f"[DEBUG] ✓ Decompiler initialized")

            print(f"[DEBUG] Collecting functions...")

            # Iterate through all non-external functions
            func_count = 0
            decompiled_count = 0
            for func in fm.getFunctions(True):
                if func.isExternal():
                    continue

                func_count += 1
                if func_count == 1:
                    print(f"[DEBUG] Processing first function: {func.getName()} at {func.getEntryPoint()}")
                addr_str = str(func.getEntryPoint())
                node_id = next_node_id
                address_to_id[addr_str] = node_id
                next_node_id += 1

                # Extract basic function info
                num_params = 0
                try:
                    params = func.getParameters()
                    if params is not None:
                        num_params = len(params)
                    if num_params == 0:
                        num_params = func.getParameterCount()
                except:
                    pass

                return_type = str(func.getReturnType())

                num_variables = 0
                try:
                    local_vars = func.getLocalVariables()
                    if local_vars is not None:
                        num_variables = len(list(local_vars))
                except:
                    pass

                instruction_size = 0
                try:
                    func_body = func.getBody()
                    if func_body:
                        instruction_size = func_body.getNumAddresses()
                except:
                    pass

                # Decompile function
                decompiled_code = ""
                try:
                    if func_count == 1:
                        print(f"[DEBUG] Attempting to decompile first function...")
                    results = decompiler.decompileFunction(func, timeout, monitor)
                    if results and results.decompileCompleted():
                        decomp_func = results.getDecompiledFunction()
                        if decomp_func:
                            decompiled_code = decomp_func.getC()
                            decompiled_count += 1
                            if func_count == 1:
                                print(f"[DEBUG] ✓ First function decompiled ({len(decompiled_code)} chars)")

                            # Try to get more accurate params/vars from HighFunction
                            high_func = results.getHighFunction()
                            if high_func:
                                try:
                                    local_symbol_map = high_func.getLocalSymbolMap()
                                    if local_symbol_map:
                                        param_count = local_symbol_map.getNumParams()
                                        if param_count > 0:
                                            num_params = param_count
                                        all_symbols = local_symbol_map.getSymbols()
                                        if all_symbols:
                                            num_variables = len(list(all_symbols)) - param_count
                                except:
                                    pass
                    else:
                        if func_count == 1:
                            print(f"[DEBUG] ⚠ First function decompilation incomplete")
                except Exception as e:
                    print(f"[DEBUG] Warning: Failed to decompile function at {addr_str}: {e}")

                # Generate embedding
                if func_count == 1:
                    print(f"[DEBUG] Generating embedding for first function...")
                embedding = get_code_embedding(decompiled_code)
                if func_count == 1:
                    print(f"[DEBUG] ✓ Embedding generated ({len(embedding)} dims)")

                # Create node
                node = {
                    "NodeID": node_id,
                    "InputParameterSize": num_params,
                    "InstructionSize": instruction_size,
                    "ReturnDataType": return_type,
                    "VariableSize": num_variables,
                    "DecompileContent": decompiled_code,
                    "DecompileEmbedding": embedding
                }
                nodes.append(node)

                # Extract call graph edges
                try:
                    called_funcs = func.getCalledFunctions(monitor)
                    if called_funcs:
                        for called_func in called_funcs:
                            if called_func.isExternal():
                                continue
                            called_addr = str(called_func.getEntryPoint())
                            edges.append({
                                'from_addr': addr_str,
                                'to_addr': called_addr
                            })
                except:
                    pass

                # Progress indicator
                if func_count % 100 == 0:
                    print(f"[DEBUG] Processed {func_count} functions (decompiled: {decompiled_count})...")

            # Clean up decompiler
            print(f"[DEBUG] Disposing decompiler...")
            decompiler.dispose()
            print(f"[DEBUG] ✓ Decompiler disposed")

        print(f"[DEBUG] Total functions processed: {func_count}")
        print(f"[DEBUG] Total functions decompiled: {decompiled_count}")
        print(f"[DEBUG] ✓ Extracted {len(nodes)} nodes")

        # Check if any functions were extracted
        if len(nodes) == 0:
            print(f"[DEBUG] ⚠ No functions were extracted. Skipping.")
            return None

        # Resolve edge IDs
        print(f"[DEBUG] Resolving edge IDs...")
        resolved_edges = []
        for edge in edges:
            from_addr = edge['from_addr']
            to_addr = edge['to_addr']
            if from_addr in address_to_id and to_addr in address_to_id:
                resolved_edges.append({
                    "from": address_to_id[from_addr],
                    "to": address_to_id[to_addr]
                })

        print(f"[DEBUG] ✓ Extracted {len(resolved_edges)} edges")

        # Create output data
        output_data = {
            "Family": family_name,
            "Nodes": nodes,
            "Edges": resolved_edges
        }

        # Save to file if output_file is specified
        if output_file is not None:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            print(f"[DEBUG] Saving features to {output_path}...")
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            print(f"[DEBUG] ✓ Features saved to {output_path}")

        print(f"[DEBUG] ========== Feature Extraction Complete ==========\n")
        return output_data

    except Exception as e:
        print(f"[DEBUG] ✗ Error during feature extraction: {e}")
        import traceback
        traceback.print_exc()
        return None

    finally:
        # Clean up temporary Ghidra project
        temp_project = TEMP_PROJECTS_DIR / project_name
        if temp_project.exists():
            try:
                shutil.rmtree(temp_project, ignore_errors=True)
            except:
                pass


# =============================================================================
# Main (for testing)
# =============================================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python feature_extractor.py <binary_path> [family_name] [output_file]")
        print("Example: python feature_extractor.py malware.exe Emotet output.json")
        sys.exit(1)

    binary_path = sys.argv[1]
    family_name = sys.argv[2] if len(sys.argv) > 2 else "Unknown"
    output_file = sys.argv[3] if len(sys.argv) > 3 else None

    result = extract_features_from_binary(binary_path, family_name, output_file=output_file)

    if result:
        print("\n✓ Feature extraction completed successfully!")
        print(f"  Nodes: {len(result['Nodes'])}")
        print(f"  Edges: {len(result['Edges'])}")
        if output_file:
            print(f"  Output: {output_file}")
    else:
        print("\n✗ Feature extraction failed!")
        sys.exit(1)
