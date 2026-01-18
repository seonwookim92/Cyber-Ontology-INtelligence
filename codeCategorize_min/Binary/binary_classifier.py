#!/usr/bin/env python3
"""
Binary Classification for APT Groups and Malware Families
Uses trained GAT v2 models to classify binaries
"""

import os
import sys
import json
import torch
import subprocess
import tempfile
import time
from pathlib import Path
from torch_geometric.data import Data

# Add model directories to path
SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR / "APTClassification"))
sys.path.insert(0, str(SCRIPT_DIR / "MalwareClassification"))

# Import models
from APTClassification.model import GATv2APTClassifier as APTModel
from MalwareClassification.model import GATv2APTClassifier as MalwareModel

# =============================================================================
# Configuration
# =============================================================================
APT_MODEL_DIR = SCRIPT_DIR / "APTClassification" / "models"
MALWARE_MODEL_DIR = SCRIPT_DIR / "MalwareClassification" / "models"

APT_LABEL_MAPPING_PATH = APT_MODEL_DIR / "label_mapping.json"
APT_MODEL_PATH = APT_MODEL_DIR / "best_model.pth"

MALWARE_LABEL_MAPPING_PATH = MALWARE_MODEL_DIR / "label_mapping.json"
MALWARE_MODEL_PATH = MALWARE_MODEL_DIR / "best_model.pth"

DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

# =============================================================================
# Helper Functions
# =============================================================================

def load_label_mapping(path):
    """Load label mapping from JSON file"""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def features_to_graph(features):
    """
    Convert extracted features to PyTorch Geometric Data object

    Args:
        features: Dict with 'Nodes' and 'Edges' keys

    Returns:
        Data: PyTorch Geometric Data object, or None if invalid
    """
    print("[DEBUG] Converting features to graph...")
    if features is None:
        print("[DEBUG] ✗ Features is None")
        return None

    nodes = features['Nodes']
    edges = features['Edges']
    print(f"[DEBUG] Features: {len(nodes)} nodes, {len(edges)} edges")

    if len(nodes) == 0:
        print("[DEBUG] ✗ No nodes found")
        return None

    # Extract node features (embeddings)
    node_features = []
    zero_embedding_count = 0
    for node in nodes:
        embedding = node.get('DecompileEmbedding', None)
        if embedding is None or len(embedding) == 0:
            embedding = [0.0] * 768
            zero_embedding_count += 1
        node_features.append(embedding)

    if zero_embedding_count > 0:
        print(f"[DEBUG] ⚠ {zero_embedding_count}/{len(nodes)} nodes have zero embeddings")

    # Convert to tensor
    x = torch.tensor(node_features, dtype=torch.float)
    print(f"[DEBUG] Node feature tensor shape: {x.shape}")

    # Extract edges
    if len(edges) > 0:
        edge_list = [[edge['from'], edge['to']] for edge in edges]
        edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
        print(f"[DEBUG] Edge index tensor shape: {edge_index.shape}")
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)
        print(f"[DEBUG] No edges, empty edge index")

    # Create Data object
    graph = Data(x=x, edge_index=edge_index)
    print(f"[DEBUG] ✓ Graph created successfully")

    return graph


def load_model_from_checkpoint(checkpoint_path, model_class, device):
    """
    Load model from checkpoint

    Args:
        checkpoint_path: Path to checkpoint file
        model_class: Model class (APTModel or MalwareModel)
        device: Device to load model on

    Returns:
        model: Loaded model, or None if failed
        num_classes: Number of classes
    """
    print(f"[DEBUG] Loading model from {checkpoint_path}...")
    try:
        checkpoint = torch.load(checkpoint_path, map_location=device)
        print(f"[DEBUG] ✓ Checkpoint loaded")

        # Get model config from checkpoint
        if 'model_state_dict' in checkpoint:
            state_dict = checkpoint['model_state_dict']
            print(f"[DEBUG] State dict keys: {len(state_dict.keys())}")

            # Infer num_classes from classifier layer
            # classifier.6.weight has shape [num_classes, hidden_dim]
            num_classes = state_dict['classifier.6.weight'].shape[0]
            hidden_dim = state_dict['classifier.6.weight'].shape[1]
            print(f"[DEBUG] Model config: hidden_dim={hidden_dim}, num_classes={num_classes}")

            # Create model
            print(f"[DEBUG] Creating model instance...")
            model = model_class(
                input_dim=768,
                hidden_dim=hidden_dim,
                num_classes=num_classes,
                dropout=0.3
            ).to(device)

            print(f"[DEBUG] Loading state dict into model...")
            model.load_state_dict(state_dict)
            model.eval()
            print(f"[DEBUG] ✓ Model loaded and set to eval mode")

            return model, num_classes
        else:
            print(f"[DEBUG] ✗ Invalid checkpoint format at {checkpoint_path}")
            return None, 0

    except Exception as e:
        print(f"[DEBUG] ✗ Error loading model from {checkpoint_path}: {e}")
        import traceback
        traceback.print_exc()
        return None, 0


def classify_with_model(graph, model, label_mapping, device):
    """
    Classify a graph with a model

    Args:
        graph: PyTorch Geometric Data object
        model: Trained model
        label_mapping: Label mapping dict
        device: Device

    Returns:
        dict: Classification result with keys:
            - predicted_label: str
            - probability: float
            - top3: [(label, prob), ...]
        Returns None values if classification failed
    """
    print("[DEBUG] Starting classification...")
    if graph is None or model is None:
        print("[DEBUG] ✗ Graph or model is None")
        return {
            'predicted_label': None,
            'probability': 0.0,
            'top3': []
        }

    try:
        # Move graph to device
        print(f"[DEBUG] Moving graph to device: {device}")
        graph = graph.to(device)

        # Add batch index (single graph)
        batch = torch.zeros(graph.x.size(0), dtype=torch.long, device=device)
        print(f"[DEBUG] Batch tensor shape: {batch.shape}")

        # Run inference
        print(f"[DEBUG] Running inference...")
        with torch.no_grad():
            logits = model(graph.x, graph.edge_index, batch)
            print(f"[DEBUG] Logits shape: {logits.shape}")
            probabilities = torch.softmax(logits, dim=1)
            pred_label_id = logits.argmax(dim=1).item()
            pred_prob = probabilities[0, pred_label_id].item()
            print(f"[DEBUG] Predicted label ID: {pred_label_id}, probability: {pred_prob:.4f}")

        # Get all class probabilities
        id_to_label = {v: k for k, v in label_mapping.items()}
        all_probs = {}
        for i in range(len(label_mapping)):
            all_probs[id_to_label[i]] = probabilities[0, i].item()

        # Sort by probability
        sorted_probs = sorted(all_probs.items(), key=lambda x: x[1], reverse=True)
        print(f"[DEBUG] Top 3 predictions: {sorted_probs[:3]}")

        return {
            'predicted_label': id_to_label[pred_label_id],
            'probability': pred_prob,
            'top3': sorted_probs[:3]
        }

    except Exception as e:
        print(f"[DEBUG] ✗ Error during classification: {e}")
        import traceback
        traceback.print_exc()
        return {
            'predicted_label': None,
            'probability': 0.0,
            'top3': []
        }


# =============================================================================
# Main Classification Function
# =============================================================================

def classify_binary(binary_path):
    """
    Classify a binary for both APT group and Malware family

    Args:
        binary_path: Path to binary file

    Returns:
        dict: Classification results with keys:
            - apt_group: str or None
            - apt_probability: float
            - apt_top3: [(group, prob), ...]
            - malware_family: str or None
            - malware_probability: float
            - malware_top3: [(family, prob), ...]
    """
    print("[DEBUG] ========== Binary Classifier: classify_binary ==========")
    print("=" * 80)
    print("Binary Classification")
    print("=" * 80)
    print(f"[DEBUG] Binary path: {binary_path}")
    print(f"[DEBUG] Binary exists: {Path(binary_path).exists()}")
    print(f"[DEBUG] Device: {DEVICE}")
    print(f"[DEBUG] APT model path: {APT_MODEL_PATH} (exists: {APT_MODEL_PATH.exists()})")
    print(f"[DEBUG] Malware model path: {MALWARE_MODEL_PATH} (exists: {MALWARE_MODEL_PATH.exists()})")
    print("=" * 80)

    # =============================================================================
    # Extract features using subprocess (to avoid PyGhidra/FastAPI conflicts)
    # =============================================================================
    print("\n[DEBUG] Starting feature extraction via subprocess...")
    print("-" * 60)

    # Create temporary file for features
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        feature_file = tmp.name

    print(f"[DEBUG] Temporary feature file: {feature_file}")

    # Convert binary_path to absolute path
    binary_path_abs = str(Path(binary_path).resolve())
    print(f"[DEBUG] Binary absolute path: {binary_path_abs}")

    # Run feature_extractor.py as subprocess
    extractor_script = SCRIPT_DIR / "feature_extractor.py"
    cmd = [
        sys.executable,  # Use same Python interpreter
        str(extractor_script),
        binary_path_abs,  # Use absolute path
        "Unknown",  # family_name
        feature_file  # output_file (already absolute from tempfile)
    ]

    print(f"[DEBUG] Running command: {' '.join(cmd)}")
    print(f"[DEBUG] Starting subprocess at {time.strftime('%H:%M:%S')}...")

    try:
        # Run with timeout (5 minutes)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            cwd=str(SCRIPT_DIR)
        )

        print(f"[DEBUG] Subprocess completed with return code: {result.returncode}")

        if result.returncode != 0:
            print(f"[DEBUG] ✗ Feature extraction subprocess failed!")
            print(f"[DEBUG] stdout: {result.stdout[-500:]}")  # Last 500 chars
            print(f"[DEBUG] stderr: {result.stderr[-500:]}")
            return {
                'apt_group': None,
                'apt_probability': 0.0,
                'apt_top3': [],
                'malware_family': None,
                'malware_probability': 0.0,
                'malware_top3': []
            }

        # Read features from file
        print(f"[DEBUG] Reading features from {feature_file}...")
        with open(feature_file, 'r', encoding='utf-8') as f:
            features = json.load(f)

        print(f"[DEBUG] ✓ Feature extraction successful")

    except subprocess.TimeoutExpired:
        print(f"[DEBUG] ✗ Feature extraction timed out after 300 seconds!")
        return {
            'apt_group': None,
            'apt_probability': 0.0,
            'apt_top3': [],
            'malware_family': None,
            'malware_probability': 0.0,
            'malware_top3': []
        }
    except Exception as e:
        print(f"[DEBUG] ✗ Error running feature extraction subprocess: {e}")
        import traceback
        traceback.print_exc()
        return {
            'apt_group': None,
            'apt_probability': 0.0,
            'apt_top3': [],
            'malware_family': None,
            'malware_probability': 0.0,
            'malware_top3': []
        }
    finally:
        # Clean up temporary file
        try:
            if Path(feature_file).exists():
                Path(feature_file).unlink()
                print(f"[DEBUG] ✓ Cleaned up temporary feature file")
        except:
            pass

    # Convert to graph
    print("\n[DEBUG] Converting features to graph...")
    graph = features_to_graph(features)
    if graph is None:
        print("[DEBUG] ✗ Failed to create graph!")
        return {
            'apt_group': None,
            'apt_probability': 0.0,
            'apt_top3': [],
            'malware_family': None,
            'malware_probability': 0.0,
            'malware_top3': []
        }

    print(f"[DEBUG] ✓ Graph created: {graph.x.size(0)} nodes, {graph.edge_index.size(1)} edges")

    # =============================================================================
    # APT Classification
    # =============================================================================
    print("\n[DEBUG] ========== APT Classification Start ==========")
    print("\n" + "=" * 80)
    print("APT Group Classification")
    print("=" * 80)

    apt_result = {'predicted_label': None, 'probability': 0.0, 'top3': []}

    print(f"[DEBUG] Checking APT model files...")
    print(f"[DEBUG] Label mapping exists: {APT_LABEL_MAPPING_PATH.exists()}")
    print(f"[DEBUG] Model exists: {APT_MODEL_PATH.exists()}")

    if not APT_LABEL_MAPPING_PATH.exists() or not APT_MODEL_PATH.exists():
        print("[DEBUG] ⚠ APT model or label mapping not found. Skipping APT classification.")
    else:
        print("[DEBUG] Loading APT label mapping...")
        apt_label_mapping = load_label_mapping(APT_LABEL_MAPPING_PATH)
        print(f"[DEBUG] ✓ Loaded {len(apt_label_mapping)} APT groups: {list(apt_label_mapping.keys())}")

        print("[DEBUG] Loading APT model...")
        apt_model, apt_num_classes = load_model_from_checkpoint(APT_MODEL_PATH, APTModel, DEVICE)
        if apt_model is not None:
            print(f"[DEBUG] ✓ Loaded model with {apt_num_classes} classes")

            print("[DEBUG] Starting APT classification...")
            apt_result = classify_with_model(graph, apt_model, apt_label_mapping, DEVICE)

            if apt_result['predicted_label'] is not None:
                print(f"[DEBUG] ✓ Predicted APT Group: {apt_result['predicted_label']} ({apt_result['probability']:.2%})")
            else:
                print("[DEBUG] ⚠ APT classification failed")
        else:
            print("[DEBUG] ✗ Failed to load APT model")

    # =============================================================================
    # Malware Family Classification
    # =============================================================================
    print("\n[DEBUG] ========== Malware Classification Start ==========")
    print("\n" + "=" * 80)
    print("Malware Family Classification")
    print("=" * 80)

    malware_result = {'predicted_label': None, 'probability': 0.0, 'top3': []}

    print(f"[DEBUG] Checking Malware model files...")
    print(f"[DEBUG] Label mapping exists: {MALWARE_LABEL_MAPPING_PATH.exists()}")
    print(f"[DEBUG] Model exists: {MALWARE_MODEL_PATH.exists()}")

    if not MALWARE_LABEL_MAPPING_PATH.exists() or not MALWARE_MODEL_PATH.exists():
        print("[DEBUG] ⚠ Malware model or label mapping not found. Skipping Malware classification.")
    else:
        print("[DEBUG] Loading Malware label mapping...")
        malware_label_mapping = load_label_mapping(MALWARE_LABEL_MAPPING_PATH)
        print(f"[DEBUG] ✓ Loaded {len(malware_label_mapping)} malware families: {list(malware_label_mapping.keys())}")

        print("[DEBUG] Loading Malware model...")
        malware_model, malware_num_classes = load_model_from_checkpoint(MALWARE_MODEL_PATH, MalwareModel, DEVICE)
        if malware_model is not None:
            print(f"[DEBUG] ✓ Loaded model with {malware_num_classes} classes")

            print("[DEBUG] Starting Malware classification...")
            malware_result = classify_with_model(graph, malware_model, malware_label_mapping, DEVICE)

            if malware_result['predicted_label'] is not None:
                print(f"[DEBUG] ✓ Predicted Malware Family: {malware_result['predicted_label']} ({malware_result['probability']:.2%})")
            else:
                print("[DEBUG] ⚠ Malware classification failed")
        else:
            print("[DEBUG] ✗ Failed to load Malware model")

    # =============================================================================
    # Return Results
    # =============================================================================
    print("\n[DEBUG] ========== Binary Classifier Complete ==========")
    print("\n" + "=" * 80)
    print("Classification Complete")
    print("=" * 80)

    result = {
        'apt_group': apt_result['predicted_label'],
        'apt_probability': apt_result['probability'],
        'apt_top3': apt_result['top3'],
        'malware_family': malware_result['predicted_label'],
        'malware_probability': malware_result['probability'],
        'malware_top3': malware_result['top3']
    }

    print(f"[DEBUG] Final result: {result}")
    return result


# =============================================================================
# Main (for testing)
# =============================================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python binary_classifier.py <binary_path>")
        print("Example: python binary_classifier.py /path/to/malware.exe")
        sys.exit(1)

    binary_path = sys.argv[1]

    if not Path(binary_path).exists():
        print(f"Error: Binary not found: {binary_path}")
        sys.exit(1)

    result = classify_binary(binary_path)

    # Print results
    print("\n" + "=" * 80)
    print("Final Results")
    print("=" * 80)

    print("\nAPT Group:")
    print(f"  Predicted: {result['apt_group']}")
    print(f"  Probability: {result['apt_probability']:.2%}")
    print("  Top 3:")
    for i, (label, prob) in enumerate(result['apt_top3'], 1):
        print(f"    {i}. {label}: {prob:.2%}")

    print("\nMalware Family:")
    print(f"  Predicted: {result['malware_family']}")
    print(f"  Probability: {result['malware_probability']:.2%}")
    print("  Top 3:")
    for i, (label, prob) in enumerate(result['malware_top3'], 1):
        print(f"    {i}. {label}: {prob:.2%}")

    print("\n" + "=" * 80)
