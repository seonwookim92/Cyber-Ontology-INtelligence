#!/usr/bin/env python3
"""
GAT v2 Model for APT Group Classification
Implements Velickovic Graph Attention Network with Brody's GAT v2 enhancement
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATv2Conv, global_mean_pool

class GATv2APTClassifier(nn.Module):
    """
    Graph Attention Network v2 for APT Group Classification

    Architecture:
    - 4 GAT v2 layers with normalization and LeakyReLU
    - First 3 layers: 4 concatenated attention heads
    - Last layer: 6 pooled (averaged) attention heads
    - Global mean pooling
    - Multi-layer feedforward classifier
    """

    def __init__(self, input_dim, hidden_dim, num_classes, dropout=0.3):
        """
        Args:
            input_dim: Input feature dimension (768 for jina embeddings)
            hidden_dim: Hidden dimension for GAT layers
            num_classes: Number of APT groups to classify
            dropout: Dropout probability
        """
        super(GATv2APTClassifier, self).__init__()

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_classes = num_classes
        self.dropout = dropout

        # GAT v2 Layers
        # Layer 1: 4 concatenated heads
        self.gat1 = GATv2Conv(
            in_channels=input_dim,
            out_channels=hidden_dim,
            heads=4,
            concat=True,  # Concatenate heads
            dropout=dropout
        )
        self.norm1 = nn.LayerNorm(hidden_dim * 4)

        # Layer 2: 4 concatenated heads
        self.gat2 = GATv2Conv(
            in_channels=hidden_dim * 4,
            out_channels=hidden_dim,
            heads=4,
            concat=True,
            dropout=dropout
        )
        self.norm2 = nn.LayerNorm(hidden_dim * 4)

        # Layer 3: 4 concatenated heads
        self.gat3 = GATv2Conv(
            in_channels=hidden_dim * 4,
            out_channels=hidden_dim,
            heads=4,
            concat=True,
            dropout=dropout
        )
        self.norm3 = nn.LayerNorm(hidden_dim * 4)

        # Layer 4: 6 pooled (averaged) heads
        self.gat4 = GATv2Conv(
            in_channels=hidden_dim * 4,
            out_channels=hidden_dim,
            heads=6,
            concat=False,  # Pool (average) heads
            dropout=dropout
        )
        self.norm4 = nn.LayerNorm(hidden_dim)

        # Multi-layer feedforward classifier
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim * 2),
            nn.LeakyReLU(0.2),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.LeakyReLU(0.2),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes)
        )

    def forward(self, x, edge_index, batch):
        """
        Forward pass

        Args:
            x: Node features [num_nodes, input_dim]
            edge_index: Edge indices [2, num_edges]
            batch: Batch assignment for each node [num_nodes]

        Returns:
            logits: Class logits [batch_size, num_classes]
        """

        # GAT Layer 1
        x = self.gat1(x, edge_index)
        x = self.norm1(x)
        x = F.leaky_relu(x, 0.2)

        # GAT Layer 2
        x = self.gat2(x, edge_index)
        x = self.norm2(x)
        x = F.leaky_relu(x, 0.2)

        # GAT Layer 3
        x = self.gat3(x, edge_index)
        x = self.norm3(x)
        x = F.leaky_relu(x, 0.2)

        # GAT Layer 4
        x = self.gat4(x, edge_index)
        x = self.norm4(x)
        x = F.leaky_relu(x, 0.2)

        # Global mean pooling
        x = global_mean_pool(x, batch)

        # Classifier
        logits = self.classifier(x)

        return logits

    def get_embeddings(self, x, edge_index, batch):
        """
        Extract graph embeddings (before classifier)

        Args:
            x: Node features [num_nodes, input_dim]
            edge_index: Edge indices [2, num_edges]
            batch: Batch assignment for each node [num_nodes]

        Returns:
            embeddings: Graph embeddings [batch_size, hidden_dim]
        """

        # GAT layers
        x = self.gat1(x, edge_index)
        x = self.norm1(x)
        x = F.leaky_relu(x, 0.2)

        x = self.gat2(x, edge_index)
        x = self.norm2(x)
        x = F.leaky_relu(x, 0.2)

        x = self.gat3(x, edge_index)
        x = self.norm3(x)
        x = F.leaky_relu(x, 0.2)

        x = self.gat4(x, edge_index)
        x = self.norm4(x)
        x = F.leaky_relu(x, 0.2)

        # Global mean pooling
        embeddings = global_mean_pool(x, batch)

        return embeddings

# =============================================================================
# Model Info
# =============================================================================

def count_parameters(model):
    """Count trainable parameters"""
    return sum(p.numel() for p in model.parameters() if p.requires_grad)

def print_model_info(model):
    """Print model architecture and parameter count"""
    print("=" * 80)
    print("Model Architecture")
    print("=" * 80)
    print(model)
    print("=" * 80)
    print(f"Total trainable parameters: {count_parameters(model):,}")
    print("=" * 80)

# =============================================================================
# Test
# =============================================================================

if __name__ == "__main__":
    # Test model creation
    print("Testing GAT v2 Model...")

    input_dim = 768  # Jina embedding dimension
    hidden_dim = 128
    num_classes = 12  # Example: 12 APT groups

    model = GATv2APTClassifier(
        input_dim=input_dim,
        hidden_dim=hidden_dim,
        num_classes=num_classes,
        dropout=0.3
    )

    print_model_info(model)

    # Test forward pass
    batch_size = 2
    num_nodes = 100
    num_edges = 200

    x = torch.randn(num_nodes, input_dim)
    edge_index = torch.randint(0, num_nodes, (2, num_edges))
    batch = torch.cat([torch.zeros(50, dtype=torch.long), torch.ones(50, dtype=torch.long)])

    with torch.no_grad():
        logits = model(x, edge_index, batch)
        embeddings = model.get_embeddings(x, edge_index, batch)

    print(f"\nTest Results:")
    print(f"  Input shape: {x.shape}")
    print(f"  Edge index shape: {edge_index.shape}")
    print(f"  Batch shape: {batch.shape}")
    print(f"  Output logits shape: {logits.shape}")
    print(f"  Embeddings shape: {embeddings.shape}")
    print("\n✓ Model test passed!")
