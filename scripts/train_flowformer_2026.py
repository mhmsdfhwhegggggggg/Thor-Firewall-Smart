#!/usr/bin/env python3
"""
FlowFormer Training Script — Tier 2 ODIN Plan
==============================================
Self-supervised Masked Autoencoder (MAE) pre-training for network flow analysis.

Architecture (USENIX Security 2024 / ATLAS IEEE S&P 2025 combined approach):
1. Pre-train FlowFormer as masked autoencoder on unlabeled network flows
2. Fine-tune on labeled attack/normal traffic from Thor's eBPF captures
3. Export to ONNX for production inference via ORT

Usage:
    # Install dependencies
    pip install torch torchvision onnx onnxruntime scikit-learn pandas numpy

    # Collect training data from Thor eBPF (run first)
    sudo python3 ml/pcap_to_features.py --interface eth0 --output data/flows.npz

    # Pre-train (self-supervised MAE — no labels needed)
    python3 scripts/train_flowformer_2026.py --mode pretrain --data data/flows.npz

    # Fine-tune on labeled data
    python3 scripts/train_flowformer_2026.py --mode finetune --data data/labeled_flows.npz

    # Export to ONNX
    python3 scripts/train_flowformer_2026.py --mode export --output models/flowformer_v1.onnx

Privacy: All training data is processed locally — no data leaves the system.
Differential Privacy: Use --dp_epsilon 0.1 to enable DP-SGD during fine-tuning.
"""

import argparse
import logging
import math
import os
import time
from pathlib import Path
from typing import Optional, Tuple

import numpy as np

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("FlowFormer")

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    logger.warning("PyTorch not installed. Run: pip install torch")
    TORCH_AVAILABLE = False

# ─── Constants ────────────────────────────────────────────────────────────────

N_FEATURES  = 28       # Must match features.rs N_FEATURES
EMBED_DIM   = 128      # Transformer embedding dimension
NUM_HEADS   = 4        # Multi-head attention heads
NUM_LAYERS  = 2        # Transformer encoder layers
FFN_DIM     = 256      # Feed-forward network hidden size
WINDOW_SIZE = 16       # Sequence window for temporal analysis
MASK_RATIO  = 0.15     # MAE masking ratio (15% of tokens masked)
BATCH_SIZE  = 256      # Training batch size
LR          = 1e-4     # Learning rate (Adam optimizer)
EPOCHS_PT   = 50       # Pre-training epochs
EPOCHS_FT   = 20       # Fine-tuning epochs

# ─── Model ────────────────────────────────────────────────────────────────────

class FlowFormerModel(nn.Module):
    """
    FlowFormer: Transformer for network flow anomaly detection.
    Implements both MAE pre-training and classification heads.
    """
    def __init__(self, n_features=N_FEATURES, embed_dim=EMBED_DIM,
                 num_heads=NUM_HEADS, num_layers=NUM_LAYERS, ffn_dim=FFN_DIM):
        super().__init__()
        self.n_features = n_features
        self.embed_dim  = embed_dim

        # Feature projection: N_FEATURES → embed_dim
        self.projection = nn.Sequential(
            nn.Linear(n_features, embed_dim),
            nn.LayerNorm(embed_dim),
            nn.GELU(),
        )

        # Learnable positional embedding (better than sinusoidal for our window sizes)
        self.pos_embed = nn.Embedding(512, embed_dim)

        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=num_heads,
            dim_feedforward=ffn_dim, dropout=0.1,
            activation="gelu", batch_first=True,
            norm_first=True,  # Pre-norm for training stability (GPT-2 style)
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        # MAE decoder head (for pre-training)
        self.mae_decoder = nn.Sequential(
            nn.Linear(embed_dim, ffn_dim),
            nn.GELU(),
            nn.Linear(ffn_dim, n_features),
        )

        # Classification head (for fine-tuning + production)
        self.classifier = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(embed_dim // 2, 1),
            nn.Sigmoid(),
        )

        # Initialize weights (Xavier uniform)
        self.apply(self._init_weights)
        logger.info(f"FlowFormer: {sum(p.numel() for p in self.parameters()):,} parameters")

    def _init_weights(self, module):
        if isinstance(module, nn.Linear):
            nn.init.xavier_uniform_(module.weight)
            if module.bias is not None:
                nn.init.zeros_(module.bias)

    def forward(self, x: torch.Tensor, mode: str = "classify") -> torch.Tensor:
        """
        Args:
            x: [batch, seq_len, n_features] or [batch, n_features]
            mode: "classify" | "pretrain" | "embed"
        """
        if x.dim() == 2:
            x = x.unsqueeze(1)  # [B, 1, F]

        B, S, F = x.shape
        pos = torch.arange(S, device=x.device).expand(B, S)

        # Project + add positional embeddings
        emb = self.projection(x) + self.pos_embed(pos)

        # Transformer encoding
        encoded = self.transformer(emb)

        if mode == "pretrain":
            # MAE: reconstruct masked tokens
            return self.mae_decoder(encoded)
        elif mode == "embed":
            # Return mean-pooled representation
            return encoded.mean(dim=1)
        else:
            # Classification: use CLS token (mean pooling)
            cls = encoded.mean(dim=1)  # [B, embed_dim]
            return self.classifier(cls).squeeze(-1)  # [B]


class MaskedAutoencoder:
    """MAE pre-training wrapper — masks 15% of feature tokens and trains reconstruction."""

    @staticmethod
    def mask_features(x: "torch.Tensor", mask_ratio: float = MASK_RATIO):
        """Create masked version of features for self-supervised pre-training."""
        B, S, F = x.shape
        n_masked = max(1, int(F * mask_ratio))
        mask_idx = torch.randint(0, F, (B, n_masked), device=x.device)
        x_masked = x.clone()
        for b in range(B):
            x_masked[b, :, mask_idx[b]] = 0.0
        return x_masked, mask_idx

    @staticmethod
    def compute_loss(pred: "torch.Tensor", target: "torch.Tensor", mask_idx: "torch.Tensor"):
        """MSE loss only on masked positions."""
        total_loss = 0.0
        for b in range(target.size(0)):
            masked_pred   = pred[b, :, mask_idx[b]]
            masked_target = target[b, :, mask_idx[b]]
            total_loss += nn.functional.mse_loss(masked_pred, masked_target)
        return total_loss / target.size(0)


# ─── Training Functions ───────────────────────────────────────────────────────

def pretrain(model: "FlowFormerModel", dataloader: "DataLoader",
             epochs: int = EPOCHS_PT, device: str = "cpu") -> "FlowFormerModel":
    """Self-supervised MAE pre-training — no labels required."""
    model = model.to(device)
    optimizer = optim.Adam(model.parameters(), lr=LR)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
    mae = MaskedAutoencoder()

    logger.info(f"Starting MAE pre-training: {epochs} epochs, device={device}")
    for epoch in range(epochs):
        total_loss = 0.0
        for batch in dataloader:
            x = batch[0].to(device)
            if x.dim() == 2:
                x = x.unsqueeze(1).expand(-1, WINDOW_SIZE, -1)

            x_masked, mask_idx = mae.mask_features(x, MASK_RATIO)
            pred = model(x_masked, mode="pretrain")
            loss = mae.compute_loss(pred, x, mask_idx)

            optimizer.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total_loss += loss.item()

        scheduler.step()
        if (epoch + 1) % 10 == 0:
            logger.info(f"  Epoch {epoch+1}/{epochs}: MAE loss={total_loss/len(dataloader):.6f}")

    return model


def finetune(model: "FlowFormerModel", dataloader: "DataLoader",
             epochs: int = EPOCHS_FT, device: str = "cpu",
             dp_epsilon: Optional[float] = None) -> "FlowFormerModel":
    """Fine-tune on labeled data with optional Differential Privacy."""
    model = model.to(device)
    optimizer = optim.AdamW(model.parameters(), lr=LR * 0.1, weight_decay=0.01)
    criterion = nn.BCELoss()

    # DP-SGD integration (requires opacus library for production)
    if dp_epsilon is not None:
        logger.info(f"DP-SGD enabled: epsilon={dp_epsilon} (requires opacus library)")
        try:
            from opacus import PrivacyEngine
            privacy_engine = PrivacyEngine()
            model, optimizer, dataloader = privacy_engine.make_private_with_epsilon(
                module=model, optimizer=optimizer, data_loader=dataloader,
                target_epsilon=dp_epsilon, target_delta=1e-5, epochs=epochs,
                max_grad_norm=1.0,
            )
            logger.info(f"Opacus DP-SGD configured: epsilon={dp_epsilon}")
        except ImportError:
            logger.warning("opacus not installed. Run: pip install opacus. Continuing without DP.")

    logger.info(f"Fine-tuning: {epochs} epochs, device={device}")
    for epoch in range(epochs):
        total_loss = 0.0; correct = 0; total = 0
        for batch in dataloader:
            if len(batch) == 2:
                x, y = batch[0].to(device), batch[1].float().to(device)
            else:
                continue

            pred = model(x, mode="classify")
            loss = criterion(pred, y)
            optimizer.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

            total_loss += loss.item()
            correct += ((pred > 0.5).float() == y).sum().item()
            total += len(y)

        acc = correct / total if total > 0 else 0
        logger.info(f"  Epoch {epoch+1}/{epochs}: loss={total_loss/len(dataloader):.4f} acc={acc:.4f}")

    return model


def export_to_onnx(model: "FlowFormerModel", output_path: str, device: str = "cpu"):
    """Export trained model to ONNX for ORT inference in Thor."""
    model.eval()
    dummy = torch.randn(1, WINDOW_SIZE, N_FEATURES, device=device)
    torch.onnx.export(
        model, (dummy,), output_path,
        export_params=True, opset_version=17,
        input_names=["flow_features"],
        output_names=["anomaly_score"],
        dynamic_axes={
            "flow_features": {0: "batch_size", 1: "seq_len"},
            "anomaly_score": {0: "batch_size"},
        }
    )
    size_mb = Path(output_path).stat().st_size / 1e6
    logger.info(f"✅ FlowFormer exported: {output_path} ({size_mb:.2f} MB)")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="FlowFormer Training — Thor ODIN Plan Tier 2")
    parser.add_argument("--mode", choices=["pretrain", "finetune", "export"], required=True)
    parser.add_argument("--data", default="data/flows.npz", help="Input .npz data file")
    parser.add_argument("--model", default="models/flowformer_pretrained.pt", help="Model checkpoint")
    parser.add_argument("--output", default="models/flowformer_v1_2026.onnx", help="ONNX output")
    parser.add_argument("--epochs", type=int, default=None, help="Training epochs (overrides defaults)")
    parser.add_argument("--device", default="cpu", choices=["cpu", "cuda", "mps"])
    parser.add_argument("--dp_epsilon", type=float, default=None, help="DP epsilon for fine-tuning")
    args = parser.parse_args()

    if not TORCH_AVAILABLE:
        logger.error("PyTorch required. Install: pip install torch"); return

    model = FlowFormerModel()

    if args.mode == "pretrain":
        # Load unlabeled flow data
        logger.info(f"Loading unlabeled data from {args.data}")
        if Path(args.data).exists():
            data = np.load(args.data)
            X = torch.tensor(data["X"], dtype=torch.float32)
        else:
            logger.warning(f"Data file {args.data} not found — generating synthetic data for testing")
            X = torch.randn(10000, N_FEATURES)

        dataset = TensorDataset(X)
        loader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)
        epochs = args.epochs or EPOCHS_PT
        model = pretrain(model, loader, epochs, args.device)
        torch.save(model.state_dict(), args.model)
        logger.info(f"Pre-trained model saved: {args.model}")

    elif args.mode == "finetune":
        if Path(args.model).exists():
            model.load_state_dict(torch.load(args.model, map_location="cpu"))
            logger.info(f"Loaded pre-trained weights: {args.model}")

        if Path(args.data).exists():
            data = np.load(args.data)
            X = torch.tensor(data["X"], dtype=torch.float32)
            y = torch.tensor(data["y"], dtype=torch.float32)
        else:
            logger.warning("No labeled data — generating synthetic (unbalanced, for demo only)")
            X = torch.randn(5000, N_FEATURES)
            y = (torch.randn(5000) > 2.0).float()  # ~2.3% anomaly rate

        dataset = TensorDataset(X, y)
        loader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)
        epochs = args.epochs or EPOCHS_FT
        model = finetune(model, loader, epochs, args.device, args.dp_epsilon)
        torch.save(model.state_dict(), args.model.replace("pretrained", "finetuned"))
        logger.info("Fine-tuned model saved")

    elif args.mode == "export":
        if Path(args.model).exists():
            model.load_state_dict(torch.load(args.model, map_location="cpu"))
        os.makedirs(Path(args.output).parent, exist_ok=True)
        export_to_onnx(model, args.output, args.device)


if __name__ == "__main__":
    main()
