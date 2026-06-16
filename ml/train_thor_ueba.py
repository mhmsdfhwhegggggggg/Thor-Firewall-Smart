#!/usr/bin/env python3
"""
ThorUEBA Training Script — Real production ML model
Trains an Isolation Forest + LSTM autoencoder on process/network telemetry.
Exports to ONNX for inference in thor-agent (ORT runtime).

Dataset: synthetic generation from real attack patterns (CICIDS-2018 inspired)
         + live collection from running Thor agent (optional)

Architecture:
  1. Feature engineering: 28 features per event
  2. Isolation Forest (anomaly scoring, fast inference)
  3. LSTM Autoencoder (temporal pattern learning, sequence anomalies)
  4. ONNX export (float32, batch-compatible)

Usage:
  pip install scikit-learn torch skl2onnx onnx numpy pandas tqdm
  python3 train_thor_ueba.py --output models/thor_ueba_model.onnx
"""

import argparse
import json
import os
import sys
import time
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Optional, Tuple

# ─── Configuration ─────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    # Process features
    "pid_normalized",          # PID / 65535 (normalized)
    "ppid_normalized",
    "cmdline_len_log",         # log(len(cmdline) + 1)
    "num_args",                # number of CLI arguments
    "has_base64",              # cmdline contains base64
    "has_pipe",                # cmdline contains | redirect
    "has_tcp_dev",             # cmdline references /dev/tcp
    "from_tmp",                # process spawned from /tmp
    "parent_is_shell",         # parent is bash/sh/zsh
    "parent_is_web",           # parent is apache/nginx/php
    "uid_root",                # running as root (uid=0)
    "suid_binary",             # binary has SUID bit

    # Network features
    "dst_port_normalized",     # dst_port / 65535
    "is_internal_dst",         # dst IP in RFC1918
    "is_tor_exit",             # known Tor exit node
    "is_ioc_hit",              # IOC database hit
    "conn_count_1m",           # connections in last 1 minute (log)
    "unique_dst_ports_1m",     # unique destination ports (log)
    "bytes_out_log",           # log(bytes sent + 1)
    "bytes_in_log",
    "duration_log",            # log(connection duration + 1)
    "protocol_tcp",            # one-hot: TCP
    "protocol_udp",
    "protocol_icmp",
    "protocol_dns",
    "protocol_tls",

    # Temporal
    "hour_of_day_sin",         # sin(hour * 2π/24) — cyclical encoding
    "hour_of_day_cos",
    "day_of_week_sin",
]

N_FEATURES = len(FEATURE_NAMES)
assert N_FEATURES == 28, f"Expected 28 features, got {N_FEATURES}"


# ─── Synthetic data generation (CICIDS-2018 inspired) ─────────────────────────

def generate_benign_samples(n: int = 50000) -> np.ndarray:
    """Generate synthetic benign traffic/process features."""
    rng = np.random.default_rng(42)
    X = np.zeros((n, N_FEATURES))

    # Normal processes: moderate PIDs, short cmdlines, common ports
    X[:, 0] = rng.uniform(0.01, 0.5, n)    # pid
    X[:, 1] = rng.uniform(0.01, 0.4, n)    # ppid
    X[:, 2] = rng.uniform(0.1, 2.0, n)     # cmdline len (log scale: 1-7)
    X[:, 3] = rng.integers(0, 5, n)        # num args
    X[:, 4] = rng.choice([0, 1], n, p=[0.98, 0.02])  # base64: rare in benign
    X[:, 5] = rng.choice([0, 1], n, p=[0.85, 0.15])  # pipe
    X[:, 6] = np.zeros(n)                   # /dev/tcp: never in benign
    X[:, 7] = rng.choice([0, 1], n, p=[0.99, 0.01])  # from_tmp
    X[:, 8] = rng.choice([0, 1], n, p=[0.7, 0.3])    # parent_shell
    X[:, 9] = np.zeros(n)                   # parent_web
    X[:, 10] = rng.choice([0, 1], n, p=[0.8, 0.2])   # uid_root
    X[:, 11] = np.zeros(n)                  # suid

    # Network: normal ports (80, 443, 22, 53, 8080)
    normal_ports = [80/65535, 443/65535, 22/65535, 53/65535, 8080/65535]
    X[:, 12] = rng.choice(normal_ports, n)
    X[:, 13] = rng.choice([0, 1], n, p=[0.2, 0.8])   # internal dst
    X[:, 14:16] = np.zeros((n, 2))                    # tor, ioc: never
    X[:, 16] = rng.uniform(0, 3, n)        # conn_count log
    X[:, 17] = rng.uniform(0, 2, n)        # unique ports log
    X[:, 18] = rng.uniform(0, 8, n)        # bytes_out
    X[:, 19] = rng.uniform(0, 8, n)        # bytes_in
    X[:, 20] = rng.uniform(0, 4, n)        # duration log

    # Protocols: mostly TCP/TLS
    proto = rng.choice([0, 1, 2, 3, 4, 5], n, p=[0.4, 0.1, 0.03, 0.15, 0.12, 0.2])
    for i in range(6):
        X[:, 21 + i] = (proto == i).astype(float)

    # Time: business hours bias
    hour = rng.integers(0, 24, n)
    business_mask = (hour >= 8) & (hour <= 18)
    hour = np.where(rng.random(n) < 0.8, rng.integers(8, 18, n), hour)
    X[:, 26] = np.sin(hour * 2 * np.pi / 24)
    X[:, 27] = np.cos(hour * 2 * np.pi / 24)

    return X.astype(np.float32)


def generate_attack_samples(n: int = 5000) -> np.ndarray:
    """Generate synthetic attack traffic features."""
    rng = np.random.default_rng(100)
    X = np.zeros((n, N_FEATURES))
    X_b = generate_benign_samples(n)
    X[:] = X_b

    n_per_type = n // 7

    def idx(i): return slice(i * n_per_type, (i+1) * n_per_type)

    # Reverse shell
    X[idx(0), 4] = 1     # base64
    X[idx(0), 6] = 1     # /dev/tcp
    X[idx(0), 8] = 1     # parent shell
    X[idx(0), 12] = rng.choice([4444/65535, 1234/65535, 9001/65535], n_per_type)

    # Lateral movement: SSH from unusual parent
    X[idx(1), 8] = 1
    X[idx(1), 9] = 1     # parent_web
    X[idx(1), 12] = 22/65535
    X[idx(1), 13] = 1

    # Data exfiltration: large uploads
    X[idx(2), 18] = rng.uniform(12, 20, n_per_type)  # huge bytes_out
    X[idx(2), 17] = rng.uniform(4, 7, n_per_type)    # many ports

    # C2 beaconing: tor exit nodes
    X[idx(3), 14] = 1    # tor exit
    X[idx(3), 12] = rng.choice([9001/65535, 9050/65535], n_per_type)

    # Execution from /tmp
    X[idx(4), 7] = 1
    X[idx(4), 10] = 1    # root
    X[idx(4), 2] = rng.uniform(3, 7, n_per_type)  # long cmdline

    # Ransomware: massive file operations
    X[idx(5), 18] = 0
    X[idx(5), 2] = rng.uniform(4, 8, n_per_type)
    X[idx(5), 4] = 1
    X[idx(5), 11] = 1    # suid

    # IOC hit
    X[idx(6), 15] = 1    # ioc_hit
    X[idx(6), 14] = rng.choice([0, 1], n_per_type, p=[0.5, 0.5])

    return X.astype(np.float32)


# ─── Model: Isolation Forest (sklearn → ONNX) ─────────────────────────────────

def train_isolation_forest(X_train: np.ndarray) -> object:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Training Isolation Forest on {len(X_train)} samples...")
    t0 = time.time()

    model = IsolationForest(
        n_estimators=200,
        max_samples=0.8,
        contamination=0.05,
        n_jobs=-1,
        random_state=42,
        verbose=0,
    )
    model.fit(X_train)
    print(f"  ✓ Trained in {time.time()-t0:.1f}s")
    return model


def export_isolation_forest_to_onnx(model, scaler, output_path: str) -> None:
    """Export sklearn pipeline (scaler + isoforest) to ONNX."""
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
        from sklearn.pipeline import Pipeline
        import onnx

        pipeline = Pipeline([("scaler", scaler), ("isoforest", model)])
        pipeline.fit(np.zeros((1, N_FEATURES), dtype=np.float32))

        initial_type = [("float_input", FloatTensorType([None, N_FEATURES]))]
        onnx_model = convert_sklearn(
            pipeline,
            initial_types=initial_type,
            options={type(model): {"method": "decision_function"}},
        )
        onnx.save(onnx_model, output_path)
        print(f"  ✓ ONNX model exported: {output_path}")
    except ImportError:
        # Fall back to joblib pickle if skl2onnx not available
        import joblib
        pkl_path = output_path.replace(".onnx", ".pkl")
        joblib.dump({"model": model, "scaler": scaler}, pkl_path)
        print(f"  ⚠ skl2onnx not installed — saved as joblib: {pkl_path}")
        print("  → Install skl2onnx for ONNX export: pip install skl2onnx")


# ─── LSTM Autoencoder (PyTorch → ONNX) ────────────────────────────────────────

class LSTMAutoencoder:
    """LSTM autoencoder for temporal sequence anomaly detection."""

    def __init__(self, n_features=N_FEATURES, hidden_size=64, num_layers=2):
        try:
            import torch
            import torch.nn as nn

            class _Encoder(nn.Module):
                def __init__(self, input_size, hidden, layers):
                    super().__init__()
                    self.lstm = nn.LSTM(input_size, hidden, layers, batch_first=True, dropout=0.2)
                    self.linear = nn.Linear(hidden, hidden // 2)

                def forward(self, x):
                    _, (h, _) = self.lstm(x)
                    return self.linear(h[-1])

            class _Decoder(nn.Module):
                def __init__(self, hidden, output_size, seq_len, layers):
                    super().__init__()
                    self.seq_len = seq_len
                    self.hidden = hidden
                    self.linear = nn.Linear(hidden // 2, hidden)
                    self.lstm = nn.LSTM(hidden, hidden, layers, batch_first=True, dropout=0.2)
                    self.output = nn.Linear(hidden, output_size)

                def forward(self, z):
                    z = self.linear(z).unsqueeze(1).repeat(1, self.seq_len, 1)
                    out, _ = self.lstm(z)
                    return self.output(out)

            class _Autoencoder(nn.Module):
                def __init__(self, n_features, hidden, layers, seq_len=10):
                    super().__init__()
                    self.encoder = _Encoder(n_features, hidden, layers)
                    self.decoder = _Decoder(hidden, n_features, seq_len, layers)

                def forward(self, x):
                    z = self.encoder(x)
                    return self.decoder(z)

            self.model = _Autoencoder(n_features, hidden_size, num_layers)
            self.available = True
        except ImportError:
            self.available = False
            print("  ⚠ PyTorch not available — skipping LSTM autoencoder")

    def train(self, X_sequences: np.ndarray, epochs=50):
        if not self.available:
            return
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Training LSTM Autoencoder ({epochs} epochs)...")
        t0 = time.time()

        device = "cuda" if torch.cuda.is_available() else "cpu"
        self.model.to(device)

        X_t = torch.FloatTensor(X_sequences).to(device)
        dataset = TensorDataset(X_t, X_t)
        loader = DataLoader(dataset, batch_size=256, shuffle=True)

        optimizer = torch.optim.Adam(self.model.parameters(), lr=1e-3, weight_decay=1e-5)
        scheduler = torch.optim.lr_scheduler.StepLR(optimizer, step_size=20, gamma=0.5)
        criterion = nn.MSELoss()

        self.model.train()
        losses = []
        for epoch in range(epochs):
            epoch_loss = 0.0
            for Xb, _ in loader:
                optimizer.zero_grad()
                out = self.model(Xb)
                loss = criterion(out, Xb)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()
                epoch_loss += loss.item()
            scheduler.step()
            losses.append(epoch_loss / len(loader))
            if (epoch + 1) % 10 == 0:
                print(f"  Epoch {epoch+1:3d}/{epochs}: loss={losses[-1]:.6f}")

        print(f"  ✓ LSTM trained in {time.time()-t0:.1f}s (final loss={losses[-1]:.6f})")

    def export_onnx(self, output_path: str, seq_len: int = 10):
        if not self.available:
            return
        try:
            import torch
            dummy = torch.randn(1, seq_len, N_FEATURES)
            torch.onnx.export(
                self.model,
                dummy,
                output_path,
                input_names=["sequence"],
                output_names=["reconstruction"],
                dynamic_axes={"sequence": {0: "batch_size"}},
                opset_version=17,
            )
            print(f"  ✓ LSTM ONNX model exported: {output_path}")
        except Exception as e:
            print(f"  ✗ LSTM ONNX export failed: {e}")


# ─── Evaluation ───────────────────────────────────────────────────────────────

def evaluate_model(model, scaler, X_benign: np.ndarray, X_attack: np.ndarray) -> dict:
    from sklearn.metrics import roc_auc_score, f1_score, precision_score, recall_score

    X_b_s = scaler.transform(X_benign[:5000])
    X_a_s = scaler.transform(X_attack)

    y_true = np.array([0] * len(X_b_s) + [1] * len(X_a_s))
    X_all = np.vstack([X_b_s, X_a_s])

    scores = -model.score_samples(X_all)  # higher = more anomalous
    threshold = np.percentile(scores[:len(X_b_s)], 95)
    y_pred = (scores > threshold).astype(int)

    return {
        "auc_roc":   float(roc_auc_score(y_true, scores)),
        "f1_score":  float(f1_score(y_true, y_pred, zero_division=0)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall":    float(recall_score(y_true, y_pred, zero_division=0)),
        "threshold": float(threshold),
        "n_benign":  len(X_benign),
        "n_attack":  len(X_attack),
    }


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ThorUEBA Model Training")
    parser.add_argument("--output",     default="models/thor_ueba_model.onnx")
    parser.add_argument("--lstm-output", default="models/thor_lstm_model.onnx")
    parser.add_argument("--n-benign",   type=int, default=50000)
    parser.add_argument("--n-attack",   type=int, default=5000)
    parser.add_argument("--lstm-epochs", type=int, default=50)
    parser.add_argument("--skip-lstm",  action="store_true")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
    os.makedirs("models", exist_ok=True)

    print("=" * 60)
    print(f"  ThorUEBA Model Training — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Features: {N_FEATURES} | Benign: {args.n_benign} | Attack: {args.n_attack}")
    print("=" * 60)

    # Generate synthetic training data
    print("\n[1/4] Generating synthetic CICIDS-2018 inspired dataset...")
    X_benign = generate_benign_samples(args.n_benign)
    X_attack = generate_attack_samples(args.n_attack)
    print(f"  ✓ Benign: {X_benign.shape} | Attack: {X_attack.shape}")

    # Fit scaler on benign-only (unsupervised scenario)
    from sklearn.preprocessing import StandardScaler
    print("\n[2/4] Fitting StandardScaler on benign data...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_benign)
    print(f"  ✓ Scaler fitted (mean shape: {scaler.mean_.shape})")

    # Train Isolation Forest
    print("\n[3/4] Training Isolation Forest...")
    model = train_isolation_forest(X_train_scaled)

    # Evaluate
    metrics = evaluate_model(model, scaler, X_benign, X_attack)
    print(f"\n  📊 Evaluation Results:")
    print(f"     AUC-ROC:   {metrics['auc_roc']:.4f}")
    print(f"     F1 Score:  {metrics['f1_score']:.4f}")
    print(f"     Precision: {metrics['precision']:.4f}")
    print(f"     Recall:    {metrics['recall']:.4f}")
    print(f"     Threshold: {metrics['threshold']:.4f}")

    # Export
    print(f"\n[4/4] Exporting model...")
    export_isolation_forest_to_onnx(model, scaler, args.output)

    # Save metrics
    metrics_path = args.output.replace(".onnx", "_metrics.json").replace(".pkl", "_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump({
            **metrics,
            "feature_names": FEATURE_NAMES,
            "trained_at": datetime.now().isoformat(),
            "model_type": "IsolationForest+StandardScaler",
            "n_estimators": 200,
        }, f, indent=2)
    print(f"  ✓ Metrics saved: {metrics_path}")

    # LSTM Autoencoder
    if not args.skip_lstm:
        print("\n[+] Training LSTM Autoencoder (optional, temporal)...")
        lstm = LSTMAutoencoder()
        # Create sequences of length 10
        n_seq = args.n_benign // 10
        X_seq = X_benign[:n_seq * 10].reshape(n_seq, 10, N_FEATURES)
        lstm.train(X_seq, epochs=args.lstm_epochs)
        lstm.export_onnx(args.lstm_output)

    print("\n" + "=" * 60)
    print(f"  ✅ ThorUEBA training complete!")
    print(f"     AUC-ROC: {metrics['auc_roc']:.4f} | F1: {metrics['f1_score']:.4f}")
    print(f"     Model: {args.output}")
    print("=" * 60)


if __name__ == "__main__":
    main()
