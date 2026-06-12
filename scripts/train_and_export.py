#!/usr/bin/env python3
"""
Thor UEBA Model Trainer and ONNX Exporter
Trains IsolationForest on synthetic network traffic, exports to ONNX
"""
import sys
import os
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
except ImportError:
    print("Install dependencies: pip install scikit-learn skl2onnx numpy")
    sys.exit(1)

FEATURE_DIMENSION = 32
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "thor_ueba_model.onnx")

def generate_normal_traffic(n_samples: int = 50_000) -> np.ndarray:
    """Generate synthetic 'normal' network behavior features"""
    rng = np.random.default_rng(42)
    X = np.zeros((n_samples, FEATURE_DIMENSION), dtype=np.float32)
    
    # Feature 0: Event type (mostly network=0)
    X[:, 0] = rng.choice([0, 1, 2], n_samples, p=[0.7, 0.2, 0.1])
    
    # Feature 1: Common destination ports (web, dns, ntp, smtp)
    common_ports = [80, 443, 53, 123, 25, 587, 22, 3306, 5432, 8080, 8443]
    port_norm = np.array([p / 65535.0 for p in common_ports])
    X[:, 1] = rng.choice(port_norm, n_samples)
    
    # Feature 2: Protocol (mostly TCP)
    X[:, 2] = rng.choice([0.5, 0.85, 0.0], n_samples, p=[0.7, 0.25, 0.05])
    
    # Feature 3: Direction (mostly outbound)
    X[:, 3] = rng.choice([0, 1], n_samples, p=[0.3, 0.7])
    
    # Feature 4: RFC1918 (mostly internal traffic)
    X[:, 4] = rng.choice([0, 1], n_samples, p=[0.4, 0.6])
    
    # Feature 5: UID (normal users 1000-2000)
    X[:, 5] = rng.uniform(1000/65535, 2000/65535, n_samples)
    
    # Feature 6: PID (typical range 100-50000)
    X[:, 6] = rng.uniform(100/100000, 50000/100000, n_samples)
    
    # Feature 7: Hour of day (business hours 8-18)
    hour = rng.choice(range(8, 19), n_samples) / 23.0
    X[:, 7] = hour
    
    # Features 8-11: IP octets (mostly 10.x.x.x or 192.168.x.x)
    X[:, 8] = rng.choice([10/255, 192/255, 172/255], n_samples, p=[0.5, 0.4, 0.1])
    X[:, 9] = rng.uniform(0, 1, n_samples)
    X[:, 10] = rng.uniform(0, 1, n_samples)
    X[:, 11] = rng.uniform(1/255, 254/255, n_samples)
    
    # Features 12-31: Small random noise (process names, flow stats)
    X[:, 12:] = rng.uniform(0, 0.3, (n_samples, 20))
    
    return X

def generate_anomalous_traffic(n_samples: int = 500) -> np.ndarray:
    """Generate anomalous traffic for contamination parameter"""
    rng = np.random.default_rng(99)
    X = np.zeros((n_samples, FEATURE_DIMENSION), dtype=np.float32)
    # Anomalies: high ports, unusual hours, external IPs, root UID
    X[:, 0] = 0  # network events
    X[:, 1] = rng.uniform(0.75, 1.0, n_samples)  # high destination ports
    X[:, 2] = 0.5  # TCP
    X[:, 3] = 1.0  # outbound
    X[:, 4] = 0.0  # external
    X[:, 5] = 0.0  # root (UID=0)
    X[:, 7] = rng.choice([2/23, 3/23, 4/23, 5/23], n_samples)  # 2-5 AM
    X[:, 12:] = rng.uniform(0.7, 1.0, (n_samples, 20))
    return X

def main():
    print(f"Thor UEBA Model Trainer")
    print(f"Feature dimension: {FEATURE_DIMENSION}")
    
    # Generate training data
    print("Generating synthetic training data...")
    X_normal = generate_normal_traffic(50_000)
    X_anomalous = generate_anomalous_traffic(500)
    X_train = np.vstack([X_normal, X_anomalous])
    
    print(f"Training set: {X_train.shape[0]} samples x {X_train.shape[1]} features")
    print("Training IsolationForest...")
    
    model = IsolationForest(
        n_estimators=100,
        contamination=0.01,  # 1% contamination
        max_features=0.8,
        max_samples=0.8,
        bootstrap=True,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train)
    
    # Evaluate
    scores = model.decision_function(X_normal[:1000])
    anomaly_scores = model.decision_function(X_anomalous)
    print(f"Normal mean score: {scores.mean():.4f} (higher=more normal)")
    print(f"Anomaly mean score: {anomaly_scores.mean():.4f} (lower=more anomalous)")
    
    # Export to ONNX
    print(f"\nExporting to ONNX: {OUTPUT_PATH}")
    initial_type = [('float_input', FloatTensorType([None, FEATURE_DIMENSION]))]
    onnx_model = convert_sklearn(
        model,
        initial_types=initial_type,
        target_opset=15,
    )
    
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "wb") as f:
        f.write(onnx_model.SerializeToString())
    
    size_kb = os.path.getsize(OUTPUT_PATH) / 1024
    print(f"✅ Model exported: {size_kb:.1f} KB")
    print(f"   Path: {OUTPUT_PATH}")
    print(f"\nNext: run thor-agent with --model {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
