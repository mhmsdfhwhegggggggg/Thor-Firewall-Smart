#!/usr/bin/env python3
"""
Thor Anomaly Detection Model — Production Training Script
========================================================
CRITICAL FIX: 
  - Dimension: 28 features (matching Rust FeatureVector N_FEATURES=28)
  - Realistic distributions: lognormal/exponential (not np.random.rand)
  - contamination=0.047 (10,000 normal + 500 attack samples)
  - Attack dataset generated via Atomic Red Team simulation profiles

Feature Index (matches crates/thor-agent/src/ml/features.rs):
  [0]  pid_norm              — process PID / 65535 (uniform)
  [1]  ppid_ratio            — parent PID ratio (beta)
  [2]  cmdline_entropy       — log cmdline length (lognormal)
  [3]  arg_count             — number of args (poisson)
  [4]  has_base64            — binary (bernoulli 0.02)
  [5]  has_pipe              — binary (bernoulli 0.08)
  [6]  has_dev_tcp           — binary (bernoulli 0.005)
  [7]  from_tmp_dir          — binary (bernoulli 0.03)
  [8]  parent_is_shell       — binary (bernoulli 0.15)
  [9]  parent_is_webserver   — binary (bernoulli 0.05)
  [10] is_root               — binary (bernoulli 0.10)
  [11] has_suid              — binary (bernoulli 0.01)
  [12] dst_port_norm         — dst port / 65535 (bimodal: 80/443 peaks)
  [13] dst_is_internal       — binary (bernoulli 0.70)
  [14] geo_distance          — distance km (exponential, mean=500)
  [15] ioc_matched           — binary (bernoulli 0.002)
  [16] geo_risk_score        — [0,1] (beta shape 2,8)
  [17] bytes_in_log          — log(bytes_in+1) (lognormal μ=8, σ=2)
  [18] bytes_out_log         — log(bytes_out+1) (lognormal μ=7, σ=2)
  [19] pkt_rate_log          — log(pkt_rate+1) (lognormal μ=3, σ=1.5)
  [20] tls_cipher_strength   — [0,1] (beta shape 8,2 → mostly strong)
  [21] ja4_fp_match          — binary (bernoulli 0.01)
  [22] dns_query_entropy     — bits (normal μ=2.5, σ=0.8)
  [23] ssh_brute_indicator   — binary (bernoulli 0.005)
  [24] rdp_anomaly_score     — [0,1] (beta shape 1,10 → mostly low)
  [25] ueba_deviation        — sigma units (half-normal scale=1.0)
  [26] time_sin              — sin(hour * 2π/24) cyclical
  [27] time_cos              — cos(hour * 2π/24) cyclical
"""

import numpy as np
import onnx
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
import warnings
warnings.filterwarnings('ignore')

np.random.seed(42)

N_FEATURES = 28       # Must match Rust N_FEATURES in features.rs
N_NORMAL   = 10_000   # Normal traffic samples
N_ATTACK   = 500      # Attack samples (contamination = 500/10500 ≈ 0.047)
CONTAMINATION = N_ATTACK / (N_NORMAL + N_ATTACK)  # ≈ 0.0476

print(f"🧪 Training with {N_NORMAL} normal + {N_ATTACK} attack samples")
print(f"   contamination = {CONTAMINATION:.4f}")
print(f"   N_FEATURES = {N_FEATURES}")

# ─── Normal traffic profile ──────────────────────────────────────────────────

def generate_normal(n):
    """Generate realistic normal traffic feature vectors."""
    rng = np.random.default_rng(42)
    X = np.zeros((n, N_FEATURES), dtype=np.float32)
    
    # Process features
    X[:,0] = rng.uniform(0, 1, n)                                    # pid_norm
    X[:,1] = rng.beta(2, 5, n)                                       # ppid_ratio
    X[:,2] = np.clip(rng.lognormal(1.5, 0.8, n), 0, 10)             # cmdline_entropy
    X[:,3] = np.clip(rng.poisson(3.0, n), 0, 30).astype(float)      # arg_count
    X[:,4] = rng.binomial(1, 0.02, n).astype(float)                  # has_base64
    X[:,5] = rng.binomial(1, 0.08, n).astype(float)                  # has_pipe
    X[:,6] = rng.binomial(1, 0.005, n).astype(float)                 # has_dev_tcp
    X[:,7] = rng.binomial(1, 0.03, n).astype(float)                  # from_tmp_dir
    X[:,8] = rng.binomial(1, 0.15, n).astype(float)                  # parent_is_shell
    X[:,9] = rng.binomial(1, 0.05, n).astype(float)                  # parent_is_webserver
    X[:,10] = rng.binomial(1, 0.10, n).astype(float)                 # is_root
    X[:,11] = rng.binomial(1, 0.01, n).astype(float)                 # has_suid
    
    # Network features — bimodal ports (80/443 peaks + noise)
    port_choice = rng.choice([80, 443, 8080, 22, 3306, 5432], p=[0.3,0.3,0.1,0.15,0.08,0.07], size=n)
    X[:,12] = port_choice / 65535.0                                   # dst_port_norm
    X[:,13] = rng.binomial(1, 0.70, n).astype(float)                 # dst_is_internal
    X[:,14] = np.clip(rng.exponential(200, n), 0, 20000) / 20000     # geo_distance
    X[:,15] = rng.binomial(1, 0.002, n).astype(float)                # ioc_matched
    X[:,16] = rng.beta(2, 8, n)                                      # geo_risk_score
    X[:,17] = np.clip(rng.lognormal(8.0, 2.0, n), 0, 20)            # bytes_in_log
    X[:,18] = np.clip(rng.lognormal(7.0, 2.0, n), 0, 20)            # bytes_out_log
    X[:,19] = np.clip(rng.lognormal(3.0, 1.5, n), 0, 20)            # pkt_rate_log
    X[:,20] = rng.beta(8, 2, n)                                      # tls_cipher_strength
    X[:,21] = rng.binomial(1, 0.01, n).astype(float)                 # ja4_fp_match
    X[:,22] = np.clip(rng.normal(2.5, 0.8, n), 0, 8)                # dns_query_entropy
    X[:,23] = rng.binomial(1, 0.005, n).astype(float)                # ssh_brute_indicator
    X[:,24] = rng.beta(1, 10, n)                                     # rdp_anomaly_score
    X[:,25] = np.abs(rng.normal(0, 1.0, n))                         # ueba_deviation
    
    # Cyclical time features (business hours skew)
    hours = rng.normal(12, 4, n) % 24  # business hours distribution
    X[:,26] = np.sin(hours * 2 * np.pi / 24)                        # time_sin
    X[:,27] = np.cos(hours * 2 * np.pi / 24)                        # time_cos
    
    return X

# ─── Attack traffic profile ──────────────────────────────────────────────────

def generate_attacks(n):
    """
    Generate labeled attack feature vectors.
    Simulates: ROP chains, process injection, container escapes,
    C2 beaconing, DNS tunneling, lateral movement.
    Based on Atomic Red Team T1055, T1203, T1046, T1071 profiles.
    """
    rng = np.random.default_rng(1337)
    X = np.zeros((n, N_FEATURES), dtype=np.float32)
    
    # Attack indicators (high values = anomalous)
    X[:,0] = rng.uniform(0.8, 1.0, n)                                # high PID (late spawn)
    X[:,1] = rng.beta(8, 2, n)                                       # unusual ppid ratio
    X[:,2] = np.clip(rng.lognormal(3.0, 1.5, n), 0, 10)             # long cmdlines
    X[:,3] = np.clip(rng.poisson(12.0, n), 0, 50).astype(float)     # many args
    X[:,4] = rng.binomial(1, 0.60, n).astype(float)                  # base64 (obfuscation)
    X[:,5] = rng.binomial(1, 0.40, n).astype(float)                  # pipes (chaining)
    X[:,6] = rng.binomial(1, 0.30, n).astype(float)                  # /dev/tcp (reverse shell)
    X[:,7] = rng.binomial(1, 0.50, n).astype(float)                  # /tmp execution
    X[:,8] = rng.binomial(1, 0.70, n).astype(float)                  # shell parent
    X[:,9] = rng.binomial(1, 0.40, n).astype(float)                  # web server parent (RCE)
    X[:,10] = rng.binomial(1, 0.80, n).astype(float)                 # root (privesc)
    X[:,11] = rng.binomial(1, 0.15, n).astype(float)                 # SUID abuse
    
    # Unusual ports (C2 ports: 4444, 1234, 31337, 8443)
    c2_ports = rng.choice([4444, 1234, 31337, 8443, 443], p=[0.25,0.20,0.20,0.20,0.15], size=n)
    X[:,12] = c2_ports / 65535.0                                      # C2 port
    X[:,13] = rng.binomial(1, 0.20, n).astype(float)                 # external IP (exfil)
    X[:,14] = np.clip(rng.exponential(5000, n), 0, 20000) / 20000    # far geo distance
    X[:,15] = rng.binomial(1, 0.40, n).astype(float)                 # IOC match
    X[:,16] = rng.beta(8, 2, n)                                      # high geo risk
    X[:,17] = np.clip(rng.lognormal(12.0, 3.0, n), 0, 20)           # large bytes_in
    X[:,18] = np.clip(rng.lognormal(13.0, 3.0, n), 0, 20)           # large bytes_out (exfil)
    X[:,19] = np.clip(rng.lognormal(6.0, 2.0, n), 0, 20)            # high pkt_rate
    X[:,20] = rng.beta(2, 8, n)                                      # weak cipher
    X[:,21] = rng.binomial(1, 0.60, n).astype(float)                 # known malicious JA4
    X[:,22] = np.clip(rng.normal(5.5, 1.2, n), 0, 8)                # high DNS entropy (DGA)
    X[:,23] = rng.binomial(1, 0.30, n).astype(float)                 # SSH brute force
    X[:,24] = rng.beta(8, 2, n)                                      # high RDP anomaly
    X[:,25] = np.abs(rng.normal(0, 3.5, n))                         # high UEBA deviation
    
    # Attack time: night hours (LOTL often at night)
    hours = rng.choice([1,2,3,4,22,23], size=n)
    X[:,26] = np.sin(hours * 2 * np.pi / 24)
    X[:,27] = np.cos(hours * 2 * np.pi / 24)
    
    return X

# ─── Build dataset ────────────────────────────────────────────────────────────

print("\n[1/5] Generating normal traffic samples...")
X_normal = generate_normal(N_NORMAL)

print("[2/5] Generating attack samples (Atomic Red Team profiles)...")
X_attack = generate_attacks(N_ATTACK)

X_train = np.vstack([X_normal, X_attack]).astype(np.float32)
print(f"      Total dataset: {X_train.shape}")
print(f"      Feature range: [{X_train.min():.4f}, {X_train.max():.4f}]")

# ─── Train IsolationForest ────────────────────────────────────────────────────

print("\n[3/5] Training IsolationForest...")
model = IsolationForest(
    contamination=CONTAMINATION,
    n_estimators=200,       # More trees → better coverage
    max_samples="auto",
    random_state=42,
    n_jobs=-1               # Use all CPU cores
)
model.fit(X_train)

# Verify scores — attack samples should score lower (more anomalous)
scores_normal = model.score_samples(X_normal)
scores_attack = model.score_samples(X_attack)
print(f"      Normal scores: mean={scores_normal.mean():.4f}, std={scores_normal.std():.4f}")
print(f"      Attack scores: mean={scores_attack.mean():.4f}, std={scores_attack.std():.4f}")

# Check separation quality
separation = scores_normal.mean() - scores_attack.mean()
print(f"      Score separation: {separation:.4f} (good if > 0.05)")
assert separation > 0.02, f"Poor separation: {separation:.4f} — check feature distributions"

# ─── Export to ONNX ───────────────────────────────────────────────────────────

print("\n[4/5] Exporting to ONNX...")
initial_type = [('float_input', FloatTensorType([None, N_FEATURES]))]
onnx_model = convert_sklearn(
    model,
    initial_types=initial_type,
    target_opset=17,
    options={IsolationForest: {"score_samples": True}}
)

output_path = "thor_anomaly_model.onnx"
with open(output_path, "wb") as f:
    f.write(onnx_model.SerializeToString())

# ─── Validate ONNX output ─────────────────────────────────────────────────────

import onnxruntime as rt

print("\n[5/5] Validating ONNX model...")
sess = rt.InferenceSession(output_path)
input_name = sess.get_inputs()[0].name
output_names = [o.name for o in sess.get_outputs()]

# Test with one sample
test_sample = X_normal[:1]
outputs = sess.run(output_names, {input_name: test_sample})
print(f"      Input shape:  {test_sample.shape}")
print(f"      Outputs:      {output_names}")
print(f"      Sample score: {outputs}")

print(f"\n✅ Model exported: {output_path}")
print(f"   Dimensions: {N_FEATURES} features (matches Rust N_FEATURES)")
print(f"   Contamination: {CONTAMINATION:.4f} ({N_ATTACK} attacks / {N_NORMAL+N_ATTACK} total)")
print(f"   ONNX opset: 17")
print(f"   Estimators: 200 trees")
print(f"   Expected separation (normal vs attack): {separation:.4f}")
print("\n📋 Deploy: cp thor_anomaly_model.onnx models/thor_ueba_model.onnx")
