#!/usr/bin/env python3
"""
Thor Firewall Smart — AI Model Training Pipeline 2025/2026
مهندس النظام: Thor Security Team | التحديث: يونيو 2026

يُدرّب 5 نماذج ONNX متقدمة:
  1. UEBA v2 — IsolationForest (48 features, 2025 threats)
  2. Malware Classifier v2 — RandomForest (64 features, 10 classes)
  3. GNN Chain Detector v2 — GradientBoosting (160 features)
  4. Ransomware Detector v1 — RandomForest (32 features, 2025 families)
  5. AI Threat Detector v1 — RandomForest (24 features, LLM/AI attacks)
"""

import sys, os, json, time
import numpy as np
from pathlib import Path
from sklearn.ensemble import (
    IsolationForest, RandomForestClassifier, GradientBoostingClassifier
)
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, roc_auc_score
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

MODELS_DIR = Path(__file__).parent.parent / "models"
MODELS_DIR.mkdir(exist_ok=True)
SEED = 2025
np.random.seed(SEED)

print("=" * 65)
print("  Thor Firewall Smart — AI Training Pipeline 2025/2026")
print("=" * 65)
print(f"  Output: {MODELS_DIR}")
print(f"  Time:   {time.strftime('%Y-%m-%d %H:%M:%S')}")
print()

results = {}

# ─────────────────────────────────────────────────────────────────────────────
# 1. UEBA v2 — IsolationForest (48 features)
# ─────────────────────────────────────────────────────────────────────────────
print("[1/5] UEBA Anomaly Detector v2 (IsolationForest, 48 features)")
print("      2025 Threats: RaaS, Supply Chain, AI Attacks, Cloud-Native,")
print("      C2-DoH/WS, eBPF Rootkits, LotL, Data Exfil, Lateral Movement")

F = 48
rng = np.random.default_rng(SEED)

n_n, n_a = 80_000, 5_000
Xn = np.zeros((n_n, F), dtype=np.float32)
Xn[:, 0]  = rng.choice([0,1,2,3,4], n_n, p=[0.60,0.20,0.10,0.07,0.03])
Xn[:, 1]  = rng.choice([80/65535,443/65535,53/65535,22/65535,8080/65535], n_n)
Xn[:, 2]  = rng.choice([0.0,0.5,0.85,1.0], n_n, p=[0.65,0.25,0.08,0.02])
Xn[:, 3]  = rng.choice([0,1], n_n, p=[0.30,0.70])
Xn[:, 4]  = rng.choice([0,1], n_n, p=[0.60,0.40])
Xn[:, 5]  = rng.uniform(1000/65535, 2000/65535, n_n)
Xn[:, 6]  = rng.uniform(100/100000, 60000/100000, n_n)
h = rng.choice(range(8,19), n_n) / 23.0
Xn[:, 7]  = h
Xn[:, 8:12] = rng.uniform(0, 1, (n_n, 4))
Xn[:, 12] = rng.uniform(3, 12, n_n)
Xn[:, 13] = rng.uniform(3, 14, n_n)
Xn[:, 14] = rng.uniform(0, 5, n_n)
Xn[:, 15] = rng.choice([0,1], n_n, p=[0.999,0.001])
Xn[:, 16:46] = rng.uniform(0, 0.15, (n_n, 30))
hr = Xn[:, 7] * 23
Xn[:, 46] = np.sin(hr * 2 * np.pi / 24).astype(np.float32)
Xn[:, 47] = np.cos(hr * 2 * np.pi / 24).astype(np.float32)

Xa = np.zeros((n_a, F), dtype=np.float32)
# توزيع تهديدات 2025
n_per = n_a // 10
# RaaS
Xa[0:n_per, 12] = rng.uniform(15,20,n_per); Xa[0:n_per, 25]=1; Xa[0:n_per, 30]=1; Xa[0:n_per, 32]=5/6
# Supply Chain
i=n_per; Xa[i:i+n_per, 43]=1; Xa[i:i+n_per, 24]=1; Xa[i:i+n_per, 4]=1
# AI Attack
i=2*n_per; Xa[i:i+n_per, 41]=1; Xa[i:i+n_per, 42]=1; Xa[i:i+n_per, 12]=rng.uniform(12,18,n_per)
# Cloud Native
i=3*n_per; Xa[i:i+n_per, 38]=1; Xa[i:i+n_per, 39]=1; Xa[i:i+n_per, 40]=1; Xa[i:i+n_per, 30]=1
# C2 DoH/WS
i=4*n_per; Xa[i:i+n_per, 44]=1; Xa[i:i+n_per, 45]=1; Xa[i:i+n_per, 20]=rng.uniform(0.7,1,n_per)
# eBPF Rootkit
i=5*n_per; Xa[i:i+n_per, 30]=1; Xa[i:i+n_per, 31]=1; Xa[i:i+n_per, 16]=rng.uniform(0.7,1,n_per)
# LotL
i=6*n_per; Xa[i:i+n_per, 23]=1; Xa[i:i+n_per, 24]=1; Xa[i:i+n_per, 27]=1; Xa[i:i+n_per, 28]=1
# Data Exfil
i=7*n_per; Xa[i:i+n_per, 4]=1; Xa[i:i+n_per, 12]=rng.uniform(16,20,n_per); Xa[i:i+n_per, 17]=rng.uniform(0.7,1,n_per)
# Lateral Movement
i=8*n_per; Xa[i:i+n_per, 34]=rng.uniform(0.7,1,n_per); Xa[i:i+n_per, 36]=rng.uniform(0.8,1,n_per)
# Credential Harvest
i=9*n_per; n_rem=n_a-i; Xa[i:, 35]=rng.uniform(0.7,1,n_rem); Xa[i:, 30]=1

Xa[:, 7] = rng.choice([2/23,3/23,4/23], n_a)
hr_a = Xa[:, 7] * 23
Xa[:, 46] = np.sin(hr_a * 2 * np.pi / 24).astype(np.float32)
Xa[:, 47] = np.cos(hr_a * 2 * np.pi / 24).astype(np.float32)

Xt = np.vstack([Xn, Xa])
cont = n_a / len(Xt)

t0 = time.time()
m1 = IsolationForest(n_estimators=200, contamination=cont, max_features=1.0,
                     max_samples=0.8, bootstrap=True, random_state=SEED, n_jobs=-1)
m1.fit(Xt)
elapsed = time.time() - t0

sn = m1.decision_function(Xn[:2000])
sa = m1.decision_function(Xa)
print(f"      Time: {elapsed:.1f}s | Normal: {sn.mean():.4f} | Anomaly: {sa.mean():.4f} | Sep: {(sn.mean()-sa.mean()):.4f}")

it = [('float_input', FloatTensorType([None, F]))]
om = convert_sklearn(m1, initial_types=it, target_opset=15)
p1a = MODELS_DIR / "thor_ueba_model_v2_2025.onnx"
p1b = MODELS_DIR / "thor_ueba_model.onnx"
for p in [p1a, p1b]:
    p.write_bytes(om.SerializeToString())
print(f"      ✅ {p1a.name} ({p1a.stat().st_size/1024:.0f} KB)")
results['ueba_v2'] = {'path': str(p1a), 'features': F, 'size_kb': p1a.stat().st_size/1024}

# ─────────────────────────────────────────────────────────────────────────────
# 2. Malware Classifier v2 — RandomForest (64 features, 10 classes)
# ─────────────────────────────────────────────────────────────────────────────
print("\n[2/5] Malware Classifier v2 (RandomForest, 64 features, 10 classes)")

CLASSES = ['benign','ransomware_raas','apt_lotl','cryptominer','botnet_mirai',
           'reverse_shell','supply_chain','ai_model_theft','cloud_stealer','ebpf_rootkit']
F2 = 64
rng2 = np.random.default_rng(SEED+1)
n_per = 6000
Xl, yl = [], []

for ci, cn in enumerate(CLASSES):
    X = np.zeros((n_per, F2), dtype=np.float32)
    if cn == 'benign':
        X = rng2.uniform(0, 0.25, (n_per, F2)).astype(np.float32)
    elif cn == 'ransomware_raas':
        X[:, 0]=rng2.uniform(0.8,1.0,n_per); X[:, 1]=rng2.uniform(0.7,1.0,n_per)
        X[:, 2]=rng2.uniform(0.9,1.0,n_per); X[:, 24]=rng2.uniform(0.85,1.0,n_per)
        X[:, 32]=rng2.uniform(0.7,1.0,n_per); X[:, 33]=rng2.uniform(0.6,1.0,n_per)
    elif cn == 'apt_lotl':
        X[:, 3]=rng2.uniform(0.7,1.0,n_per); X[:, 4]=rng2.uniform(0.6,1.0,n_per)
        X[:, 5]=rng2.uniform(0.5,1.0,n_per); X[:, 35]=rng2.uniform(0.6,1.0,n_per)
    elif cn == 'cryptominer':
        X[:, 10]=rng2.uniform(0.85,1.0,n_per); X[:, 11]=rng2.uniform(0.7,1.0,n_per)
        X[:, 12]=rng2.uniform(0.6,1.0,n_per); X[:, 37]=rng2.uniform(0.8,1.0,n_per)
    elif cn == 'botnet_mirai':
        X[:, 13]=rng2.uniform(0.8,1.0,n_per); X[:, 14]=rng2.uniform(0.7,1.0,n_per)
        X[:, 15]=rng2.uniform(0.6,1.0,n_per); X[:, 38]=rng2.uniform(0.7,1.0,n_per)
    elif cn == 'reverse_shell':
        X[:, 16]=rng2.uniform(0.8,1.0,n_per); X[:, 17]=rng2.uniform(0.7,1.0,n_per)
        X[:, 18]=rng2.uniform(0.6,1.0,n_per); X[:, 39]=rng2.uniform(0.7,1.0,n_per)
    elif cn == 'supply_chain':
        X[:, 19]=rng2.uniform(0.8,1.0,n_per); X[:, 20]=rng2.uniform(0.7,1.0,n_per)
        X[:, 21]=rng2.uniform(0.6,1.0,n_per); X[:, 40]=rng2.uniform(0.5,1.0,n_per)
    elif cn == 'ai_model_theft':
        X[:, 22]=rng2.uniform(0.8,1.0,n_per); X[:, 23]=rng2.uniform(0.7,1.0,n_per)
        X[:, 41]=rng2.uniform(0.6,1.0,n_per); X[:, 42]=rng2.uniform(0.5,1.0,n_per)
    elif cn == 'cloud_stealer':
        X[:, 43]=rng2.uniform(0.8,1.0,n_per); X[:, 44]=rng2.uniform(0.7,1.0,n_per)
        X[:, 45]=rng2.uniform(0.6,1.0,n_per); X[:, 46]=rng2.uniform(0.5,1.0,n_per)
    elif cn == 'ebpf_rootkit':
        X[:, 47]=rng2.uniform(0.8,1.0,n_per); X[:, 48]=rng2.uniform(0.7,1.0,n_per)
        X[:, 49]=rng2.uniform(0.6,1.0,n_per); X[:, 50]=rng2.uniform(0.5,1.0,n_per)
        X[:, 51]=1.0
    noise = rng2.normal(0, 0.05, (n_per, F2))
    X = np.clip(X + noise, 0.0, 1.0).astype(np.float32)
    Xl.append(X); yl.extend([ci]*n_per)

Xa2 = np.vstack(Xl); ya2 = np.array(yl)
Xtr, Xte, ytr, yte = train_test_split(Xa2, ya2, test_size=0.15, random_state=SEED, stratify=ya2)

t0 = time.time()
m2 = RandomForestClassifier(n_estimators=200, max_depth=15, min_samples_leaf=3,
                             class_weight='balanced', random_state=SEED, n_jobs=-1)
m2.fit(Xtr, ytr)
elapsed = time.time() - t0

yp = m2.predict(Xte)
f1 = f1_score(yte, yp, average='weighted')
acc = (yp == yte).mean()
print(f"      Time: {elapsed:.1f}s | F1: {f1:.4f} | Acc: {acc:.4f}")

it2 = [('float_input', FloatTensorType([None, F2]))]
om2 = convert_sklearn(m2, initial_types=it2, target_opset=15)
p2 = MODELS_DIR / "thor_malware_classifier_v2_2025.onnx"
p2.write_bytes(om2.SerializeToString())
(MODELS_DIR / "malware_classes_2025.json").write_text(json.dumps(CLASSES, indent=2))
print(f"      ✅ {p2.name} ({p2.stat().st_size/1024:.0f} KB)")
results['malware_v2'] = {'path': str(p2), 'features': F2, 'classes': len(CLASSES), 'size_kb': p2.stat().st_size/1024}

# ─────────────────────────────────────────────────────────────────────────────
# 3. GNN Chain Detector v2 — GradientBoosting (160 features)
# ─────────────────────────────────────────────────────────────────────────────
print("\n[3/5] Attack Chain Detector v2 (GradientBoosting, 5×32=160 features)")

F3 = 160
rng3 = np.random.default_rng(SEED+2)
n_b, n_a3 = 30_000, 8_000

Xb3 = rng3.uniform(0, 0.25, (n_b, F3)).astype(np.float32)
yb3 = np.zeros(n_b, dtype=np.int32)

Xa3 = np.zeros((n_a3, F3), dtype=np.float32)
n1 = n_a3 // 3
# Pattern 1: Recon→Exploit→Install→C2→Exfil
Xa3[0:n1, 0:32]   = rng3.uniform(0.6,1.0,(n1,32)); Xa3[0:n1, 0]=0.9
Xa3[0:n1, 32:64]  = rng3.uniform(0.5,0.9,(n1,32)); Xa3[0:n1, 32]=0.85
Xa3[0:n1, 64:96]  = rng3.uniform(0.6,1.0,(n1,32)); Xa3[0:n1, 64]=0.9
Xa3[0:n1, 96:128] = rng3.uniform(0.5,0.9,(n1,32)); Xa3[0:n1, 96]=0.8
Xa3[0:n1, 128:]   = rng3.uniform(0.7,1.0,(n1,32)); Xa3[0:n1, 128]=0.95
# Pattern 2: Supply Chain→Lateral→PrivEsc→Exfil
Xa3[n1:2*n1, 5]=0.9; Xa3[n1:2*n1, 38]=0.85; Xa3[n1:2*n1, 70]=0.9; Xa3[n1:2*n1, 128]=0.95
# Pattern 3: AI Attack Chain (2025)
Xa3[2*n1:, 10]=0.9; Xa3[2*n1:, 47]=0.85; Xa3[2*n1:, 84]=0.9; Xa3[2*n1:, 121]=0.8; Xa3[2*n1:, 158]=0.95
ya3 = np.ones(n_a3, dtype=np.int32)

X3 = np.vstack([Xb3, Xa3]); y3 = np.concatenate([yb3, ya3])
Xtr3, Xte3, ytr3, yte3 = train_test_split(X3, y3, test_size=0.15, random_state=SEED, stratify=y3)

t0 = time.time()
m3 = GradientBoostingClassifier(n_estimators=150, max_depth=5, learning_rate=0.1,
                                  subsample=0.85, random_state=SEED,
                                  validation_fraction=0.1, n_iter_no_change=15)
m3.fit(Xtr3, ytr3)
elapsed = time.time() - t0

yp3 = m3.predict(Xte3)
ypr3 = m3.predict_proba(Xte3)[:,1]
f1_3 = f1_score(yte3, yp3)
auc3 = roc_auc_score(yte3, ypr3)
print(f"      Time: {elapsed:.1f}s | F1: {f1_3:.4f} | AUC: {auc3:.4f}")

it3 = [('float_input', FloatTensorType([None, F3]))]
om3 = convert_sklearn(m3, initial_types=it3, target_opset=15)
p3 = MODELS_DIR / "thor_gnn_chain_detector_v2_2025.onnx"
p3.write_bytes(om3.SerializeToString())
print(f"      ✅ {p3.name} ({p3.stat().st_size/1024:.0f} KB)")
results['gnn_v2'] = {'path': str(p3), 'features': F3, 'size_kb': p3.stat().st_size/1024}

# ─────────────────────────────────────────────────────────────────────────────
# 4. Ransomware Detector v1 — RandomForest (32 features, 2025 families)
# ─────────────────────────────────────────────────────────────────────────────
print("\n[4/5] Ransomware Detector v1 (RandomForest, 32 features)")
print("      Families: LockBit 4.0, BlackCat/ALPHV, Cl0p, Play, Akira, Rhysida")

F4 = 32
rng4 = np.random.default_rng(SEED+3)
n_b4, n_r4 = 50_000, 15_000

Xb4 = np.zeros((n_b4, F4), dtype=np.float32)
Xb4[:, 0:8]   = rng4.uniform(0, 0.2, (n_b4, 8))
Xb4[:, 8:16]  = rng4.uniform(0, 0.3, (n_b4, 8))
Xb4[:, 16:24] = rng4.uniform(0.3, 0.6, (n_b4, 8))
Xb4[:, 24:32] = rng4.uniform(0, 0.1, (n_b4, 8))

Xr4 = np.zeros((n_r4, F4), dtype=np.float32)
fams = {'lockbit4': 0.25, 'blackcat': 0.20, 'clop': 0.15, 'play': 0.15,
        'akira': 0.10, 'rhysida': 0.08, 'generic': 0.07}
idx4 = 0
for fam, frac in fams.items():
    n = int(n_r4 * frac)
    if idx4 + n > n_r4: n = n_r4 - idx4
    if n <= 0: break
    Xr4[idx4:idx4+n, 0] = rng4.uniform(0.8,1.0,n)   # file_write_rate
    Xr4[idx4:idx4+n, 1] = rng4.uniform(0.7,1.0,n)   # file_rename_rate
    Xr4[idx4:idx4+n, 2] = rng4.uniform(0.85,1.0,n)  # file_entropy
    Xr4[idx4:idx4+n, 3] = rng4.uniform(0.6,1.0,n)   # vss_delete
    Xr4[idx4:idx4+n, 4] = rng4.uniform(0.5,1.0,n)   # backup_deletion
    Xr4[idx4:idx4+n, 16] = rng4.uniform(0.85,1.0,n) # entropy_mean
    Xr4[idx4:idx4+n, 17] = rng4.uniform(0.9,1.0,n)  # entropy_variance
    if fam in ['clop','play','akira','rhysida']:
        Xr4[idx4:idx4+n, 5] = rng4.uniform(0.7,1.0,n)  # data_staging
        Xr4[idx4:idx4+n, 9] = rng4.uniform(0.6,1.0,n)  # exfil_before_encrypt
    if fam == 'lockbit4':
        Xr4[idx4:idx4+n, 24] = rng4.uniform(0.7,1.0,n)  # fast_encryption
        Xr4[idx4:idx4+n, 25] = rng4.uniform(0.6,1.0,n)  # multi_threaded
    noise = rng4.normal(0, 0.03, (n, F4))
    Xr4[idx4:idx4+n] = np.clip(Xr4[idx4:idx4+n] + noise, 0, 1).astype(np.float32)
    idx4 += n

X4 = np.vstack([Xb4, Xr4])
y4 = np.concatenate([np.zeros(n_b4), np.ones(n_r4)]).astype(np.int32)
Xtr4, Xte4, ytr4, yte4 = train_test_split(X4, y4, test_size=0.15, random_state=SEED, stratify=y4)

t0 = time.time()
m4 = RandomForestClassifier(n_estimators=200, max_depth=15, min_samples_leaf=5,
                             class_weight='balanced', random_state=SEED, n_jobs=-1)
m4.fit(Xtr4, ytr4)
elapsed = time.time() - t0

yp4 = m4.predict(Xte4)
ypr4 = m4.predict_proba(Xte4)[:,1]
f1_4 = f1_score(yte4, yp4)
auc4 = roc_auc_score(yte4, ypr4)
print(f"      Time: {elapsed:.1f}s | F1: {f1_4:.4f} | AUC: {auc4:.4f}")

it4 = [('float_input', FloatTensorType([None, F4]))]
om4 = convert_sklearn(m4, initial_types=it4, target_opset=15)
p4 = MODELS_DIR / "thor_ransomware_detector_v1_2025.onnx"
p4.write_bytes(om4.SerializeToString())
print(f"      ✅ {p4.name} ({p4.stat().st_size/1024:.0f} KB)")
results['ransomware_v1'] = {'path': str(p4), 'features': F4, 'size_kb': p4.stat().st_size/1024}

# ─────────────────────────────────────────────────────────────────────────────
# 5. AI Threat Detector v1 — RandomForest (24 features)
# ─────────────────────────────────────────────────────────────────────────────
print("\n[5/5] AI Threat Detector v1 (RandomForest, 24 features) — NEW 2025")
print("      Threats: Prompt Injection, Model Theft, Adversarial, Data Poisoning,")
print("               Model Inversion, Membership Inference, LLM Jailbreak")

F5 = 24
rng5 = np.random.default_rng(SEED+4)
n_b5, n_t5 = 40_000, 10_000

Xb5 = rng5.uniform(0, 0.2, (n_b5, F5)).astype(np.float32)

Xt5 = np.zeros((n_t5, F5), dtype=np.float32)
threats = {
    'prompt_injection': (0.25, [0,1,2]),
    'model_theft':      (0.20, [3,4,5]),
    'adversarial':      (0.15, [6,7]),
    'data_poisoning':   (0.15, [8,9]),
    'model_inversion':  (0.10, [10,11]),
    'membership_inf':   (0.10, [12,13]),
    'llm_jailbreak':    (0.05, [14,15,16]),
}
idx5 = 0
for t, (frac, feat_idxs) in threats.items():
    n = int(n_t5 * frac)
    if idx5 + n > n_t5: n = n_t5 - idx5
    if n <= 0: break
    for fi in feat_idxs:
        Xt5[idx5:idx5+n, fi] = rng5.uniform(0.7, 1.0, n)
    Xt5[idx5:idx5+n, 20] = rng5.uniform(0.6,1.0,n)  # api_rate_anomaly
    Xt5[idx5:idx5+n, 21] = rng5.uniform(0.5,1.0,n)  # unusual_payload
    Xt5[idx5:idx5+n, 22] = rng5.uniform(0.4,1.0,n)  # external_origin
    Xt5[idx5:idx5+n, 23] = rng5.uniform(0.3,1.0,n)  # off_hours
    noise = rng5.normal(0, 0.04, (n, F5))
    Xt5[idx5:idx5+n] = np.clip(Xt5[idx5:idx5+n] + noise, 0, 1).astype(np.float32)
    idx5 += n

X5 = np.vstack([Xb5, Xt5])
y5 = np.concatenate([np.zeros(n_b5), np.ones(n_t5)]).astype(np.int32)
Xtr5, Xte5, ytr5, yte5 = train_test_split(X5, y5, test_size=0.15, random_state=SEED, stratify=y5)

t0 = time.time()
m5 = RandomForestClassifier(n_estimators=200, max_depth=12, min_samples_leaf=5,
                             class_weight='balanced', random_state=SEED, n_jobs=-1)
m5.fit(Xtr5, ytr5)
elapsed = time.time() - t0

yp5 = m5.predict(Xte5)
ypr5 = m5.predict_proba(Xte5)[:,1]
f1_5 = f1_score(yte5, yp5)
auc5 = roc_auc_score(yte5, ypr5)
print(f"      Time: {elapsed:.1f}s | F1: {f1_5:.4f} | AUC: {auc5:.4f}")

it5 = [('float_input', FloatTensorType([None, F5]))]
om5 = convert_sklearn(m5, initial_types=it5, target_opset=15)
p5 = MODELS_DIR / "thor_ai_threat_detector_v1_2025.onnx"
p5.write_bytes(om5.SerializeToString())
print(f"      ✅ {p5.name} ({p5.stat().st_size/1024:.0f} KB)")
results['ai_threat_v1'] = {'path': str(p5), 'features': F5, 'size_kb': p5.stat().st_size/1024}

# ─────────────────────────────────────────────────────────────────────────────
# Manifest
# ─────────────────────────────────────────────────────────────────────────────
manifest = {
    "version": "2.0.0-2025",
    "trained_at": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
    "training_data_year": 2025,
    "threat_coverage": [
        "ransomware_raas_gen5_lockbit4_blackcat_clop_play_akira_rhysida",
        "supply_chain_npm_pypi_poisoning",
        "ai_llm_attacks_prompt_injection_model_theft",
        "cloud_native_k8s_imds_abuse",
        "c2_dns_over_https_websocket_beacon",
        "ebpf_rootkits_kernel_hooking",
        "lotl_advanced_lolbins_wmi",
        "data_exfiltration_large_transfer",
        "lateral_movement_gnn_detection",
        "credential_harvesting_brute_force",
        "adversarial_ml_attacks",
        "membership_inference_attacks",
        "model_inversion_attacks",
    ],
    "models": {k: v for k, v in results.items()},
    "performance": {
        "ueba_separation_ratio": float(f"{(sn.mean()-sa.mean()):.4f}"),
        "malware_f1_weighted": float(f"{f1:.4f}"),
        "chain_detector_auc": float(f"{auc3:.4f}"),
        "ransomware_auc": float(f"{auc4:.4f}"),
        "ai_threat_auc": float(f"{auc5:.4f}"),
    }
}

mp = MODELS_DIR / "model_manifest_2025.json"
mp.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))

total_size = sum(r['size_kb'] for r in results.values())
print("\n" + "=" * 65)
print("  ✅ ALL 5 MODELS TRAINED AND EXPORTED SUCCESSFULLY")
print("=" * 65)
print(f"  Total model size: {total_size:.0f} KB")
print(f"  Manifest: {mp.name}")
print()
print("  Model Summary:")
for name, info in results.items():
    print(f"    • {Path(info['path']).name:50s} {info['size_kb']:.0f} KB")
print("=" * 65)
