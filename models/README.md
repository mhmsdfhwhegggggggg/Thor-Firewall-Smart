# Aegis XDR — ONNX ML Models

> **Sovereign Conditional AI**: All six models run entirely on-premises.  
> No raw data ever leaves the deployment environment.  
> Models are updated via Federated Learning (gradient deltas only).

---

## Model Registry

| Model File | Purpose | Input Shape | Output | Inference Target |
|---|---|---|---|---|
| `thor_master_brain_v3_2026.onnx` | Primary threat classifier | (1, 32) float32 | score (0–1) | ≤ 30 µs |
| `thor_deep_brain_v2_2026.onnx` | Deep L7/WAF anomaly detection | (1, 64) float32 | score (0–1) | ≤ 30 µs |
| `thor_gnn_chain_detector_v2_2025.onnx` | Graph neural network — kill-chain correlation | (N, 32) float32 | chain_score | ≤ 50 µs |
| `thor_malware_classifier_v2_2025.onnx` | Static + behavioral malware classification | (1, 128) float32 | class_id + confidence | ≤ 40 µs |
| `thor_ueba_model.onnx` | User/entity behavioral anomaly (IsolationForest) | (1, 32) float32 | [label, anomaly_score] | ≤ 1 ms |
| `thor_zero_day_guardian_v7_2026.onnx` | Zero-day exploit primitive detection | (1, 256) float32 | exploit_score | ≤ 50 µs |

---

## Feature Schemas

### Master Brain / UEBA — 32-dimensional vector

| Index | Feature | Range | Agent |
|---|---|---|---|
| 0 | Event type (0=net, 1=proc, 2=xdp, 3=web) | 0–3 | All |
| 1 | Destination port (normalized) | 0–1 | Net, Web |
| 2 | Protocol (TCP=0.5, UDP=0.85, ICMP=0.1) | 0–1 | Net |
| 3 | Direction (0=inbound, 1=outbound) | 0–1 | Net |
| 4 | Is RFC1918 destination | 0/1 | Net |
| 5 | UID normalized (1.0 = root) | 0–1 | Server |
| 6 | PID normalized | 0–1 | Server |
| 7 | Hour of day | 0–1 | All |
| 8–11 | Destination IP octets | 0–1 each | Net |
| 12–15 | Process name encoding (4-byte hash) | 0–1 | Server |
| 8 | CPU usage percentage | 0–1 | Server |
| 9 | Memory usage (MB/4096) | 0–1 | Server |
| 10 | Command line length (clamped at 512) | 0–1 | Server |
| 11 | Parent PID normalized | 0–1 | Server |
| 13 | DGA entropy (normalized, /8.0) | 0–1 | Net |
| 14 | PPS rate (normalized, /1M) | 0–1 | Net |
| 15 | Is TLS port (443/8443) | 0/1 | Net |
| 16 | Is DNS port (53) | 0/1 | Net |
| 17 | Is known C2 port (4444/1337/6666) | 0/1 | Net |
| 18–31 | Flow statistics / reserved | 0–1 | All |

### Deep Brain — 64-dimensional vector (Web Agent)

| Index | Feature | Range |
|---|---|---|
| 0–31 | Same as Master Brain base | 0–1 |
| 32 | URI length (normalized /2048) | 0–1 |
| 33 | Body length (normalized /65536) | 0–1 |
| 34 | OWASP hit count (normalized /20) | 0–1 |
| 35 | Rate limit proximity (req/RPM) | 0–1 |
| 36 | JA4H fingerprint hash (low 16 bits) | 0–1 |
| 37 | Content-Type category | 0–1 |
| 38 | Is TLS terminated | 0/1 |
| 39 | Method encoding (GET=0.2, POST=0.8, PUT=0.5, ...) | 0–1 |
| 40–63 | Payload n-gram features (reserved) | 0–1 |

---

## Confidence Thresholds & Conditional Autonomy

All agents use the same threshold model — controlled by SOC policy:

```
score ≥ SOC_THRESHOLD (default 0.90)  → Autonomous action
score ∈ [0.50, SOC_THRESHOLD)         → Escalate to SOC inbox
score < 0.50                           → Log only
```

**Default thresholds per agent (adjustable via SOC Dashboard):**

| Agent | Default Threshold | Allowed Auto-Actions |
|---|---|---|
| Network (XDP) | 90% | XDP_DROP, RATE_LIMIT, REDIRECT_HONEYPOT |
| Web (WAF) | 90% | WAF_BLOCK, CHALLENGE, RATE_LIMIT |
| Server (EDR) | 90% | PROCESS_ALERT, FILE_QUARANTINE |

> ⚠️ **PROCESS_KILL** is intentionally **not** on the autonomous allowlist by default.  
> It requires explicit SOC approval to prevent service disruption.

---

## Federated Learning — Training & Update Pipeline

### 1. Local Training (Agent-Side, every 24h)

```bash
# Run on the agent host — generates gradient delta, NOT exported model
python ml/online_learning.py \
  --model-path models/thor_master_brain_v3_2026.onnx \
  --local-events /var/log/thor/events.jsonl \
  --output-delta /tmp/fl_delta_$(hostname).bin
```

### 2. Contribution (Automatic via Agent)

Agents automatically POST gradient deltas to the SOC FL coordinator:
```
POST /api/v1/fl/contribute
{
  "round_id": "<uuid>",
  "agent_id": "net-hostname",
  "model_id": "thor_master_brain_v3_2026",
  "local_samples": 4821,
  "jsd_metric": 0.08,
  "layer_deltas": { "dense_1": [...], "output": [...] }
}
```

### 3. Aggregation (SOC Coordinator — FedAvg)

```bash
python ml/online_learning.py \
  --mode aggregate \
  --deltas-dir /var/thor/fl-rounds/current/ \
  --output-model models/thor_master_brain_v4_2026.onnx
```

### 4. SOC Approval Gate

If `max_jsd > 0.15` (significant distribution shift detected):
1. SOC coordinator flags the round as `retrain_proposed`
2. SOC analyst reviews via Dashboard → FL tab
3. Approval triggers model distribution to all agents
4. Action is recorded in tamper-evident audit log

### 5. Model Distribution

```bash
python ml/online_learning.py \
  --mode distribute \
  --new-model models/thor_master_brain_v4_2026.onnx \
  --agents-list /etc/thor/agents.txt
```

---

## Initial Model Training

If models are missing (fresh install):

```bash
pip install scikit-learn skl2onnx onnx numpy
python scripts/train_and_export.py --all
```

This generates all models using IsolationForest / GradientBoosting on  
synthetic behavioral profiles. Production deployments should train on  
real traffic with appropriate data governance controls.

---

## Model Verification

Verify ONNX model integrity before loading:

```bash
python -c "
import onnx
for f in models/*.onnx:
    m = onnx.load(f)
    onnx.checker.check_model(m)
    print(f'OK: {f}')
"
```

---

## XAI — How Decisions are Explained

Every inference result includes a **SHAP-approximated explanation**:

```json
{
  "summary": "High entropy DNS query (3.8 bits) + known C2 port 4444 + IOC match",
  "top_features": [
    {"feature_name": "ioc_match",       "importance": 0.50, "value": "Feodo-C2-tracker"},
    {"feature_name": "suspicious_port", "importance": 0.25, "value": "dst_port=4444"},
    {"feature_name": "dga_entropy",     "importance": 0.20, "value": "entropy=3.82"}
  ],
  "triggered_signals": ["FEODO_C2_IOC", "OWASP-SQLi", "SIGMA-T1071.001"],
  "counterfactual": "Remove IOC-matched domain from DNS query",
  "explanation_method": "shap-approximation"
}
```

All XAI outputs are stored in the tamper-evident audit log  
and displayed in the SOC Dashboard for every escalated event.

---

## Compliance Notes

- **GDPR Article 22**: All automated decisions include XAI explanation + human review path
- **SOC 2 Type II**: Audit chain provides immutable evidence for all security actions
- **PCI-DSS 10.x**: Log retention policy enforced via SOC engine configuration
- **ISO 27001 A.12.4**: All model updates and policy changes logged with analyst attribution

---

*Aegis XDR — Sovereign Conditional AI Platform v2.0.0*  
*Thor Firewall Smart — Production-grade XDR for Linux, Windows, Cloud & Edge*
