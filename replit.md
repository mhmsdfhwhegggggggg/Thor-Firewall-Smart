# Thor Firewall Smart

**Enterprise cybersecurity platform competing with CrowdStrike and Palo Alto Networks.**
100% standalone — concepts from Wazuh/Suricata/Zeek/Sigma/YARA re-implemented natively in Rust.

## Run & Operate

```bash
# Build
cargo build --release

# Run agent (requires root for eBPF)
THOR_JWT_SECRET=$(openssl rand -hex 64) \
THOR_ADMIN_PASSWORD=$(openssl rand -base64 32) \
./target/release/thor-agent --interface eth0

# Train ML model
pip install scikit-learn skl2onnx onnx numpy
python3 ml/train_thor_ueba.py --output models/thor_ueba_model.onnx

# Run tests
cargo test --workspace
```

## Stack

- **Language**: Rust (nightly for eBPF), Python (ML training)
- **eBPF**: aya + bpf-linker (XDP, kprobes, tracepoints)
- **API**: Axum 0.7 (async, WebSocket, Prometheus)
- **DB**: sled (embedded FIM baseline), DashMap (IOC + flows)
- **ML**: ORT/ONNX (Isolation Forest + LSTM Autoencoder)
- **Detection**: AhoCorasick DFA, PCRE, YARA, Sigma 2.0

## Where things live

```
crates/
  thor-agent/src/
    fim/          # ThorFIM — File Integrity Monitoring (Blake3 + sled + eBPF)
    intel/        # ThorIntelSync — 10 threat intel feeds
    ids/          # ThorIDS — Suricata-compatible rule engine
    detection/    # Sigma 2.0 + YARA + IOC + ML detection
    ml/           # ONNX UEBA anomaly scoring
    events/       # Event pipeline (enrich → detect → SOAR)
    state/        # IOC DB + flow table + shared state
    api/          # Axum REST + WebSocket + Swagger
    soar/         # Automated response (TheHive integration)
    audit/        # HMAC-chained tamper-evident audit log
    metrics/      # Prometheus metrics
  thor-bpf/src/
    xdp_drop.*          # XDP packet filter
    process_monitor.*   # Process kprobe
    network_correlator.* # Network events
    fim_monitor.*       # FIM tracepoints (new)
  thor-common/src/
    lib.rs  # ThreatLevel, MitreTactic

rules/
  sigma/linux/    # 27 Linux Sigma rules
  sigma/network/  # 5 network Sigma rules
  sigma/windows/  # 3 Windows Sigma rules
  ids/            # thor-builtin.rules (30 IDS rules)

ml/
  train_thor_ueba.py   # Full training script (IF + LSTM → ONNX)
  models/              # Trained ONNX models
```

## Architecture Decisions

- **Blake3 over SHA256 for FIM**: 10× faster, equally secure for integrity monitoring
- **Bloom filter + DashMap IOC DB**: O(1) false negatives (99% of benign IPs exit at Bloom), O(1) true positive lookup
- **Suricata-compatible IDS**: allows loading existing ET Open rules without conversion
- **Sigma condition AST**: full boolean parsing instead of flat keyword matching enables complex detections
- **ORT/ONNX inference**: allows training in Python (sklearn/PyTorch) and serving in Rust with zero Python dependency in production

## Product

**Axis 1 (v0.2.0) — Detection Foundation:**
- ThorFIM: real-time file integrity monitoring with kernel-level eBPF hooks
- ThorIntelSync: automatic IOC sync from 10 free threat intel feeds
- ThorIDS: 30+ built-in + ET Open IDS rules
- 35 production Sigma detection rules
- ML/UEBA anomaly scoring (Isolation Forest)

**Planned (Axis 2): Network Analysis** — full L7 DPI, JA4 TLS fingerprinting, DNS analytics, NetFlow

**Planned (Axis 3): Forensics** — memory forensics, process injection detection, audit trail

**Planned (Axis 4): AI/ML** — LSTM temporal anomaly, GNN attack chain, LLM rule generation

**Planned (Axis 5): Dashboard** — React + WebSocket real-time SOC interface

## Security Configuration

```bash
# Required environment variables
THOR_JWT_SECRET=<min 32 chars>       # JWT signing key
THOR_ADMIN_PASSWORD=<min 16 chars>   # API admin password

# Optional
THOR_OTX_API_KEY=<your_key>          # AlienVault OTX (enables subscribed pulses)
THOR_FIM_ENABLED=true                # Enable FIM (default: true)
THOR_INTEL_ENABLED=true              # Enable threat intel sync (default: true)
THOR_FIM_INTERVAL=30                 # FIM polling interval in seconds
THOR_FIM_DB=/var/lib/thor/fim.db     # FIM baseline database path
THOR_SIGMA_DIR=rules/sigma           # Sigma rules directory
THOR_IDS_DIR=rules/ids               # IDS rules directory
```

## Gotchas

- eBPF programs require CAP_BPF (or root) — use `setcap cap_bpf+ep` on binary
- FIM requires write access to `THOR_FIM_DB` path (default: `/var/lib/thor/`)
- ML model must be trained before running: `python3 ml/train_thor_ueba.py`
- `blake3` and `sha2` both needed: blake3 for speed, sha256 for YARA compatibility
- Never run `cargo build` without `--release` in production — debug builds are 100× slower for AhoCorasick DFA construction

## User preferences

- All modules must be 100% standalone (no external agent dependencies)
- Source of truth for design patterns: Wazuh (FIM), Suricata (IDS), Sigma (YAML rules)
- Push all changes to GitHub with `GITHUB_PERSONAL_ACCESS_TOKEN`
