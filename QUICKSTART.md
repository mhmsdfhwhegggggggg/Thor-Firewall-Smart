# ⚡ Thor Enterprise: Quickstart Deployment

Welcome to the **Thor Network Security Platform**. This guide is designed for investors, security engineers, and DevOps teams to launch the entire production-grade suite locally or in a Staging environment in under 5 minutes.

## 🏛️ Ecosystem Overview

1. **Thor Control Plane (Server + Dashboard)**
   - **gRPC Server (`50051`)**: Manages agent connections with mTLS.
   - **REST API & Dashboard (`3000` / `8080`)**: Role-Based Access Control (RBAC) panel for SOC engineers.
2. **Thor Agent (eBPF + AI)**
   - **XDP & Kprobe**: Kernel-level blocking and stream tracking.
   - **ONNX ML Engine**: Sub-millisecond AI inference runtime scoring packet flows.

---

## 🚀 1-Click Deployment (Local / PoC Demo)

### Prerequisites

- `docker` and `docker-compose`
- `rust` toolchain (if compiling from source)
- Linux Kernel 5.4+ (for eBPF CO-RE capabilities)

### Step 1: Exporting the AI Model
First, run the Python script to generate the ONNX anomaly detection model.
```bash
pip install numpy scikit-learn skl2onnx onnx
python3 ml_train_export.py
```
This will generate `thor_anomaly_model.onnx` representing the zero-day anomaly detection engine.

### Step 2: Boot Control Plane services
Start the Control Plane and its required databases:
```bash
docker-compose up -d
```
*Note: This spins up the Dashboard on port `3000` and the gRPC proxy.*

### Step 3: Run the Thor Agent (Requires Root)
In a fresh terminal with Sudo privileges:
```bash
# Needs root/CAP_BPF to load eBPF modules
sudo cargo run --bin thor-agent
```

---

## 🌪️ Chaos Engineering & Resilience Testing

To demonstrate the platform's stability to stakeholders, run the Chaos Engineering suite:
```bash
python3 chaos_runner.py
```

**Testing Vectors Demonstrated:**
1. **L4 SYN Flood Resistance:** Ensures eBPF XDP maps drop packets before TCP stack exhaustion.
2. **Network Partition Recovery:** Simulates Control Plane severances to show autonomous Agent edge logic.
3. **Agent Death (Fail-Open):** Simulates Panic/SIGKILL. Traffic seamlessly resumes unmonitored bypassing downtime.

---

## 🔐 Enterprise Kubernetes (HA/DR) Deployment

For production DMZ or Staging environments, use the provided Kubernetes deployment files:
```bash
kubectl apply -f k8s/thor-control-deployment.yaml
# Verifying High Availability replica states
kubectl get pods -n thor-security
```

## 📚 Future Implementations
- **Elastic SIEM exporter**: Integrating `events/siem_exporter.rs` with Kafka streaming for Splunk/QRadar feeds.
- **Toxiproxy Integration**: Deep resilience testing metrics.
