# Thor Firewall Smart: Deep System Analysis

Thor is a production-grade, multi-layered cybersecurity platform designed for high-performance network and application protection. It integrates kernel-level filtering with advanced AI-driven detection and automated response.

## 🏗️ Core Architecture

The system is organized into four distinct layers:

### 1. Kernel Layer (L0: Fast Filter)
- **Linux**: Uses **XDP/eBPF** for ultra-fast packet filtering (15-20 Mpps) with latency under 100ns.
- **Windows**: Uses **NDIS Light Weight Filter (LWF)**.
- **Function**: Handles DDoS mitigation, IP blacklisting, and early-stage packet dropping before it reaches the network stack.

### 2. Application Layer (L1: WAF & IPS)
- **Envoy Sidecar**: Handles traffic processing, TLS termination, and circuit breaking.
- **Coraza WAF**: Integrated via Envoy Go filters to protect against OWASP Top 10 attacks.
- **Deep Packet Inspection (DPI)**: Dissectors for HTTP, DNS, SMB, and TLS.

### 3. Agent Layer (Thor Agent)
The "brain" of the platform, implemented in Rust.
- **Detection Engine**:
    - **Sigma**: Condition-aware rule matching (1000+ rules).
    - **YARA**: File and process scanning for malware.
    - **IDS**: Suricata-compatible rule engine.
    - **IOC**: Bloom filter and DashMap for fast indicator-of-compromise matching.
- **ML Engine (ONNX)**:
    - **UEBA**: Anomaly scoring for behavioral analysis.
    - **Malware Classifier**: Identifies malware families.
    - **Time-Series Anomaly**: Detects deviations in host behavior over time.
- **SOAR Engine**:
    - **Circuit Breaker**: Prevents over-blocking storms.
    - **Playbooks**: Automated actions like Forensic capture, Network isolation, and File quarantine.
    - **TheHive Integration**: Incident management synchronization.

### 4. Management Layer (L2: SOC Control Plane)
- **Control Plane**: gRPC/REST server for managing multiple agents.
- **Dashboard**: React-based Command Center for real-time monitoring and incident response.
- **Audit Chain**: Tamper-evident HMAC logs for forensic integrity.

---

## 🔒 Key Security Features

| Feature | Implementation | Benefit |
|---------|----------------|---------|
| **Fail-Open Safety** | `SafeBpfManager` | Ensures traffic flows normally if the agent crashes. |
| **Circuit Breaker** | `SoarEngine` | Prevents automated systems from blocking critical infra. |
| **JA4+ Fingerprinting** | `FingerprintEngine` | Identifies malicious clients/servers via TLS/SSH/HTTP fingerprints. |
| **ThorQL** | Axis 3 feature | SQL-like query language for querying system states and forensics. |

---

## 📈 System Health & Tuning
- **ML Threshold**: Configurable (default `0.495`) to balance detection rate and false positives.
- **Performance**: Uses `mimalloc`, `dashmap`, and `flume` for maximum concurrency and throughput.
- **Observability**: Prometheus metrics and OpenTelemetry support.

---

## 🗺️ Roadmap Highlights
- **AI Copilot**: Local LLM for incident analysis and human-led SOC assistance.
- **Zero-Trust**: Identity-based micro-segmentation.
- **eBPF WAF**: Moving L7 inspection deeper into the kernel.
