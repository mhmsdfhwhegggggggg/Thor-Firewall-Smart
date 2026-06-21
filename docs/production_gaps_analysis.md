# Thor Firewall Smart: Real-World Production Gaps

This document identifies the critical gaps and technical obstacles that must be resolved before the platform can reach 100% enterprise-grade production stability.

## 1. Operational & Lifecycle Gaps

### 🛡️ Kernel Compatibility & CO-RE
- **The Gap**: While we use **eBPF CO-RE**, diverse Linux distributions (especially older enterprise kernels like RHEL 7/8 or custom vendor kernels) often have missing helpers or slightly different BPF verifier behaviors.
- **Problem**: Deploying the Agent on a legacy kernel might lead to a "Verifier Rejection," rendering the L0 filter useless.
- **Action**: Implement a thorough "Environment Sanity Check" in the Agent's bootstrap phase to validate kernel features before loading eBPF maps.

### 🔄 Certificate & Key Rotation at Scale
- **The Gap**: We implemented **mTLS** and **signed policies**, but there is no automated mechanism for certificate rotation or Revocation Lists (CRL/OCSP).
- **Problem**: If an Agent's private key is compromised, or if a Control Plane key expires, the entire "Action Protocol" trust chain breaks without a way to revoke just one node.
- **Action**: Integrate with a PKI orchestrator (like HashiCorp Vault or cert-manager) to handle short-lived certificates.

## 2. Architectural High-Load Gaps

### 🧠 ML Inference Latency vs. Throughput
- **The Gap**: Running ONNX models (UEBA/Malware) on every packet or even every flow introduction adds overhead.
- **Problem**: Under a real DDoS or high-concurrency attack (e.g., 10M concurrent flows), the `DetectionEngine` might become a CPU bottleneck due to context switching between the network stack and the ML runtime.
- **Action**: Implement "Opportunistic ML" — only analyze flows that cross a certain "suspicion threshold" defined by eBPF.

### 💾 Storage Explosion (Data Volume)
- **The Gap**: Collecting L7 dissector data, XAI reports, and JA4 fingerprints for a 40Gbps link produces massive amounts of telemetry.
- **Problem**: Post-analysis databases (PostgreSQL/TimescaleDB) will reach capacity in days without a sophisticated shard-and-archive strategy.
- **Action**: Use **ClickHouse** for high-volume telemetry and implement data-reduction (Sampling) at the Agent level using eBPF maps.

## 3. Security & Reliability Gaps

### 📉 False Positive Storms (Alert Fatigue)
- **The Gap**: AI models and complex Sigma rules can trigger cascading alerts in complex Enterprise environments (e.g., legitimate but aggressive developer scripts).
- **Problem**: Blockers might trigger on "Normal but anomalous" traffic, causing critical service downtime (Self-Inflicted Denial of Service).
- **Action**: Implement a "Confirmation Loop" — suspicious activity is first placed in "Shadow Mode" for 5 minutes, and only promoted to "Enforce" if verified by secondary engines or human operator.

### 🛡️ Adversarial ML (Evasion)
- **The Gap**: Attackers can probe the Open-Source nature of some of our engines (Sigma/YARA) to craft payloads that bypass them.
- **Problem**: A sophisticated attacker could generate "adversarial noise" to lower the ML engine's confidence score below the `0.495` threshold.
- **Action**: Move to an **Ensemble Model** strategy where multiple models must agree before a high-confidence block is authorized.

## 4. Platform Heterogeneity

### 🍎 Windows Support Maturity
- **The Gap**: The Linux eBPF path is highly mature, but the Windows path (LWF/eBPF-for-windows) is still experimental in many areas.
- **Problem**: Achieving feature parity (Performance and Detection) on Windows requires deep kernel-mode driver signing and testing that takes months.
- **Action**: Focus on Linux for High-Performance Gateways and use a "Light Agent" (Audit-only) for Windows endpoints until the kernel path matures.

---
**Conclusion**: The system is physically "hardened" but requires **Operational Maturity** (PKI, Sharding, Ensemble Models) to survive a 24/7/365 production environment with mission-critical SLAs.
