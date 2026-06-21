# Thor: Enterprise Resilience Architecture (ERA)

This document outlines the "Great Engineering" solutions designed to overcome the identified production gaps, transforming Thor into a state-of-the-art, self-healing cybersecurity infrastructure.

## 🏛️ 1. Zero-Trust Identity (The "SPIFFE" Pattern)
**Problem**: Static certifications and lack of rotation.
**Solution**: **IDT (Identity-Bound Token) Orchestration**.
- **Hardware Attestation**: Agents must provide a TPM/TEE-signed "Device Identity" during registration.
- **Short-Lived Provisioning**: The Control Plane issues **6-hour JWTs/Certificates** via a `CredentialOrchestrator`. 
- **Automated Revocation**: A "Kill-Signal" broadcast on the gRPC stream immediately blacklists compromised fingerprints across all nodes in the cluster.

## 📊 2. Telemetry Compression (Edge Deduplication)
**Problem**: Storage explosion from 10Gbps+ telemetry.
**Solution**: **High-Cardinality Sketching in Kernel**.
- **eBPF Sketches**: Use **HyperLogLog (HLL)** and **Count-Min Sketches** in the eBPF maps to track "Uniqueness" of IPs and Fingerprints locally.
- **Delta-Only Streaming**: The Agent only streams "New Observation" or "Statistical Deviation" events instead of raw logs.
- **Durable Cold Storage**: Use **ClickHouse** with automated partition aging, moving 30-day+ data to S3/Object Storage with Zstandard compression.

## 🚀 3. Multi-Path Compatibility (The Hybrid Buffer)
**Problem**: Kernel/eBPF version incompatibility.
**Solution**: **The Hybrid Packet Pipeline**.
- **Path-A (XDP)**: Primary ultra-fast path for modern kernels.
- **Path-B (TC-BPF)**: Fallback for older kernels (easier helper requirements).
- **Path-C (AF_XDP/DPDK)**: User-space fallback for legacy kernels or enterprise NICs (Mellanox/Intel) that have poor XDP support.
- This ensures 100% deployment coverage regardless of the underlying OS age.

## 🧠 4. Bayesian Consensus (False Positive Shield)
**Problem**: Blockers causing service downtime due to AI "hallucinations."
**Solution**: **Staged Enforcement & Probability Scoring**.
- **Probabilistic Action**:
    - **Score > 0.95**: Immediate Interdiction (eBPF Drop).
    - **Score 0.7 - 0.95**: "Deep Inspection" (Envoy Sidecar isolation).
    - **Score 0.5 - 0.7**: "Traffic Shaping" (Rate-limiting to 1Mbps to allow legitimate flow but neuter an attack).
- **Human-in-the-Loop (HITL)**: Use the **AI Copilot** to summarize "Borderline" blocks and request one-click human verification via the Dashboard.

## 🛡️ 5. AI Resilience (The Big-Small Architecture)
**Problem**: Local ML performance vs. global accuracy.
**Solution**: **Asynchronous Cross-Validation**.
- **Agent (Small-ML)**: Fast, low-latency ONNX models for immediate local detection.
- **Control Plane (Deep-ML)**: Agents send "Highly Suspicious" (but not blocked) samples to the Control Plane for verification by a much larger **Transformer-based** model.
- **Result Feedback**: The Control Plane updates the Agent's local "Local Confidence Matrix" based on the Deep-ML results, allowing the system to learn from its own environment in real-time.

---
**Vision**: Thor becomes an **Autonomous Cyber-Organism** that not only monitors traffic but evolves its own defenses based on the collective intelligence of the cluster while remaining stable and resilient against its own errors.
