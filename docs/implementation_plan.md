# Thor Firewall Smart: Hardening Surgery & Refactoring Plan

This plan outlines the "technical surgery" required to transition the Thor project from a structural prototype to a production-hardened platform.

## Proposed Changes

### 1. Stability & Infrastructure (Phase 1)
- **Goal**: Establish a baseline for testing kernel-level behaviors safely.
- **Action**: Create a `thor-integration` test suite.
- **New Files**:
    - `tests/integration/docker-compose.test.yml`: Setup for multi-agent + control plane.
    - `scripts/run_chaos_tests.sh`: Automated attack simulation (DDoS, RCE, malware execution).

### 2. Control Plane: State Orchestration & Delegation (Phase 2)
- **Goal**: Professionalize the Control Plane to manage agent state and authorization.
- **Modify**: `thor-control-server/src/main.rs`, `thor-control-server/src/grpc.rs`
- **Action**:
    - **Delegation Policy Manager**: Implement a middleware that validates if an operator has the authority to issue specific commands to specific agent groups.
    - **mTLS Enforcement**: Hard-enforce `Identity` and `client_ca_root` in `tonic` server config.
    - **State Store**: Extend the PostgreSQL schema to track agent runtime status (e.g., eBPF map counts, ML model version).

### 3. Action Protocol: Signed Commands (Phase 3)
- **Goal**: Prevent unauthorized command execution even if the network is compromised.
- **Action**:
    - **Control Plane**: Add Ed25519 signing using the `ed25519-dalek` crate. Sign all `PolicyUpdate` and `ResponseAction` protobuf messages.
    - **Agent**: Implement signature verification in `control_plane_client.rs` before processing any command.
- **Modify**: `thor-control-proto/proto/thor_control.proto` (add signature field), `thor-agent/src/control_plane_client.rs`.

### 4. Explainable AI (XAI) (Phase 4)
- **Goal**: Transparency in ML decisions.
- **Modify**: `thor-agent/src/ml/mod.rs`, `thor-agent/src/ml/onnx_scorer.rs`.
- **Action**:
    - Update `OnnxScorer::score` to return a `(f32, Vec<FeatureWeight>)`.
    - Feature weights will be calculated by comparing the input features to the `IsolationForest` decision paths (or a simpler heuristic approximation for the 28 features).
    - Update `Alert` struct to include `xai_report` field.

### 5. eBPF Hardening: Memory & Map Optimization (Phase 5)
- **Goal**: Zero contention and system stability.
- **Modify**: `crates/thor-bpf/src/xdp_drop.bpf.c`, `crates/thor-bpf/src/process_monitor.bpf.c`.
- **Action**:
    - Convert `thor_blocklist_ports` from `LRU_HASH` to `PERCPU_LRU_HASH` (mostly for writing ease across cores).
    - Convert `thor_tracked_procs` to `PERCPU_LRU_HASH`.
    - Ensure all `__sync_fetch_and_add` operations on global counters are moved to `PERCPU_ARRAY` maps where possible to avoid atomic overhead at 20Mpps.

### 6. ERA: Staged Enforcement (Confidence-Based)
- **Goal**: Neutering attacks without killing business traffic.
- **Action**: Update `SoarEngine` and `DetectionEngine` to handle multi-stage response actions (Drop, Shape, Quarantine, Allow).
- **Modify**: `crates/thor-agent/src/soar/mod.rs`, `crates/thor-agent/src/detection/mod.rs`.

### 7. ERA: Edge Aggregation (eBPF Telemetry Optimization)
- **Goal**: High-fidelity detection with low-volume telemetry.
- **Action**: Implement HyperLogLog maps in eBPF to track unique IPs and only notify Control Plane of statistical deviations.
- **Modify**: `crates/thor-bpf/src/xdp_drop.bpf.c`.

### 8. ERA: Zero-Trust Attestation (TPM Simulation)
- **Goal**: Cryptographic binding of identity to hardware.
- **Action**: Update Control Plane registration to require and verify a "Device-Unique Hardware Hash" (Simulated).
- **Modify**: `thor-control-plane/crates/thor-control-server/src/grpc.rs`.

## Verification Plan

### Automated Tests
1. **Unit Tests**:
    - Run `cargo test --package thor-agent --lib ml` to verify XAI output logic.
    - Run `cargo test --package thor-control-server` to verify delegation logic.
2. **Integration Tests**:
    - Run `bash scripts/run_chaos_tests.sh` in a controlled Linux environment with eBPF support to verify packet dropping and process tracking stability.
    - Verify signature verification by sending an unsigned command and ensuring the agent rejects it.

### Manual Verification
- Deploy the control plane and one agent.
- Use the dashboard to issue a "Network Isolate" command.
- Verify in agent logs: "Command signature verified. Executing playbook...".
