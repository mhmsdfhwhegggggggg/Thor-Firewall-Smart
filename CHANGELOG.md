## [Unreleased] — Production Hardening Phase 2

### Added
- `Makefile` — Full developer workflow automation (build/test/docker/k8s/helm/sbom/release)
- Per-crate multi-stage `Dockerfile` for `thor-agent-net`, `thor-agent-web`, `thor-agent-srv`, `thor-soc-slm` (distroless/nonroot)
- `.github/workflows/docker.yml` — Docker build/push to GHCR + Trivy scanning + cosign signing + SPDX SBOM attestation
- `helm/thor-firewall/` — Complete Helm chart (Chart.yaml + values.yaml + HPA templates + helpers)
- `k8s/thor-hpa.yaml` — HPA for `agent-web` (3→50), `soc-slm` (2→10), `agent-srv` (2→20)
- `k8s/thor-configmap.yaml` — ConfigMap with `thor.yaml` + Prometheus `ServiceMonitor` CRD
- `k8s/thor-deployments.yaml` — Deployments for `thor-agent-web` + `thor-soc-slm` with zero-downtime RollingUpdate
- `crates/thor-ids/benches/detection_engine.rs` — Criterion benchmarks (Aho-Corasick WAF throughput)
- `.github/workflows/coverage.yml` — Code coverage (cargo-llvm-cov + Codecov + 60% threshold gate)
- `migrations/002_decisions.sql` — SOC decisions + Federated Learning model versions + gradient deltas tables
- `scripts/install.sh` — One-shot production installation with systemd service
- `scripts/health_check.sh` — Production health check (API + metrics + DB + Redis + certs + K8s)
- `configs/grafana/provisioning/` — Auto-provisioned datasources (Prometheus + Jaeger + PostgreSQL)
- `configs/grafana/dashboards/thor-overview.json` — Security Overview dashboard (XDP + ML + WAF + agent fleet)
- `configs/vector.toml` — Vector log aggregation pipeline (Docker → Elasticsearch/Kafka/Prometheus)
- `.github/CODEOWNERS` — Automatic review assignment
- `CONTRIBUTING.md` — Full contributor guide (setup, code standards, branch strategy, commit format)

### Changed
- `monitoring/prometheus.yml` — Full scrape config for all 5 agents + PostgreSQL + Redis + Kafka + Node exporter
- `.cargo/config.toml` — Aggressive release optimizations (LLD + native CPU + SIMD + aliases)

### Removed
- `Cargo.toml.bak` — Stale backup file

# Thor Firewall Smart — Changelog

## [v0.3.0] — Phase 0: Zero-Trust Foundation (2026-06-19)

### 🏗️ Architecture — Workspace Modularization
- **Fixed** workspace `Cargo.toml`: added 6 previously-orphaned crates:
  `thor-agent-net`, `thor-agent-web`, `thor-agent-srv`,
  `thor-soc-slm`, `thor-xdp`, `thor-xdp-ebpf`
- Bumped workspace version to `0.3.0`
- Added mTLS dependency block: `rcgen`, `rustls 0.23`, `tokio-rustls 0.26`,
  `rustls-pemfile`, `webpki-roots`

### 🔐 Security — mTLS Zero-Trust (CISO Requirement)
- **New `crates/thor-common/src/crypto.rs`** — full production mTLS implementation:
  - `ThorCertAuthority::generate()` — self-signed CA (5-year lifetime)
  - `ThorCertAuthority::issue_agent_cert()` — short-lived agent certs (72 h, SPIFFE URI SAN)
  - `ThorCertAuthority::server_tls_config()` — Control-Plane `ServerConfig` with mandatory client cert verification
  - `ThorCertAuthority::agent_client_config()` — Agent `ClientConfig` with CA pinning
  - 3 unit tests (CA generation, cert issuance, full server+client config roundtrip)
- Replaced broken `rustls::client::NoServerCertVerifier` stub with production-safe code

### 📐 Schema — Unified Event Protocol
- **New `UnifiedThorEvent`** in `thor-common/src/lib.rs` — canonical event schema:
  - `EventDetails::Network(NetworkEventDetails)` — L3/L4: src/dst IP+port, TCP flags, IOC match
  - `EventDetails::Web(WebEventDetails)` — L7: method, URI, anomaly score, signatures, payload hash
  - `EventDetails::Server(ServerEventDetails)` — EDR: PID, PPID, cmdline, FIM hash
  - `AgentPlatform` enum (Linux / Windows / Container)
  - Action enums: `NetworkAction`, `WebAction`, `ServerAction`
  - `WebThreatCategory` (SQLi, XSS, PathTraversal, CommandInjection, Log4Shell, WebShell…)
  - Auto-derives `threat_level` and `description` on construction
  - 3 unit tests

### ⚙️ Infrastructure
- **New `.github/workflows/ci.yml`** — full CI pipeline:
  - Rust stable + nightly matrix
  - `cargo check` on all workspace members
  - `cargo test --lib` (no eBPF kernel code in CI)
  - `cargo clippy -- -D warnings`
  - `cargo fmt --check`
- **New `configs/envoy/envoy.yaml`** — Envoy Proxy Cluster config (Phase 2 foundation):
  - TLS 1.3 listener on port 8443
  - Cluster with outlier detection + health checks
  - JWT + ext_authz filter wired to `thor-agent-web` on port 8082
  - Access log to `/var/log/thor/envoy-access.log`
- **New `windows/wfp/src/lib.rs`** — Windows Filtering Platform (WFP) stub:
  - Documents the `FWPM_FILTER0` + `FwpmFilterAdd0` call path for future NDIS LWF driver

### 📝 Documentation
- **New `IMPLEMENTATION_STATUS_AR.md`** — honest % completion per module:
  - Network Agent: 25% → target 100% (Phase 1)
  - Web Agent: 35% → target 100% (Phase 1)
  - Server EDR: 20% → target 100% (Phase 1)
  - SOC Control Plane: 12% → target 100% (Phase 2)
  - AI/SLM Engine: 8% → target 100% (Phase 3)
  - Windows Support: 3% → target 100% (Phase 2)
  - mTLS / Zero-Trust: **100%** ✅ (this release)

---

## [v0.2.0] — Axis 1: Detection Foundation (2025-06-16)

### 🆕 ThorFIM — File Integrity Monitoring
- Blake3 hashing (10× faster than SHA256) + SHA256 compatibility layer
- sled embedded DB for tamper-evident baseline persistence
- Monitors 40+ critical Linux paths (CIS Benchmark Level 2 + OSSEC defaults)
- Detects: Create, Modify, Delete, PermissionChange, OwnerChange
- Per-path severity mapping (Critical/High/Medium)
- Recursive directory scanning with depth limit
- eBPF program (`fim_monitor.bpf.c`) for kernel-level file operation hooks
  - Hooks: openat, unlinkat, renameat2, fchmodat, fchownat
  - Ring Buffer delivery (zero-copy, sub-microsecond latency)
  - Per-CPU scratch maps for high-throughput scanning
- SIGTERM graceful shutdown, configurable polling interval

### 🆕 ThorIntelSync — Threat Intelligence Synchronization
- **10 feed sources** with zero API key requirement:
  - Abuse.ch Feodo Tracker (C2 IP blocklist, 300+ IPs)
  - Abuse.ch URLhaus (malicious URLs, 10k+)
  - Abuse.ch ThreatFox (IPs + domains + hashes, 50k+)
  - Abuse.ch MalwareBazaar (SHA256 hashes, 500 samples/sync)
  - Emerging Threats compromised IPs
  - Spamhaus DROP + EDROP (CIDR ranges)
  - Tor exit nodes (bulk exit list)
  - AlienVault OTX reputation feed
  - STIX 2.1 bundle parser
  - MISP JSON attribute export parser
- Scheduled per-feed refresh (configurable intervals)
- Background sync loop (non-blocking, spawned on startup)
- AlienVault OTX subscribed pulses (when `THOR_OTX_API_KEY` is set)

### 🆕 ThorIDS — Suricata-Compatible IDS Engine
- Full Suricata rule parser: action, protocol, src/dst with ports, options
- Supported actions: alert, drop, pass, reject, log
- Supported protocols: tcp, udp, icmp, http, dns, tls, ftp, smtp, ssh
- Content matching: Boyer-Moore case-insensitive, multi-pattern AND logic
- PCRE pattern matching via Rust regex crate
- Port matching: single, range (1024:65535), group ([80,443,8080])
- Rule suppression table (60s cooldown per SID to prevent alert flooding)
- **30 built-in Thor IDS rules** (`rules/ids/thor-builtin.rules`):
  - C2 ports: Meterpreter (4444), Android ADB (5555), BackOrifice (31337)
  - DNS tunneling detection (DGA pattern, TXT record abuse)
  - SQL injection (UNION SELECT, OR 1=1)
  - Path traversal (../../etc/passwd)
  - XSS, web shells (cmd=, eval(base64_decode))
  - Log4Shell (${jndi:...)
  - Metasploit, Cobalt Strike, Sliver C2
  - SSH/RDP/VNC brute force (threshold-based)
  - Large outbound transfer exfiltration detection
  - DNS exfiltration (base64 encoded queries)
  - Crypto miner (xmrig, stratum protocol)
  - Tor ORPORT/SOCKS5 connections
  - Reverse shell patterns (bash /dev/tcp, Python socket, netcat)
- ET Open rules loader (loads from `rules/ids/` directory)

### 🆕 Sigma 2.0 Compiler — Full Condition Parser
- Full boolean condition AST: AND / OR / NOT
- Aggregations: `1of(selection*)`, `allof(selection*)`
- Nested parentheses support
- Field modifier parsing: `|contains`, `|startswith`, `|endswith`, `|contains|all`
- `|not` negate modifier support
- AhoCorasick DFA compilation per selection (O(N) multi-pattern)
- PCRE fallback for complex patterns

### 🆕 Production Sigma Rules (35 rules across 3 categories)
**Linux (27 rules):**
- Credential: /etc/passwd+shadow access, SSH key harvest
- Execution: shell from web parent, base64 pipe decode, Python PTY spawn, LOLBins
- Persistence: crontab, SSH authorized_keys, systemd service, LD_PRELOAD
- Privilege Escalation: sudo abuse, SUID bit setting, Polkit/PwnKit (CVE-2021-4034)
- Defense Evasion: log deletion, shell history clearing, rootkit loading, fileless malware
- Discovery: network scan (nmap/masscan), AWS IMDS abuse, cloud credentials
- Lateral Movement: SSH from unusual parent
- C2: reverse shell patterns (bash/python/perl/nc)
- Collection: AWS/Azure/GCP credential files
- Impact: ransomware indicators, crypto miner execution
- Container Escape: Docker socket abuse, namespace escape

**Network (5 rules):**
- DNS C2 beaconing (DGA patterns)
- Port sweep / host scan
- Tor exit node connections
- TLS suspicious SNI + DGA domains
- Web shell HTTP patterns

**Windows (3 rules):**
- PowerShell encoded command (-enc/-EnC)
- Mimikatz credential dumping
- Registry Run key persistence

### 🔧 Architecture Improvements
- `EnrichedEvent` now carries `ioc_matched: bool` (resolved at enrichment time)
- `RuleType` expanded: `Ids`, `Fim`, `Ueba`, `ThreatIntel`
- `ThreatLevel::from_score(f32)` — ML score to severity mapping
- `ThreatLevel::from_str_level(str)` — string parsing
- `ThreatLevel::is_critical_or_high()` helper
- `ThorConfig` expanded with `fim_*`, `intel_*`, `ids_*` fields
- `main.rs` wires all Axis 1 components on startup
- Bloom filter IOC lookup integrated into event enrichment pipeline

### 📦 New Dependencies
- `blake3 = "1.5"` — fast file hashing
- `hostname = "0.4"` — agent hostname resolution
- `tracing-appender = "0.2"` — rotating log files
- `reqwest` updated with `gzip + deflate` support

---

## [v0.1.0] — Initial Prototype
- XDP-based packet capture and IP blocklist enforcement
- Basic Sigma rule loading (flat keyword matching)
- YARA file scanner
- Axum REST API with JWT auth
- Audit log (HMAC-chained entries)
- WebSocket real-time alert stream
- Prometheus metrics
- SOAR: TheHive integration stub
