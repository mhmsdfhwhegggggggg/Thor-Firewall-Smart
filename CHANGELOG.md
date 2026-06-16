# Thor Firewall Smart — Changelog

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
