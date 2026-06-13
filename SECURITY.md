# Thor Firewall Smart — Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Active  |

## Reporting a Vulnerability

Email: security@thor-firewall.internal  
Response SLA: **4 hours** for Critical, **24 hours** for High  
Patch SLA: **48 hours** for Critical/High after confirmation  

Do NOT open a public GitHub issue for security vulnerabilities.

---

## Security Architecture

### Authentication & Authorization
- All API endpoints except `/health` and `/api/v1/login` require a valid JWT.
- JWT secret is loaded from `THOR_JWT_SECRET` environment variable — never hardcoded.
- Three RBAC roles enforced at middleware level:
  | Role       | Permissions |
  |------------|-------------|
  | `readonly` | View stats, alerts |
  | `analyst`  | + View/export audit log |
  | `admin`    | + Inject/approve rules, manage IOCs |

### Audit Log (PCI-DSS Compliant)
- Every security action is logged to an embedded sled database.
- Entries form a SHA-256 tamper-evident hash chain.
- Entries are NEVER deleted — retained per your data retention policy.
- Verify chain integrity: `GET /api/v1/audit/verify` (analyst+)

### AI Safety (Rule Injection)
- ALL rules (including `inject_dynamic_rule`) enter **Shadow Mode** first.
- Shadow mode = monitoring only, NO enforcement action.
- Minimum 1-hour observation window before approval is possible.
- Rules matching >100 times/minute in shadow are auto-rejected (hallucination guard).
- Rules with overly broad scope (any IP, all processes) are rejected at ingestion.
- Human admin approval required via `POST /api/v1/rules/approve/:id`.

### Network (eBPF/XDP)
- Packet filtering runs at NIC driver level (before kernel TCP/IP stack).
- Supports **IPv4 and IPv6** blocklists (LPM Trie — CIDR notation).
- BPF maps are pinned to `/sys/fs/bpf/` to survive agent restarts.
- Fail-Open policy: malformed packets are passed (not dropped) to avoid network disruption.

### Secrets Management
- No secrets in source code or docker-compose.yml — all via environment variables.
- Use HashiCorp Vault or AWS Secrets Manager in production.
- Required secrets: `THOR_JWT_SECRET`, `THOR_ADMIN_PASSWORD`, `POSTGRES_PASSWORD`.

---

## Deployment Checklist (Banking Grade)

### Before First Run
- [ ] Generate `THOR_JWT_SECRET`: `openssl rand -hex 64`
- [ ] Set `THOR_ADMIN_PASSWORD` ≥ 16 characters
- [ ] Set `POSTGRES_PASSWORD` — strong random string
- [ ] Copy `.env.example` to `.env`, never commit `.env`
- [ ] Verify `.env` is in `.gitignore`

### Network Hardening
- [ ] Expose only port 8080 (API) — bind to `127.0.0.1` behind a reverse proxy
- [ ] Enable TLS on the reverse proxy (nginx/caddy) with a valid certificate
- [ ] Do NOT expose PostgreSQL (5432) or Redis (6379) to the internet
- [ ] Configure `THOR_INTERFACE` to the correct network interface

### Operational
- [ ] Set up log shipping to SIEM (Splunk/QRadar)
- [ ] Schedule audit chain verification: `GET /api/v1/audit/verify` daily
- [ ] Test agent restart (BPF maps persist): `kill -SIGTERM <pid>`
- [ ] Establish alert escalation procedure for CRITICAL threats
- [ ] Document data retention policy and configure export schedule

---

## Known Limitations

1. **No mTLS between internal services** — planned for v0.2.
2. **Single-agent deployment** — no built-in HA/clustering yet.
3. **IPv6 rate limiting** — not yet implemented (IPv4 only).
4. **LLM reports** — require local Ollama instance (`ollama run phi3`).

---

## Compliance Mapping

| Control | Standard | Status |
|---------|----------|--------|
| Access Control | PCI-DSS 7, ISO 27001 A.9 | ✅ JWT + RBAC |
| Audit Logging | PCI-DSS 10, ISO 27001 A.12.4 | ✅ Tamper-evident chain |
| AI Rule Safety | Internal Policy | ✅ Shadow mode + human approval |
| Secrets Management | PCI-DSS 8, ISO 27001 A.9 | ✅ Env vars (no hardcoding) |
| Network Filtering | PCI-DSS 1 | ✅ XDP IPv4+IPv6 |
| Intrusion Detection | PCI-DSS 11.5 | ✅ Sigma + YARA + ML |
| Pen Test | PCI-DSS 11.3 | ⚠️ Required before production |
| HA / DR | PCI-DSS 12.10 | ⚠️ Planned v0.2 |
