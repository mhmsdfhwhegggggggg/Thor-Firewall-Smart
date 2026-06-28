# Contributing to Thor Firewall Smart

Thank you for your interest in Thor! This document explains how to contribute effectively.

## Table of Contents
- [Development Setup](#development-setup)
- [Code Standards](#code-standards)
- [Branch Strategy](#branch-strategy)
- [Commit Format](#commit-format)
- [Testing Requirements](#testing-requirements)
- [Security Policy](#security-policy)

---

## Development Setup

```bash
# 1. Prerequisites (Linux x86_64, kernel 5.4+)
sudo apt-get install -y clang llvm libbpf-dev libssl-dev libyara-dev pkg-config

# 2. Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add bpfel-unknown-none

# 3. Dev tools
make dev    # installs cargo-audit, cargo-deny, cargo-criterion

# 4. Build
make build

# 5. Tests
make test
```

## Code Standards

All Rust code **must** pass before submitting a PR:

```bash
make lint        # cargo clippy — zero warnings
make fmt-check   # cargo fmt — consistent formatting
make audit       # cargo audit — no known vulnerabilities
make deny        # cargo deny — license + banned crate policy
```

### Style Rules
- No `unsafe` blocks without a `// SAFETY:` comment explaining invariants
- All public APIs must have doc comments (`///`)
- Error handling: use `anyhow::Result` in binaries, `thiserror` in library crates
- Async code: `tokio` runtime only — no mixing of runtimes
- Logging: `tracing` macros only (`info!`, `warn!`, `error!`) — no `println!` in lib code

## Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Stable, production-ready code |
| `develop` | Active development (PRs target here) |
| `release/vX.Y.Z` | Release preparation |
| `feat/*` | New features |
| `fix/*` | Bug fixes |
| `security/*` | Security patches (fast-track review) |

## Commit Format

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

**Types:** `feat`, `fix`, `perf`, `refactor`, `test`, `bench`, `ci`, `docs`, `chore`, `security`

**Scopes:** `agent`, `agent-net`, `agent-web`, `agent-srv`, `soc`, `bpf`, `ids`, `common`, `helm`, `k8s`, `ci`, `docker`

**Examples:**
```
feat(agent-net): add JA4 fingerprinting for SSH tunnels
perf(ids): replace linear scan with Aho-Corasick for OWASP patterns
fix(soc): correct HPA max replica calculation on CPU spike
security(agent-web): patch HTTP request smuggling bypass
bench(ids): add Criterion throughput benchmark for WAF engine
```

## Testing Requirements

Every PR must include:

| Change Type | Required Tests |
|-------------|---------------|
| New feature | Unit test + integration test |
| Bug fix | Regression test (test that fails before fix) |
| Performance | Before/after Criterion benchmark |
| Security | CVE reference + remediation proof |

```bash
make test          # must pass
make bench         # must not regress >5% vs main
```

## eBPF Development

eBPF programs have special requirements:

```bash
# Build eBPF separately (different target)
make build-bpf

# Test eBPF in isolated network namespace (needs root)
sudo ./scripts/chaos_ringbuffer.sh
```

## Security Policy

**Please do NOT open public GitHub Issues for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

Security patches get priority review and fast-track merge.

---

*Thor Engineering Team — building the most capable open-source firewall in Rust*
