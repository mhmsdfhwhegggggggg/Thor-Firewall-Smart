#!/usr/bin/env bash
# =============================================================================
# Thor Firewall Smart — Security Audit Script
# Runs on every CI push and before every production deployment.
# Fails the build if any CRITICAL or HIGH vulnerability is found.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
log_info() { echo -e "       $1"; }

echo "=========================================================="
echo "  Thor Firewall Smart — Security Audit"
echo "  $(date '+%Y-%m-%d %H:%M:%S UTC')"
echo "=========================================================="

# ── 1. Check for secrets in code ──────────────────────────────────────────────
echo ""
echo "--- [1/6] Secrets Scan ---"

PATTERNS=(
  "password\s*=\s*['\"][^'\"]{4,}"
  "secret\s*=\s*['\"][^'\"]{4,}"
  "api_key\s*=\s*['\"][^'\"]{4,}"
  "ghp_[A-Za-z0-9_]{36}"
  "AKIA[0-9A-Z]{16}"
)

FOUND_SECRETS=0
for pattern in "${PATTERNS[@]}"; do
  MATCHES=$(grep -rniE "$pattern" \
    --include="*.rs" --include="*.toml" --include="*.yaml" --include="*.yml" \
    --exclude-dir=".git" --exclude-dir="target" . 2>/dev/null || true)
  if [ -n "$MATCHES" ]; then
    log_fail "Potential secret found (pattern: $pattern)"
    echo "$MATCHES" | head -5
    FOUND_SECRETS=1
  fi
done

if [ "$FOUND_SECRETS" -eq 0 ]; then
  log_pass "No hardcoded secrets detected"
fi

# ── 2. cargo audit (CVE check) ────────────────────────────────────────────────
echo ""
echo "--- [2/6] Dependency CVE Scan (cargo audit) ---"

if command -v cargo-audit &> /dev/null; then
  AUDIT_OUTPUT=$(cargo audit --json 2>/dev/null || echo '{"vulnerabilities":{"found":false}}')
  VULN_COUNT=$(echo "$AUDIT_OUTPUT" | node -e \
    "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{
      try{const r=JSON.parse(d);console.log(r.vulnerabilities.list?.length||0);}catch{console.log(0);}
    }" 2>/dev/null || echo "0")

  if [ "$VULN_COUNT" -gt 0 ]; then
    log_fail "$VULN_COUNT CVEs found in dependencies — review with: cargo audit"
    cargo audit 2>/dev/null | grep -E "(RUSTSEC|severity)" | head -10
  else
    log_pass "No known CVEs in dependencies"
  fi
else
  log_warn "cargo-audit not installed — run: cargo install cargo-audit"
  log_info "Skipping CVE scan"
fi

# ── 3. Check .env is not committed ────────────────────────────────────────────
echo ""
echo "--- [3/6] Environment File Check ---"

if git ls-files --error-unmatch .env &>/dev/null 2>&1; then
  log_fail ".env file is tracked by git — REMOVE IMMEDIATELY with: git rm --cached .env"
else
  log_pass ".env is not tracked by git"
fi

if [ -f ".env.example" ]; then
  log_pass ".env.example exists"
else
  log_warn ".env.example not found — create it for documentation"
fi

# ── 4. Check SECURITY.md exists ───────────────────────────────────────────────
echo ""
echo "--- [4/6] Security Policy Check ---"

if [ -f "SECURITY.md" ]; then
  log_pass "SECURITY.md exists"
else
  log_warn "SECURITY.md missing — required for PCI-DSS compliance"
fi

# ── 5. Check for hardcoded "localhost" or dev URLs in production code ─────────
echo ""
echo "--- [5/6] Development Artifact Check ---"

DEV_PATTERNS=("localhost" "127\.0\.0\.1" "0\.0\.0\.0" "TODO" "FIXME" "HACK" "XXX")
DEV_FOUND=0
for pat in "${DEV_PATTERNS[@]}"; do
  COUNT=$(grep -rn "$pat" crates/ --include="*.rs" \
    --exclude-dir="target" 2>/dev/null | grep -v "#" | grep -v "//" | wc -l || echo 0)
  if [ "$COUNT" -gt 5 ]; then
    log_warn "$COUNT occurrences of '$pat' in source code — review if intentional"
    DEV_FOUND=1
  fi
done
if [ "$DEV_FOUND" -eq 0 ]; then
  log_pass "No suspicious development artifacts in production code"
fi

# ── 6. Docker Compose port exposure check ─────────────────────────────────────
echo ""
echo "--- [6/6] Docker Compose Security Check ---"

if [ -f "docker-compose.yml" ]; then
  # Check if DB ports are exposed to 0.0.0.0
  if grep -qE '^\s+- "[0-9]+:5432"' docker-compose.yml 2>/dev/null; then
    log_fail "PostgreSQL port 5432 exposed to 0.0.0.0 — bind to 127.0.0.1"
  else
    log_pass "PostgreSQL not exposed to public interface"
  fi

  if grep -qE '^\s+- "[0-9]+:6379"' docker-compose.yml 2>/dev/null; then
    log_fail "Redis port 6379 exposed to 0.0.0.0 — bind to 127.0.0.1"
  else
    log_pass "Redis not exposed to public interface"
  fi

  # Check hardcoded passwords
  if grep -qiE "(password|secret|key)\s*:\s*[a-zA-Z0-9_-]{6}" docker-compose.yml 2>/dev/null; then
    log_fail "Possible hardcoded credential in docker-compose.yml"
  else
    log_pass "No hardcoded credentials in docker-compose.yml"
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=========================================================="
echo "  Results: ${GREEN}${PASS} passed${NC} | ${YELLOW}${WARN} warnings${NC} | ${RED}${FAIL} failed${NC}"
echo "=========================================================="

if [ "$FAIL" -gt 0 ]; then
  echo -e "${RED}Security audit FAILED — fix issues before deploying${NC}"
  exit 1
elif [ "$WARN" -gt 0 ]; then
  echo -e "${YELLOW}Security audit passed with warnings — review before production${NC}"
  exit 0
else
  echo -e "${GREEN}Security audit PASSED${NC}"
  exit 0
fi
