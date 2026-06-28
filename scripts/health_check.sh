#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Thor Firewall Smart — Production Health Check Script
# ═══════════════════════════════════════════════════════════════════════════════
# Checks: API health, metrics, agent status, DB, Redis, Kafka, certs expiry
#
# Usage:
#   bash scripts/health_check.sh                    # local Docker stack
#   bash scripts/health_check.sh --k8s              # Kubernetes
#   bash scripts/health_check.sh --host 10.0.0.1   # remote agent
#   bash scripts/health_check.sh --json             # JSON output (for monitoring)
#
# Exit codes:
#   0 = all checks PASS
#   1 = one or more checks FAIL
#   2 = WARN (degraded but operational)
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
RESET="\033[0m"

# ─── Config ──────────────────────────────────────────────────────────────────
AGENT_HOST="${THOR_HOST:-localhost}"
AGENT_PORT="${THOR_API_PORT:-8080}"
METRICS_PORT="${THOR_METRICS_PORT:-9090}"
SOC_PORT="${THOR_SOC_PORT:-8090}"
WAF_PORT="${THOR_WAF_PORT:-8082}"
DB_HOST="${DB_HOST:-localhost}"
REDIS_HOST="${REDIS_HOST:-localhost}"
CERT_DIR="${CERT_DIR:-./certs}"
WARN_CERT_DAYS=30    # Warn if cert expires within 30 days
K8S_MODE=false
JSON_OUTPUT=false
OVERALL_STATUS=0

# ─── Flags ───────────────────────────────────────────────────────────────────
for arg in "$@"; do
  case $arg in
    --k8s)  K8S_MODE=true ;;
    --json) JSON_OUTPUT=true ;;
    --host=*) AGENT_HOST="${arg#*=}" ;;
    --host) shift; AGENT_HOST="$1" ;;
  esac
done

declare -A RESULTS=()

pass() { RESULTS["$1"]="PASS"; printf "${GREEN}[PASS]${RESET} %s\n" "$2"; }
fail() { RESULTS["$1"]="FAIL"; OVERALL_STATUS=1; printf "${RED}[FAIL]${RESET} %s\n" "$2"; }
warn() { RESULTS["$1"]="WARN"; [ $OVERALL_STATUS -eq 0 ] && OVERALL_STATUS=2; printf "${YELLOW}[WARN]${RESET} %s\n" "$2"; }
info() { printf "${CYAN}[INFO]${RESET} %s\n" "$*"; }

http_check() {
    local name="$1" url="$2" expected="${3:-200}"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
    if [[ "$code" == "$expected" ]]; then
        pass "$name" "$name: HTTP $code ← $url"
    else
        fail "$name" "$name: Expected HTTP $expected, got $code ← $url"
    fi
}

# ─── 1. Core API Health ───────────────────────────────────────────────────────
printf "\n${BOLD}🔍 Thor Agent Health Checks${RESET}\n"
http_check "agent-health"   "http://${AGENT_HOST}:${AGENT_PORT}/health"
http_check "agent-ready"    "http://${AGENT_HOST}:${AGENT_PORT}/ready"
http_check "agent-metrics"  "http://${AGENT_HOST}:${METRICS_PORT}/metrics"
http_check "soc-health"     "http://${AGENT_HOST}:${SOC_PORT}/api/v1/health"
http_check "waf-health"     "http://${AGENT_HOST}:${WAF_PORT}/health"
http_check "swagger-ui"     "http://${AGENT_HOST}:${AGENT_PORT}/swagger-ui" "200"

# ─── 2. Metrics sanity check ─────────────────────────────────────────────────
printf "\n${BOLD}📊 Metrics Sanity Checks${RESET}\n"
METRICS=$(curl -s --max-time 5 "http://${AGENT_HOST}:${METRICS_PORT}/metrics" 2>/dev/null || echo "")
for metric in "thor_alerts_total" "thor_xdp_packets_total" "thor_events_processed_total"; do
    if echo "$METRICS" | grep -q "^$metric"; then
        pass "metric-$metric" "Metric present: $metric"
    else
        warn "metric-$metric" "Metric missing: $metric (agent may be starting)"
    fi
done

# ─── 3. Database ──────────────────────────────────────────────────────────────
printf "\n${BOLD}🗄️  Database Checks${RESET}\n"
if command -v pg_isready &>/dev/null; then
    if pg_isready -h "$DB_HOST" -U thor -q 2>/dev/null; then
        pass "postgres" "PostgreSQL: accepting connections on $DB_HOST"
    else
        fail "postgres" "PostgreSQL: NOT accepting connections on $DB_HOST"
    fi
else
    warn "postgres" "pg_isready not installed — skipping DB check"
fi

# ─── 4. Redis ─────────────────────────────────────────────────────────────────
printf "\n${BOLD}📦 Redis Checks${RESET}\n"
if command -v redis-cli &>/dev/null; then
    if redis-cli -h "$REDIS_HOST" ping 2>/dev/null | grep -q "PONG"; then
        pass "redis" "Redis: PONG from $REDIS_HOST"
    else
        fail "redis" "Redis: no PONG from $REDIS_HOST"
    fi
else
    warn "redis" "redis-cli not installed — skipping Redis check"
fi

# ─── 5. TLS Certificates expiry ──────────────────────────────────────────────
printf "\n${BOLD}🔐 Certificate Expiry Checks${RESET}\n"
if command -v openssl &>/dev/null; then
    for cert_file in "$CERT_DIR"/ca/ca.crt "$CERT_DIR"/thor-agent/agent.crt; do
        if [[ -f "$cert_file" ]]; then
            expiry=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
            expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || gdate -d "$expiry" +%s 2>/dev/null || echo 0)
            now_epoch=$(date +%s)
            days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
            if [[ $days_left -lt 0 ]]; then
                fail "cert-$(basename $cert_file)" "EXPIRED: $cert_file (${days_left} days ago)"
            elif [[ $days_left -lt $WARN_CERT_DAYS ]]; then
                warn "cert-$(basename $cert_file)" "EXPIRING SOON: $cert_file (${days_left} days)"
            else
                pass "cert-$(basename $cert_file)" "Valid: $cert_file (${days_left} days remaining)"
            fi
        else
            warn "cert-$(basename $cert_file)" "Not found: $cert_file (run: make certs)"
        fi
    done
else
    warn "certs" "openssl not found — skipping cert checks"
fi

# ─── 6. K8s checks ───────────────────────────────────────────────────────────
if [[ "$K8S_MODE" == "true" ]]; then
    printf "\n${BOLD}☸️  Kubernetes Checks${RESET}\n"
    if command -v kubectl &>/dev/null; then
        # Check pod status
        for pod_app in thor-agent thor-agent-web thor-soc-slm; do
            READY=$(kubectl get pods -n thor-firewall -l "app=$pod_app" \
                --field-selector=status.phase=Running -o name 2>/dev/null | wc -l)
            if [[ $READY -gt 0 ]]; then
                pass "k8s-$pod_app" "K8s: $pod_app has $READY running pods"
            else
                fail "k8s-$pod_app" "K8s: $pod_app has NO running pods"
            fi
        done
    else
        warn "k8s" "kubectl not found — skipping K8s checks"
    fi
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
printf "\n${BOLD}══════════════════════════════════════════${RESET}\n"
PASS_COUNT=$(echo "${RESULTS[@]}" | tr ' ' '\n' | grep -c "PASS" || echo 0)
FAIL_COUNT=$(echo "${RESULTS[@]}" | tr ' ' '\n' | grep -c "FAIL" || echo 0)
WARN_COUNT=$(echo "${RESULTS[@]}" | tr ' ' '\n' | grep -c "WARN" || echo 0)

if [[ "$JSON_OUTPUT" == "true" ]]; then
    python3 -c "
import json, sys
results = $(echo "${RESULTS[@]@Q}" | python3 -c "
import sys
data = {}
# Output JSON results
print(json.dumps({'pass': $PASS_COUNT, 'fail': $FAIL_COUNT, 'warn': $WARN_COUNT, 'status': $OVERALL_STATUS}))
")
"
fi

if [[ $FAIL_COUNT -gt 0 ]]; then
    printf "${RED}${BOLD}RESULT: FAIL — ${FAIL_COUNT} check(s) failed${RESET}\n"
elif [[ $WARN_COUNT -gt 0 ]]; then
    printf "${YELLOW}${BOLD}RESULT: DEGRADED — ${WARN_COUNT} warning(s) — ${PASS_COUNT} passed${RESET}\n"
else
    printf "${GREEN}${BOLD}RESULT: ALL PASS — ${PASS_COUNT} checks passed${RESET}\n"
fi

exit $OVERALL_STATUS
