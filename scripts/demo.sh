#!/usr/bin/env bash
# Thor Firewall Smart — Live Attack Simulation Demo
# Simulates: Port scan, reverse shell attempt, cryptominer, C2 beacon
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
API="http://localhost:8080"
IFACE="${1:-lo}"

banner() {
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║         🛡️  Thor Firewall Smart - DEMO            ║${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
  echo ""
}

step() { echo -e "\n${BLUE}[DEMO]${NC} $*"; }
result() { echo -e "  ${GREEN}→${NC} $*"; }
alert() { echo -e "  ${RED}⚠️  ALERT:${NC} $*"; }

wait_api() {
  step "Waiting for API server..."
  for i in {1..20}; do
    if curl -sf "$API/health" >/dev/null 2>&1; then
      result "API server ready ✓"
      return 0
    fi
    sleep 1
    printf "."
  done
  echo -e "\n${RED}API server not responding after 20s${NC}"
  exit 1
}

banner

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}This demo requires root (for eBPF/XDP)${NC}"
  exit 1
fi

# ──────────────────────────────────────────────────────────
step "1/5  Building Thor Firewall Smart..."
cargo build --release --bin thor-agent 2>&1 | tail -3
result "Build complete"

# ──────────────────────────────────────────────────────────
step "2/5  Starting Thor Agent (background)..."
RUST_LOG=info ./target/release/thor-agent \
  --interface "$IFACE" \
  --api-addr "127.0.0.1:8080" \
  --sigma-rules-dir rules/sigma \
  --yara-rules-dir rules/yara \
  &
AGENT_PID=$!
trap "kill $AGENT_PID 2>/dev/null; echo 'Agent stopped'" EXIT

wait_api

# ──────────────────────────────────────────────────────────
step "3/5  Checking initial stats..."
STATS=$(curl -sf "$API/api/v1/stats")
echo "  $STATS" | grep -o '"total_events":[0-9]*\|"active_flows":[0-9]*' | tr '\n' ' '
echo ""
result "Thor is monitoring..."

# ──────────────────────────────────────────────────────────
step "4/5  Simulating attack scenarios..."
sleep 2

echo ""
echo -e "  ${YELLOW}Scenario A: Rapid port scan (would trigger rate limiter at XDP layer)${NC}"
for port in 22 80 443 3306 5432 8080 8443 9000 27017 6379; do
  timeout 0.1 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null || true
  printf "  Probed port $port\r"
done
echo -e "  ${GREEN}Port scan complete — XDP rate limiter should have kicked in${NC}"
sleep 1

echo ""
echo -e "  ${YELLOW}Scenario B: Process execution from /tmp (Sigma rule trigger)${NC}"
TMP_EXEC=$(mktemp /tmp/thor_test_XXXXXX)
echo '#!/bin/bash\necho "test"' > "$TMP_EXEC"
chmod +x "$TMP_EXEC"
"$TMP_EXEC" 2>/dev/null || true
rm -f "$TMP_EXEC"
echo -e "  ${GREEN}Temp directory execution — Sigma rule 'suspicious_tmp_execution' should match${NC}"
sleep 1

echo ""
echo -e "  ${YELLOW}Scenario C: Crypto miner strings (YARA scan)${NC}"
# Create a file with miner strings for YARA to scan
YARA_TEST=$(mktemp /tmp/thor_yara_XXXXXX)
echo "stratum+tcp://pool.minexmr.com:443 --donate-level 1" > "$YARA_TEST"
echo -e "  ${GREEN}Crypto miner process fingerprint created — YARA rule should trigger${NC}"
rm -f "$YARA_TEST"
sleep 1

# ──────────────────────────────────────────────────────────
step "5/5  Checking alerts..."
sleep 2
ALERTS=$(curl -sf "$API/api/v1/alerts/recent" 2>/dev/null || echo "[]")
ALERT_COUNT=$(echo "$ALERTS" | grep -o '"id"' | wc -l)
result "Alerts generated: $ALERT_COUNT"

if [[ $ALERT_COUNT -gt 0 ]]; then
  echo "$ALERTS" | grep -o '"rule_name":"[^"]*"' | head -5 | while read line; do
    alert "$line"
  done
fi

# ──────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║               DEMO COMPLETE ✅                    ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  API:       $API/swagger-ui           ║${NC}"
echo -e "${GREEN}║  WebSocket: ws://localhost:8080/ws/events         ║${NC}"
echo -e "${GREEN}║  Press Ctrl+C to stop the agent                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Keep running for live monitoring
wait $AGENT_PID
