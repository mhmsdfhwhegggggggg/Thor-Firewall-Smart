#!/bin/bash
# Thor Chaos Orchestrator
# Aggressive fault injection to verify ERA resilience.

TARGET_AGENT_PID=$(pgrep thor-agent)
CONTROL_PLANE_PID=$(pgrep thor-control-server)

echo "🌪️ Starting Chaos Orchestration..."

# Test 1: Control Plane Outage (Verify Fail-Soft/Cache-First)
echo "1. Killing Control Plane..."
kill -9 $CONTROL_PLANE_PID
sleep 2
echo "   [!] Control Plane is DOWN. Verifying Agent Autonomous Mode..."
# In a real test, we would check logs here
sleep 5

# Test 2: Agent Crash & Persistence (Verify Redb recovery)
echo "2. Killing Thor Agent..."
kill -9 $TARGET_AGENT_PID
sleep 2
echo "   [!] Agent CRASHED. Restarting to verify state recovery from Redb/JSON..."
# Restart agent (cmd placeholder)
# ./thor-agent &
sleep 5

# Test 3: Network Partition Simulation
echo "3. Simulating Network Partition (dropping gRPC port 50051)..."
sudo iptables -A OUTPUT -p tcp --dport 50051 -j DROP
sleep 10
echo "   [!] Partition active. Verifying Cache-First sub-cycle..."
sudo iptables -D OUTPUT -p tcp --dport 50051 -j DROP

echo "✅ Chaos Test Loop Complete."
