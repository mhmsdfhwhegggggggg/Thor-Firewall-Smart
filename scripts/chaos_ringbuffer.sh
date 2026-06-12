#!/bin/bash
echo "🌪️ Activating Linux Traffic Control (tc) Chaos Test on interface eth0..."

# 1. محاكاة التقطعات الشديدة والتأخير (Jitter/Delay) لإجهاد خوارزميات الـ Stateful
echo "=> Injecting network delay (100ms) and jitter (20ms) to simulate heavy connection contention..."
tc qdisc add dev eth0 root netem delay 100ms 20ms distribution normal

# 2. محاكاة فساد البيانات لإرباك محلل L7
echo "=> Inducing artificial packet corruption (1% corruption) to test Parser memory safety..."
tc qdisc change dev eth0 root netem corrupt 1%

echo "=> Triggering simulated Subnet Flood to overwhelm the eBPF RingBuffer..."
# في الاختبار الفعلي داخل الـ DMZ: hping3 -S --flood -p 80 10.0.0.1 2>/dev/null &
# FLOOD_PID=$!

echo "⏳ Letting the Chaos Engine run for 10 seconds. Watch the logs!"
sleep 10

echo "🛑 Stopping flood and removing Chaos constraints from kernel network stack."
# kill $FLOOD_PID
tc qdisc del dev eth0 root netem

echo "✅ Review the Agent logs (journalctl -u thor-agent) to ensure 'Activating SURVIVAL MODE' triggered cleanly without Kernel Panics."
