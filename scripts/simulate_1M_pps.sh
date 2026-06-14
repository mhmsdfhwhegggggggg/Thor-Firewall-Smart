#!/bin/bash
# High-Performance tcpreplay load test for Thor Agent CMS
# Expects a pre-generated pcap with 1,000,000 packets

IFACE=${1:-eth0}
PCAP_FILE="fuzz/corpus_1m_spoofed.pcap"

echo "🛡️ Thor Firewall Performance Load Test"
echo "--------------------------------------"
echo "Interface: $IFACE"
echo "Targeting 1,000,000 packets per second"

# Verify ethtool settings
ethtool -K $IFACE gro off gso off tso off lro off

# Run pure blast
tcpreplay --intf1=$IFACE \
          --mbps=1000 \
          --loop=10000 \
          --preload-pcap \
          $PCAP_FILE

echo "Test Complete."
echo "Check Thor Agent dashboard / metrics for dropped packet rate."
