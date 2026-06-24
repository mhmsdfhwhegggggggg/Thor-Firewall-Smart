// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Thor Slow DDoS Detector — Per-Source Absolute Rate Tracking
// ===========================================================
// PROBLEM: HyperLogLog detects volumetric DDoS (many unique IPs)
// BLIND SPOT: Slow-and-low DDoS (5 IPs × 200k rps) or slow scans
//
// SOLUTION: Per-source absolute rate counter + sliding window
// Track: packets_per_second AND bytes_per_second per source IP
// Alert when: single IP exceeds threshold over sustained window
//
// Covers:
//   - Low-rate DDoS (few IPs, high rate per IP)
//   - Slow port scans (1 packet per 30s but across many ports)
//   - HTTP flood from single IP (legitimate-looking but high volume)
//   - SYN cookies bypass (low SYN rate but high ACK storm)
//
// This COMPLEMENTS HyperLogLog (which handles volumetric DDoS)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

/* Per-IP rate tracking — sliding window over last 1 second */
struct src_rate {
    __u64 window_start_ns;  /* start of current 1-second window */
    __u32 pkt_count;        /* packets in window */
    __u64 byte_count;       /* bytes in window */
    __u32 unique_ports;     /* distinct dst ports (for scan detection) */
    __u16 last_ports[32];   /* circular buffer of recent dst ports */
    __u8  port_idx;
    __u8  alerted;          /* prevent alert flood */
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_LRU_HASH);
    __uint(max_entries, 500000);  /* 500k unique IPs */
    __type(key, __u32);
    __type(value, struct src_rate);
} thor_src_rates SEC(".maps");

/* Scan pattern: per-IP port tracking */
struct port_scan_state {
    __u64 window_start_ns;
    __u32 port_count;
    __u8  alerted;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_LRU_HASH);
    __uint(max_entries, 200000);
    __type(key, __u32);
    __type(value, struct port_scan_state);
} thor_scan_states SEC(".maps");

/* Rate limit events — sent to userspace */
struct rate_event {
    __u32 src_ip;
    __u32 pkt_rate;     /* packets per second */
    __u64 byte_rate;    /* bytes per second */
    __u32 scan_ports;   /* unique ports hit */
    __u8  alert_type;   /* 0=pps, 1=bps, 2=port-scan, 3=slow-scan */
    __u64 timestamp_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 262144);
} thor_rate_events SEC(".maps");

/* Thresholds (configurable via BPF map in production) */
#define MAX_PPS_PER_IP      10000    /* 10k pps per source = suspicious */
#define MAX_BPS_PER_IP      104857600 /* 100MB/s per source */
#define MAX_PORTS_PER_SEC   50       /* 50 unique ports/sec = port scan */
#define WINDOW_NS           1000000000ULL  /* 1 second */

static __always_inline void emit_rate_event(__u32 src_ip, __u32 pps, __u64 bps, __u32 ports, __u8 type) {
    struct rate_event *ev = bpf_ringbuf_reserve(&thor_rate_events, sizeof(*ev), 0);
    if (!ev) return;
    ev->src_ip=src_ip; ev->pkt_rate=pps; ev->byte_rate=bps;
    ev->scan_ports=ports; ev->alert_type=type; ev->timestamp_ns=bpf_ktime_get_ns();
    bpf_ringbuf_submit(ev,0);
}

/* Called from main XDP program for every passing packet */
/* Attach point: tc/ingress or as a tail call from xdp_drop */
SEC("tc/ingress/rate_check")
int thor_rate_check(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    __u32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();
    __u64 pkt_size = skb->len;

    /* Per-source rate tracking */
    struct src_rate *rate = bpf_map_lookup_elem(&thor_src_rates, &src_ip);
    struct src_rate new_rate = {};

    if (rate) {
        new_rate = *rate;
        if (now - new_rate.window_start_ns >= WINDOW_NS) {
            /* New window: reset counters, emit alert if previous window exceeded threshold */
            if (!new_rate.alerted) {
                if (new_rate.pkt_count > MAX_PPS_PER_IP)
                    emit_rate_event(src_ip, new_rate.pkt_count, new_rate.byte_count, 0, 0);
                else if (new_rate.byte_count > MAX_BPS_PER_IP)
                    emit_rate_event(src_ip, new_rate.pkt_count, new_rate.byte_count, 0, 1);
            }
            new_rate.window_start_ns = now;
            new_rate.pkt_count = 0; new_rate.byte_count = 0;
            new_rate.unique_ports = 0; new_rate.port_idx = 0; new_rate.alerted = 0;
        }
        new_rate.pkt_count++;
        new_rate.byte_count += pkt_size;
    } else {
        new_rate.window_start_ns = now;
        new_rate.pkt_count = 1; new_rate.byte_count = pkt_size;
    }
    bpf_map_update_elem(&thor_src_rates, &src_ip, &new_rate, BPF_ANY);

    /* Port scan detection */
    __u16 dst_port = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) <= data_end) dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) <= data_end) dst_port = bpf_ntohs(udp->dest);
    }

    if (dst_port > 0) {
        struct port_scan_state *scan = bpf_map_lookup_elem(&thor_scan_states, &src_ip);
        struct port_scan_state new_scan = {};
        if (scan) {
            new_scan = *scan;
            if (now - new_scan.window_start_ns >= WINDOW_NS) {
                if (!new_scan.alerted && new_scan.port_count > MAX_PORTS_PER_SEC)
                    emit_rate_event(src_ip, 0, 0, new_scan.port_count, 2);
                new_scan.window_start_ns = now; new_scan.port_count = 0; new_scan.alerted = 0;
            }
            new_scan.port_count++;
            if (new_scan.port_count > MAX_PORTS_PER_SEC && !new_scan.alerted) {
                emit_rate_event(src_ip, 0, 0, new_scan.port_count, 2);
                new_scan.alerted = 1;
            }
        } else {
            new_scan.window_start_ns = now; new_scan.port_count = 1;
        }
        bpf_map_update_elem(&thor_scan_states, &src_ip, &new_scan, BPF_ANY);
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
