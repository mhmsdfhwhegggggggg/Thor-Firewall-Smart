// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Thor TC Egress Hooks — Tier 1 ODIN Plan
// ========================================
// Traffic Control (TC) BPF programs for egress packet filtering.
// XDP only handles ingress. TC hooks handle EGRESS (outbound) traffic.
//
// Used for:
// 1. Blocking outbound C2 communication from compromised processes
// 2. Rate-limiting egress per-process (via socket cookie)
// 3. Egress DNS monitoring (C2 over DNS, DNS tunneling)
// 4. Data exfiltration detection (large outbound transfers)
//
// Architecture:
//   Process → socket → TC_EGRESS hook (this program) → NIC
//                              ↓
//                   Block if quarantined OR rate-limit
//
// Reference:
//   "TC-BPF: Using eBPF for Traffic Control", Linux Networking Summit 2019
//   Daniel Borkmann, "Advanced BPF Kernel Features for the Container Age", DockerCon 2019

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

/* Quarantined process socket cookie map.
 * Socket cookies are per-process identifiers that survive clone().
 * Written by Thor agent when SIGSTOP is applied to a process.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);    /* socket cookie */
    __type(value, __u8);   /* 1 = block egress, 0 = allow */
} thor_blocked_sockets SEC(".maps");

/* Per-process egress rate limiting state */
struct egress_rate {
    __u64 last_ts_ns;
    __u64 bytes_this_sec;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);    /* socket cookie */
    __type(value, struct egress_rate);
} thor_egress_rates SEC(".maps");

/* Egress block events — sent to userspace for SIEM */
struct egress_event {
    __u64 socket_cookie;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  proto;
    __u8  reason;   /* 0=quarantine, 1=rate_limit, 2=suspicious_port */
    __u64 timestamp_ns;
    __u64 pkt_size;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 131072);
} thor_egress_events SEC(".maps");

/* Per-CPU egress statistics */
struct egress_stats {
    __u64 packets_allowed;
    __u64 packets_blocked;
    __u64 bytes_allowed;
    __u64 bytes_blocked;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct egress_stats);
} thor_egress_stats SEC(".maps");

/* Suspicious outbound ports (C2 beaconing indicators) */
static __always_inline int is_suspicious_port(__u16 port) {
    /* Common C2 ports: 4444, 1337, 31337, 8443 (non-standard HTTPS), etc. */
    return port == 4444 || port == 1337 || port == 31337 ||
           port == 6666 || port == 6667 || port == 6668 || /* IRC C2 */
           port == 9999 || port == 12345;
}

static __always_inline void emit_egress_event(
    __u64 cookie, __u32 dst_ip, __u16 dst_port, __u8 proto, __u8 reason, __u64 size)
{
    struct egress_event *ev = bpf_ringbuf_reserve(&thor_egress_events, sizeof(*ev), 0);
    if (!ev) return;
    ev->socket_cookie = cookie;
    ev->dst_ip        = dst_ip;
    ev->dst_port      = bpf_ntohs(dst_port);
    ev->proto         = proto;
    ev->reason        = reason;
    ev->timestamp_ns  = bpf_ktime_get_ns();
    ev->pkt_size      = size;
    bpf_ringbuf_submit(ev, 0);
}

SEC("tc/egress")
int thor_tc_egress(struct __sk_buff *skb)
{
    __u32 zero = 0;
    struct egress_stats *stats = bpf_map_lookup_elem(&thor_egress_stats, &zero);

    /* Get socket cookie (unique per-process socket identifier) */
    __u64 cookie = bpf_get_socket_cookie(skb);
    __u64 pkt_size = skb->len;

    /* Check if socket belongs to a quarantined process */
    __u8 *blocked = bpf_map_lookup_elem(&thor_blocked_sockets, &cookie);
    if (blocked && *blocked == 1) {
        /* Block all egress from quarantined processes */
        void *data_end = (void *)(long)skb->data_end;
        void *data     = (void *)(long)skb->data;

        struct iphdr *ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) <= data_end) {
            __u32 dst_ip = ip->daddr;
            __u16 dst_port = 0;

            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (void *)(ip + 1);
                if ((void *)(tcp + 1) <= data_end)
                    dst_port = tcp->dest;
            } else if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = (void *)(ip + 1);
                if ((void *)(udp + 1) <= data_end)
                    dst_port = udp->dest;
            }

            emit_egress_event(cookie, dst_ip, dst_port, ip->protocol, 0, pkt_size);
        }

        if (stats) {
            stats->packets_blocked++;
            stats->bytes_blocked += pkt_size;
        }
        return TC_ACT_SHOT;  /* Drop the packet */
    }

    /* Per-process egress rate limiting */
    struct egress_rate *rate = bpf_map_lookup_elem(&thor_egress_rates, &cookie);
    if (rate) {
        __u64 now = bpf_ktime_get_ns();
        __u64 elapsed = now - rate->last_ts_ns;

        /* Reset counter every second */
        if (elapsed >= 1000000000ULL) {
            rate->last_ts_ns = now;
            rate->bytes_this_sec = pkt_size;
        } else {
            rate->bytes_this_sec += pkt_size;

            /* Rate limit: 100MB/s per process (configurable) */
            if (rate->bytes_this_sec > 100 * 1024 * 1024) {
                if (stats) {
                    stats->packets_blocked++;
                    stats->bytes_blocked += pkt_size;
                }
                return TC_ACT_SHOT;
            }
        }
        rate->total_bytes += pkt_size;
    }

    /* Check for suspicious destination ports */
    void *d  = (void *)(long)skb->data;
    void *de = (void *)(long)skb->data_end;
    struct iphdr *ip = d + sizeof(struct ethhdr);
    if ((void *)(ip + 1) <= de && ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) <= de) {
            __u16 dport = bpf_ntohs(tcp->dest);
            if (is_suspicious_port(dport)) {
                emit_egress_event(cookie, ip->daddr, tcp->dest, IPPROTO_TCP, 2, pkt_size);
                /* Allow but alert — operator decides whether to block */
            }
        }
    }

    if (stats) {
        stats->packets_allowed++;
        stats->bytes_allowed += pkt_size;
    }
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
