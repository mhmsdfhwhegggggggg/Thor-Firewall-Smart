// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Thor XDP Threat Dropper — High-performance XDP packet filter
// Supports: LPM CIDR blocklist, port blocklist, per-IP rate limiting, malformed packet detection
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

struct lpm_key { __u32 prefixlen; __u32 ip; };

/* IP blocklist (LPM Trie for CIDR support) */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_BLOCKLIST_IPS);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} thor_blocklist_ips SEC(".maps");

/* Port blocklist */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCKLIST_PORTS);
    __type(key, __u16);
    __type(value, __u8);
} thor_blocklist_ports SEC(".maps");

/* Per-CPU statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct thor_stats);
} thor_stats SEC(".maps");

/* Ring buffer for events to user-space */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} thor_xdp_events SEC(".maps");

/* Per-IP rate limiting state */
struct rate_state { __u64 last_ts; __u32 count; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, struct rate_state);
} thor_rate_states SEC(".maps");

/* Rate limit config */
struct rate_limit_cfg { __u32 pps; __u64 window_ns; };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_limit_cfg);
} thor_rate_config SEC(".maps");

static __always_inline void emit_drop_event(struct xdp_md *ctx, __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port, __u8 proto, __u8 reason, __u32 pkt_len) {
    struct thor_xdp_drop_event *e = bpf_ringbuf_reserve(&thor_xdp_events, sizeof(*e), 0);
    if (!e) return;
    e->event_type = EVENT_XDP_DROP; e->src_ip4 = src_ip; e->dst_ip4 = dst_ip;
    e->src_port = bpf_ntohs(src_port); e->dst_port = bpf_ntohs(dst_port);
    e->protocol = proto; e->reason = reason; e->packet_len = pkt_len;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);
}

static __always_inline int check_rate_limit(__u32 src_ip) {
    __u32 zero = 0;
    struct rate_limit_cfg *cfg = bpf_map_lookup_elem(&thor_rate_config, &zero);
    __u32 pps = cfg ? cfg->pps : 10000;
    __u64 window = cfg ? cfg->window_ns : 1000000000ULL;
    __u64 now = bpf_ktime_get_ns();
    struct rate_state *state = bpf_map_lookup_elem(&thor_rate_states, &src_ip);
    if (!state) {
        struct rate_state new_state = { .last_ts = now, .count = 1 };
        bpf_map_update_elem(&thor_rate_states, &src_ip, &new_state, BPF_ANY);
        return 0;
    }
    if (now - state->last_ts > window) { state->last_ts = now; state->count = 1; return 0; }
    state->count++;
    return state->count > pps ? 1 : 0;
}

SEC("xdp")
int thor_xdp_drop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 zero = 0;
    struct thor_stats *stats = bpf_map_lookup_elem(&thor_stats, &zero);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        if (stats) { __sync_fetch_and_add(&stats->malformed_packets, 1); __sync_fetch_and_add(&stats->packets_dropped, 1); }
        return XDP_DROP;
    }
    if (stats) __sync_fetch_and_add(&stats->packets_processed, 1);
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        if (stats) { __sync_fetch_and_add(&stats->malformed_packets, 1); __sync_fetch_and_add(&stats->packets_dropped, 1); }
        return XDP_DROP;
    }

    /* CIDR blocklist check */
    struct lpm_key key = { .prefixlen = 32, .ip = ip->saddr };
    if (bpf_map_lookup_elem(&thor_blocklist_ips, &key)) {
        if (stats) { __sync_fetch_and_add(&stats->ip_blocklist_hits, 1); __sync_fetch_and_add(&stats->packets_dropped, 1); }
        emit_drop_event(ctx, ip->saddr, ip->daddr, 0, 0, ip->protocol, DROP_REASON_BLOCKLIST, data_end - data);
        return XDP_DROP;
    }

    /* Port blocklist check */
    __u16 src_port = 0, dst_port = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) { if (stats) __sync_fetch_and_add(&stats->malformed_packets, 1); return XDP_DROP; }
        src_port = tcp->source; dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) { if (stats) __sync_fetch_and_add(&stats->malformed_packets, 1); return XDP_DROP; }
        src_port = udp->source; dst_port = udp->dest;
    }

    if (src_port && bpf_map_lookup_elem(&thor_blocklist_ports, &src_port)) {
        if (stats) { __sync_fetch_and_add(&stats->port_blocklist_hits, 1); __sync_fetch_and_add(&stats->packets_dropped, 1); }
        emit_drop_event(ctx, ip->saddr, ip->daddr, src_port, dst_port, ip->protocol, DROP_REASON_BLOCKLIST, data_end - data);
        return XDP_DROP;
    }
    if (dst_port && bpf_map_lookup_elem(&thor_blocklist_ports, &dst_port)) {
        if (stats) { __sync_fetch_and_add(&stats->port_blocklist_hits, 1); __sync_fetch_and_add(&stats->packets_dropped, 1); }
        emit_drop_event(ctx, ip->saddr, ip->daddr, src_port, dst_port, ip->protocol, DROP_REASON_BLOCKLIST, data_end - data);
        return XDP_DROP;
    }

    /* Rate limiting */
    if (check_rate_limit(ip->saddr)) {
        if (stats) { __sync_fetch_and_add(&stats->rate_limit_hits, 1); __sync_fetch_and_add(&stats->packets_dropped, 1); }
        emit_drop_event(ctx, ip->saddr, ip->daddr, src_port, dst_port, ip->protocol, DROP_REASON_RATE_LIMIT, data_end - data);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
