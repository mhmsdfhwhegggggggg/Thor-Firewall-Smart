// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_BLOCKLIST_ENTRIES 65536
#define RINGBUF_SIZE (1 << 24) // 16 MB
#define RATE_LIMIT_EVENTS_PER_SEC 100

// هيكل الحدث المرسل لمساحة المستخدم (Zero-Copy) يدعم IPv6 و IPv4
struct xdp_drop_event {
    union {
        __u32 ipv4;
        __u32 ipv6[4];
    } src_ip;
    union {
        __u32 ipv4;
        __u32 ipv6[4];
    } dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 reason; // 1=Blocklist, 2=RateLimit Drop
    __u8 is_ipv6;
    __u8 _pad;
    __u64 timestamp_ns;
};

// خريطة LPM Trie للحظر السريع IPv4 (تدعم CIDR مثل 10.0.0.0/8)
struct lpm_key_v4 {
    __u32 prefixlen;
    __u32 ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_v4);
    __type(value, __u8);
    __uint(max_entries, MAX_BLOCKLIST_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} thor_blocklist SEC(".maps");

// خريطة LPM Trie للحظر السريع IPv6
struct lpm_key_v6 {
    __u32 prefixlen;
    __u32 ip[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_v6);
    __type(value, __u8);
    __uint(max_entries, MAX_BLOCKLIST_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} thor_blocklist_v6 SEC(".maps");

// Rate Limit Map for Event Submission to Ring Buffer (per IP)
struct rl_state {
    __u64 count;
    __u64 window_start_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32); // Map by IPv4 for simplicity (lower 32-bits for v6)
    __type(value, struct rl_state);
    __uint(max_entries, MAX_BLOCKLIST_ENTRIES);
} event_rate_limit SEC(".maps");

// Ring Buffer للإبلاغ عن الحظر لمساحة المستخدم بأقصى سرعة
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} thor_xdp_events SEC(".maps");

// Global Configuration Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32); // 0 = Fail-Open, 1 = Fail-Close
    __uint(max_entries, 1);
} thor_config SEC(".maps");

// Rate Limit check function for events (returns 1 if allowed, 0 if rate limited)
static inline int check_rate_limit(__u32 hash_key, __u64 now) {
    struct rl_state *state = bpf_map_lookup_elem(&event_rate_limit, &hash_key);
    if (!state) {
        struct rl_state new_state = { .count = 1, .window_start_ns = now };
        bpf_map_update_elem(&event_rate_limit, &hash_key, &new_state, BPF_ANY);
        return 1;
    }
    
    // 1 second window
    if (now - state->window_start_ns > 1000000000ULL) {
        state->count = 1;
        state->window_start_ns = now;
        return 1;
    }
    
    if (state->count < RATE_LIMIT_EVENTS_PER_SEC) {
        __sync_fetch_and_add(&state->count, 1);
        return 1;
    }
    return 0; // Throttle event submission!
}

SEC("xdp")
int thor_xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u32 cfg_key = 0;
    __u32 *cfg_val_ptr = bpf_map_lookup_elem(&thor_config, &cfg_key);
    __u32 is_fail_close = cfg_val_ptr ? *cfg_val_ptr : 0;

    // 1. تحليل Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return is_fail_close ? XDP_DROP : XDP_PASS; 

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    
    // دعم IPv4 و IPv6 بشكل كامل للمرور والفحص
    if (h_proto == 0x0800) { // IPv4
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return is_fail_close ? XDP_DROP : XDP_PASS;
        
        __u32 src_ip = bpf_ntohl(ip->saddr);
        __u32 dst_ip = bpf_ntohl(ip->daddr);
        __u8 protocol = ip->protocol;

        struct lpm_key_v4 key = { .prefixlen = 32, .ip = src_ip };
        if (bpf_map_lookup_elem(&thor_blocklist, &key)) {
            __u64 now = bpf_ktime_get_ns();
            if (check_rate_limit(src_ip, now)) {
                struct xdp_drop_event *e = bpf_ringbuf_reserve(&thor_xdp_events, sizeof(*e), 0);
                if (e) {
                    e->is_ipv6 = 0;
                    e->src_ip.ipv4 = src_ip;
                    e->dst_ip.ipv4 = dst_ip;
                    e->protocol = protocol;
                    e->reason = 1; // Blocklist
                    e->timestamp_ns = now;
                    bpf_ringbuf_submit(e, 0);
                }
            }
            return XDP_DROP;
        }
        return XDP_PASS;
        
    } else if (h_proto == 0x86DD) { // IPv6
        struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return is_fail_close ? XDP_DROP : XDP_PASS;
        
        struct lpm_key_v6 key6;
        key6.prefixlen = 128;
        __builtin_memcpy(&key6.ip, &ip6->saddr, 16);

        if (bpf_map_lookup_elem(&thor_blocklist_v6, &key6)) {
            __u64 now = bpf_ktime_get_ns();
            // simple hash key for ratelimit (use last 4 bytes of IPv6 for simplicity in Map key)
            if (check_rate_limit(key6.ip[3], now)) {
                struct xdp_drop_event *e = bpf_ringbuf_reserve(&thor_xdp_events, sizeof(*e), 0);
                if (e) {
                    e->is_ipv6 = 1;
                    __builtin_memcpy(&e->src_ip.ipv6, &ip6->saddr, 16);
                    __builtin_memcpy(&e->dst_ip.ipv6, &ip6->daddr, 16);
                    e->protocol = ip6->nexthdr;
                    e->reason = 1; // Blocklist Drop
                    e->timestamp_ns = now;
                    bpf_ringbuf_submit(e, 0);
                }
            }
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
