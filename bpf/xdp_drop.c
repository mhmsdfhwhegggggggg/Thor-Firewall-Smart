// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_BLOCKLIST_ENTRIES 65536
#define RINGBUF_SIZE (1 << 24) // 16 MB
#define RATE_LIMIT_EVENTS_PER_SEC 100

// CMS parameters
#define CMS_ROWS 3
#define CMS_COLS 16384
#define CMS_MASK (CMS_COLS - 1)

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
    __u8 reason; 
    __u8 is_ipv6;
    __u8 _pad;
    __u64 timestamp_ns;
};

// blocklist maps
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

// 1. HEARTBEAT MAPS
struct hb_state {
    __u32 last_tick;
    __u64 last_tick_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct hb_state);
    __uint(max_entries, 1);
} thor_agent_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1); // User space increments this every 1s
} thor_agent_tick SEC(".maps");

// 2. COUNT-MIN SKETCH FOR RATE LIMITING
struct cms_val {
    __u64 window_start_ns;
    __u32 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct cms_val);
    __uint(max_entries, CMS_ROWS * CMS_COLS);
} event_rate_limit_cms SEC(".maps");

static __always_inline __u32 inline_hash(__u32 val, __u32 seed) {
    val ^= seed;
    val ^= val >> 16;
    val *= 0x85ebca6b;
    val ^= val >> 13;
    val *= 0xc2b2ae35;
    val ^= val >> 16;
    return val;
}

static __always_inline int check_rate_limit_cms(__u32 ip, __u64 now) {
    __u64 window_start = now - (now % 1000000000ULL);
    __u32 hashes[CMS_ROWS];
    hashes[0] = inline_hash(ip, 0x12345678) & CMS_MASK;
    hashes[1] = inline_hash(ip, 0x87654321) & CMS_MASK;
    hashes[2] = inline_hash(ip, 0x9E3779B9) & CMS_MASK;

    __u32 min_count = 0xFFFFFFFF;

    #pragma unroll
    for (int i = 0; i < CMS_ROWS; i++) {
        __u32 idx = i * CMS_COLS + hashes[i];
        struct cms_val *v = bpf_map_lookup_elem(&event_rate_limit_cms, &idx);
        if (v) {
            if (v->window_start_ns != window_start) {
                v->window_start_ns = window_start;
                v->count = 0;
            }
            __sync_fetch_and_add(&v->count, 1);
            if (v->count < min_count) {
                min_count = v->count;
            }
        }
    }

    if (min_count > RATE_LIMIT_EVENTS_PER_SEC) {
        return 0; // Throttle
    }
    return 1;
}

SEC("xdp")
int thor_xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u32 zero = 0;
    __u32 *cfg_val_ptr = bpf_map_lookup_elem(&thor_config, &zero);
    __u32 is_fail_close = cfg_val_ptr ? *cfg_val_ptr : 0;
    
    __u64 now = bpf_ktime_get_ns();

    // Heartbeat check
    __u32 *user_tick = bpf_map_lookup_elem(&thor_agent_tick, &zero);
    struct hb_state *state = bpf_map_lookup_elem(&thor_agent_state, &zero);
    
    if (user_tick && state) {
        if (*user_tick != state->last_tick) {
            state->last_tick = *user_tick;
            state->last_tick_ns = now;
        } else if (now - state->last_tick_ns > 2000000000ULL) {
            // Agent hasn't ticked in 2 seconds - considered dead.
            if (is_fail_close) return XDP_DROP;
        }
    }

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return is_fail_close ? XDP_DROP : XDP_PASS; 

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    
    if (h_proto == 0x0800) { 
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return is_fail_close ? XDP_DROP : XDP_PASS;
        
        __u32 src_ip = bpf_ntohl(ip->saddr);
        __u32 dst_ip = bpf_ntohl(ip->daddr);
        __u8 protocol = ip->protocol;

        struct lpm_key_v4 key = { .prefixlen = 32, .ip = src_ip };
        if (bpf_map_lookup_elem(&thor_blocklist, &key)) {
            if (check_rate_limit_cms(src_ip, now)) {
                struct xdp_drop_event *e = bpf_ringbuf_reserve(&thor_xdp_events, sizeof(*e), 0);
                if (e) {
                    e->is_ipv6 = 0;
                    e->src_ip.ipv4 = src_ip;
                    e->dst_ip.ipv4 = dst_ip;
                    e->protocol = protocol;
                    e->reason = 1; 
                    e->timestamp_ns = now;
                    bpf_ringbuf_submit(e, 0);
                }
            }
            return XDP_DROP;
        }
        return XDP_PASS;
        
    } else if (h_proto == 0x86DD) { 
        struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return is_fail_close ? XDP_DROP : XDP_PASS;
        
        // --- IPv6 EXTENSION HEADERS PARSING ---
        __u8 nexthdr = ip6->nexthdr;
        void *hdr_ptr = ip6 + 1;
        
        #pragma unroll
        for (int i = 0; i < 6; i++) {
            if (nexthdr == 0 || nexthdr == 43 || nexthdr == 60 || nexthdr == 51 || nexthdr == 135) {
                struct { __u8 nexthdr; __u8 len; } *ext = hdr_ptr;
                if ((void *)(ext + 1) > data_end) return is_fail_close ? XDP_DROP : XDP_PASS;
                nexthdr = ext->nexthdr;
                hdr_ptr += (ext->len + 1) * 8; 
            } else if (nexthdr == 44) {
                struct { __u8 nexthdr; __u8 reserved; __u16 frag_off; __u32 id; } *frag = hdr_ptr;
                if ((void *)(frag + 1) > data_end) return is_fail_close ? XDP_DROP : XDP_PASS;
                nexthdr = frag->nexthdr;
                hdr_ptr += 8;
            } else {
                break;
            }
        }
        
        if (hdr_ptr > data_end) {
             return is_fail_close ? XDP_DROP : XDP_PASS;
        }
        // -------------------------------------

        struct lpm_key_v6 key6;
        key6.prefixlen = 128;
        __builtin_memcpy(&key6.ip, &ip6->saddr, 16);

        if (bpf_map_lookup_elem(&thor_blocklist_v6, &key6)) {
            if (check_rate_limit_cms(key6.ip[3], now)) {
                struct xdp_drop_event *e = bpf_ringbuf_reserve(&thor_xdp_events, sizeof(*e), 0);
                if (e) {
                    e->is_ipv6 = 1;
                    __builtin_memcpy(&e->src_ip.ipv6, &ip6->saddr, 16);
                    __builtin_memcpy(&e->dst_ip.ipv6, &ip6->daddr, 16);
                    e->protocol = nexthdr; // Use the parsed inner protocol
                    e->reason = 1; 
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
