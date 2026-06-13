// SPDX-License-Identifier: GPL-2.0
//
// dns_monitor.bpf.c — eBPF DNS Query Monitor
// Captures all outbound DNS queries in kernel space.
// Detects: DNS tunneling, C2 over DNS, DGA domains, unusually long queries.
//
// Attach points:
//   kprobe/udp_sendmsg    — capture outbound UDP (port 53)
//   tracepoint/net/netif_rx — packet ingress for DNS response parsing

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_DNS_NAME    256
#define MAX_EVENTS      65536
#define DNS_PORT        53
#define DNS_TUNNEL_LEN  60    // queries >60 chars are suspicious
#define MAX_LABELS      10    // DNS labels per query

// ─── Event types ──────────────────────────────────────────────────────────────

#define DNS_EVENT_QUERY     1
#define DNS_EVENT_RESPONSE  2
#define DNS_EVENT_TUNNEL    3   // suspected DNS tunneling
#define DNS_EVENT_DGA       4   // suspected DGA domain

// ─── Maps ─────────────────────────────────────────────────────────────────────

// Ring buffer for events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} dns_events SEC(".maps");

// Rate limit: src_ip → query count per second
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} dns_rate_limit SEC(".maps");

// Blocklist of known bad DNS query substrings (label hash)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, __u8);
} dns_blocklist SEC(".maps");

// ─── Event structs ────────────────────────────────────────────────────────────

struct dns_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 query_len;
    __u8  event_type;   // DNS_EVENT_*
    __u8  label_count;
    __u8  suspicious;   // 1 = suspicious, 0 = normal
    char  query[MAX_DNS_NAME];
};

// ─── DNS Header ───────────────────────────────────────────────────────────────

struct dns_header {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

static __always_inline __u64 hash_bytes(const char *data, int len) {
    __u64 h = 0xcbf29ce484222325ULL; // FNV-1a offset basis
    for (int i = 0; i < len && i < 64; i++) {
        h ^= (__u64)(unsigned char)data[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

static __always_inline int is_high_entropy(const char *label, int len) {
    // Simple entropy check: count unique characters
    // High entropy in DNS labels is a DGA signature
    __u64 seen = 0;
    int uniq = 0;
    for (int i = 0; i < len && i < 32; i++) {
        unsigned char c = (unsigned char)label[i];
        if (c < 64) {
            __u64 bit = 1ULL << c;
            if (!(seen & bit)) { seen |= bit; uniq++; }
        }
    }
    // >20 unique chars in a 32-char window → suspicious
    return (len > 20 && uniq > 20) ? 1 : 0;
}

static __always_inline int check_rate_limit(__u32 src_ip) {
    __u64 now = bpf_ktime_get_ns();
    __u64 *count = bpf_map_lookup_elem(&dns_rate_limit, &src_ip);
    if (!count) {
        __u64 init = 1;
        bpf_map_update_elem(&dns_rate_limit, &src_ip, &init, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(count, 1);
    // >100 DNS queries in observed window from one IP is tunneling-like
    return (*count > 100) ? 1 : 0;
}

// ─── TC (Traffic Control) ingress hook ───────────────────────────────────────

SEC("tc")
int dns_monitor(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return TC_ACT_OK;

    // IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;

    // UDP header
    struct udphdr *udp = (struct udphdr *)((char *)ip + (ip->ihl * 4));
    if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

    __u16 dst_port = bpf_ntohs(udp->dest);
    __u16 src_port = bpf_ntohs(udp->source);
    if (dst_port != DNS_PORT && src_port != DNS_PORT) return TC_ACT_OK;

    // DNS header
    struct dns_header *dns = (struct dns_header *)(udp + 1);
    if ((void *)(dns + 1) > data_end) return TC_ACT_OK;

    __u8  is_query    = !(bpf_ntohs(dns->flags) & 0x8000);
    __u16 qdcount     = bpf_ntohs(dns->qdcount);

    if (!is_query || qdcount == 0) return TC_ACT_OK;

    // Allocate ring buffer event
    struct dns_event *ev = bpf_ringbuf_reserve(&dns_events, sizeof(*ev), 0);
    if (!ev) return TC_ACT_OK;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->src_ip       = ip->saddr;
    ev->dst_ip       = ip->daddr;
    ev->src_port     = src_port;
    ev->dst_port     = dst_port;
    ev->event_type   = DNS_EVENT_QUERY;
    ev->suspicious   = 0;
    ev->label_count  = 0;

    // Parse DNS question: labels separated by length bytes
    char *qname = (char *)(dns + 1);
    int   total_len = 0;
    int   label_count = 0;
    int   max_entropy = 0;

    #pragma unroll
    for (int i = 0; i < MAX_LABELS; i++) {
        if ((void *)(qname + 1) > data_end) break;
        __u8 label_len = *(__u8 *)qname;
        if (label_len == 0) break;
        if (label_len > 63) { ev->suspicious = 1; break; }

        qname++;
        if ((void *)(qname + label_len) > data_end) break;

        // Copy label into query buffer
        if (total_len + label_len + 1 < MAX_DNS_NAME) {
            if (total_len > 0) ev->query[total_len++] = '.';
            bpf_probe_read_kernel(&ev->query[total_len],
                                  label_len < 64 ? label_len : 64, qname);
            total_len += label_len;
        }

        // Check label entropy (DGA detection)
        if (is_high_entropy(qname, label_len)) max_entropy = 1;

        qname += label_len;
        label_count++;
    }

    ev->query_len  = total_len;
    ev->label_count = label_count;

    // DNS tunneling heuristics
    int suspicious_rate  = check_rate_limit(ip->saddr);
    int suspicious_len   = (total_len > DNS_TUNNEL_LEN) ? 1 : 0;
    int suspicious_dga   = max_entropy;

    if (suspicious_rate || suspicious_len) {
        ev->suspicious = 1;
        ev->event_type = DNS_EVENT_TUNNEL;
    } else if (suspicious_dga) {
        ev->suspicious = 1;
        ev->event_type = DNS_EVENT_DGA;
    }

    bpf_ringbuf_submit(ev, 0);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
