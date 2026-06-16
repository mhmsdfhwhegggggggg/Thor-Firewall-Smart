// SPDX-License-Identifier: GPL-2.0
//
// dns_monitor.bpf.c — eBPF DNS Query Monitor (IPv4 + IPv6)
// Captures all outbound DNS queries in kernel space.
// Detects: DNS tunneling, C2 over DNS, DGA domains, unusually long queries.
// IPv6: Full extension-header chaining (Hop-by-Hop, Routing, Fragment, Dest).
//
// Attach points:
//   tc/ingress — packet ingress, handles both IPv4 (ETH_P_IP) and IPv6 (ETH_P_IPV6)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_DNS_NAME        256
#define MAX_EVENTS          65536
#define DNS_PORT            53
#define DNS_TUNNEL_LEN      60
#define MAX_LABELS          10
#define MAX_EXT_HEADERS     8   /* max extension headers to chain */

/* Ethernet protocol constants */
#define ETH_P_IP            0x0800
#define ETH_P_IPV6          0x86DD

/* IPv6 extension header next-header values (RFC 2460) */
#define IPV6_NH_HOPBYHOP    0
#define IPV6_NH_ROUTING     43
#define IPV6_NH_FRAGMENT    44
#define IPV6_NH_ESP         50
#define IPV6_NH_AH          51
#define IPV6_NH_DEST_OPT    60
#define IPV6_NH_MOBILITY    135
#define IPV6_NH_UDP         17
#define IPV6_NH_TCP         6

/* ─── Event types ─────────────────────────────────────────────────── */
#define DNS_EVENT_QUERY     1
#define DNS_EVENT_RESPONSE  2
#define DNS_EVENT_TUNNEL    3
#define DNS_EVENT_DGA       4
#define DNS_EVENT_BLOCKLIST 5

/* Address family tag */
#define AF_INET4            4
#define AF_INET6            6

/* ─── Maps ────────────────────────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} dns_events SEC(".maps");

/* IPv4 rate limit: src_ipv4 → query count */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} dns_rate_limit_v4 SEC(".maps");

/* IPv6 rate limit: src_ipv6[16] → query count  */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u8[16]);
    __type(value, __u64);
} dns_rate_limit_v6 SEC(".maps");

/* Blocklist of known bad DNS query substrings (label hash) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, __u8);
} dns_blocklist SEC(".maps");

/* ─── Event struct (supports both IPv4 and IPv6) ─────────────────── */
struct dns_event {
    __u64 timestamp_ns;
    /* 16-byte address fields: IPv4 stored in first 4 bytes, rest zero */
    __u8  src_addr[16];
    __u8  dst_addr[16];
    __u16 src_port;
    __u16 dst_port;
    __u16 query_len;
    __u8  event_type;
    __u8  label_count;
    __u8  suspicious;
    __u8  addr_family;   /* AF_INET4 or AF_INET6 */
    __u8  _pad[2];
    char  query[MAX_DNS_NAME];
};

/* ─── DNS Header ─────────────────────────────────────────────────── */
struct dns_header {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

/* ─── Helpers ────────────────────────────────────────────────────── */
static __always_inline __u64 hash_bytes(const char *data, int len) {
    __u64 h = 0xcbf29ce484222325ULL;
    for (int i = 0; i < len && i < 64; i++) {
        h ^= (__u64)(unsigned char)data[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

static __always_inline int is_high_entropy(const char *label, int len) {
    __u64 seen = 0;
    int uniq = 0;
    for (int i = 0; i < len && i < 32; i++) {
        unsigned char c = (unsigned char)label[i];
        if (c < 64) {
            __u64 bit = 1ULL << c;
            if (!(seen & bit)) { seen |= bit; uniq++; }
        }
    }
    return (len > 20 && uniq > 20) ? 1 : 0;
}

static __always_inline int check_rate_limit_v4(__u32 src_ip) {
    __u64 *count = bpf_map_lookup_elem(&dns_rate_limit_v4, &src_ip);
    if (!count) {
        __u64 init = 1;
        bpf_map_update_elem(&dns_rate_limit_v4, &src_ip, &init, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(count, 1);
    return (*count > 100) ? 1 : 0;
}

static __always_inline int check_rate_limit_v6(__u8 src_ip[16]) {
    __u64 *count = bpf_map_lookup_elem(&dns_rate_limit_v6, src_ip);
    if (!count) {
        __u64 init = 1;
        bpf_map_update_elem(&dns_rate_limit_v6, src_ip, &init, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(count, 1);
    return (*count > 100) ? 1 : 0;
}

/* Parse DNS labels from the question section, populate query string */
static __always_inline void parse_dns_labels(
    void *data_end, char *qname_ptr,
    struct dns_event *ev)
{
    int total_len = 0;
    int label_count = 0;
    int max_entropy = 0;

    #pragma unroll
    for (int i = 0; i < MAX_LABELS; i++) {
        if ((void *)((__u8 *)qname_ptr + 1) > data_end) break;
        __u8 label_len = *(__u8 *)qname_ptr;
        if (label_len == 0) break;
        if (label_len > 63) { ev->suspicious = 1; break; }

        qname_ptr++;
        if ((void *)((__u8 *)qname_ptr + label_len) > data_end) break;

        if (total_len + label_len + 1 < MAX_DNS_NAME) {
            if (total_len > 0) ev->query[total_len++] = '.';
            bpf_probe_read_kernel(
                &ev->query[total_len],
                label_len < 64 ? label_len : 64,
                qname_ptr);
            total_len += label_len;
        }

        if (is_high_entropy(qname_ptr, label_len)) max_entropy = 1;

        qname_ptr += label_len;
        label_count++;
    }

    ev->query_len   = total_len;
    ev->label_count = label_count;

    /* Tunneling heuristics (applied post-parse, no IP needed) */
    if (total_len > DNS_TUNNEL_LEN) {
        ev->suspicious = 1;
        ev->event_type = DNS_EVENT_TUNNEL;
    } else if (max_entropy) {
        ev->suspicious = 1;
        ev->event_type = DNS_EVENT_DGA;
    }
}

/* ─── TC hook ────────────────────────────────────────────────────── */
SEC("tc")
int dns_monitor(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    /* ── Branch A: IPv4 ────────────────────────────────────────────── */
    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
        if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;

        struct udphdr *udp = (struct udphdr *)((char *)ip + (ip->ihl * 4));
        if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

        __u16 dst_port = bpf_ntohs(udp->dest);
        __u16 src_port = bpf_ntohs(udp->source);
        if (dst_port != DNS_PORT && src_port != DNS_PORT) return TC_ACT_OK;

        struct dns_header *dns = (struct dns_header *)(udp + 1);
        if ((void *)(dns + 1) > data_end) return TC_ACT_OK;

        __u8  is_query = !(bpf_ntohs(dns->flags) & 0x8000);
        __u16 qdcount  = bpf_ntohs(dns->qdcount);
        if (!is_query || qdcount == 0) return TC_ACT_OK;

        struct dns_event *ev = bpf_ringbuf_reserve(&dns_events, sizeof(*ev), 0);
        if (!ev) return TC_ACT_OK;

        ev->timestamp_ns = bpf_ktime_get_ns();
        /* Store IPv4 in first 4 bytes of 16-byte field, rest zero */
        __builtin_memset(ev->src_addr, 0, 16);
        __builtin_memset(ev->dst_addr, 0, 16);
        *(__u32 *)ev->src_addr = ip->saddr;
        *(__u32 *)ev->dst_addr = ip->daddr;
        ev->src_port    = src_port;
        ev->dst_port    = dst_port;
        ev->event_type  = DNS_EVENT_QUERY;
        ev->suspicious  = 0;
        ev->label_count = 0;
        ev->addr_family = AF_INET4;

        int suspicious_rate = check_rate_limit_v4(ip->saddr);
        parse_dns_labels(data_end, (char *)(dns + 1), ev);

        if (suspicious_rate && ev->event_type == DNS_EVENT_QUERY) {
            ev->suspicious = 1;
            ev->event_type = DNS_EVENT_TUNNEL;
        }

        bpf_ringbuf_submit(ev, 0);
        return TC_ACT_OK;
    }

    /* ── Branch B: IPv6 ────────────────────────────────────────────── */
    if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return TC_ACT_OK;

        __u8  next_hdr   = ip6->nexthdr;
        void *ext_cursor = (void *)(ip6 + 1);

        /* Walk extension headers (RFC 2460 §4) — up to MAX_EXT_HEADERS */
        #pragma unroll
        for (int h = 0; h < MAX_EXT_HEADERS; h++) {
            /* Hop-by-Hop (0), Routing (43), Destination Options (60), Mobility (135) */
            if (next_hdr == IPV6_NH_HOPBYHOP ||
                next_hdr == IPV6_NH_ROUTING   ||
                next_hdr == IPV6_NH_DEST_OPT  ||
                next_hdr == IPV6_NH_MOBILITY) {
                /* Extension headers have: 1-byte next-hdr, 1-byte len (units of 8),
                   followed by (len+1)*8 - 2 bytes of data. */
                if ((void *)((char *)ext_cursor + 2) > data_end) return TC_ACT_OK;
                __u8 *hdr_bytes = (__u8 *)ext_cursor;
                next_hdr   = hdr_bytes[0];
                __u8 hdrlen = hdr_bytes[1];
                ext_cursor  = (void *)((char *)ext_cursor + ((__u32)(hdrlen + 1) * 8));
                if (ext_cursor > data_end) return TC_ACT_OK;

            } else if (next_hdr == IPV6_NH_FRAGMENT) {
                /* Fragment header is fixed 8 bytes */
                if ((void *)((char *)ext_cursor + 8) > data_end) return TC_ACT_OK;
                __u8 *frag_hdr = (__u8 *)ext_cursor;
                next_hdr   = frag_hdr[0];
                ext_cursor = (void *)((char *)ext_cursor + 8);

            } else if (next_hdr == IPV6_NH_AH) {
                /* AH header: next(1) + payloadlen(1) + reserved(2) + spi(4) + seq(4) */
                if ((void *)((char *)ext_cursor + 2) > data_end) return TC_ACT_OK;
                __u8 *ah_hdr = (__u8 *)ext_cursor;
                next_hdr   = ah_hdr[0];
                __u8 ah_len = ah_hdr[1];
                ext_cursor  = (void *)((char *)ext_cursor + ((__u32)(ah_len + 2) * 4));
                if (ext_cursor > data_end) return TC_ACT_OK;

            } else {
                /* Not an extension header — stop walking */
                break;
            }
        }

        /* After walking extension headers, next_hdr should be UDP */
        if (next_hdr != IPV6_NH_UDP) return TC_ACT_OK;

        struct udphdr *udp = (struct udphdr *)ext_cursor;
        if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

        __u16 dst_port = bpf_ntohs(udp->dest);
        __u16 src_port = bpf_ntohs(udp->source);
        if (dst_port != DNS_PORT && src_port != DNS_PORT) return TC_ACT_OK;

        struct dns_header *dns = (struct dns_header *)(udp + 1);
        if ((void *)(dns + 1) > data_end) return TC_ACT_OK;

        __u8  is_query = !(bpf_ntohs(dns->flags) & 0x8000);
        __u16 qdcount  = bpf_ntohs(dns->qdcount);
        if (!is_query || qdcount == 0) return TC_ACT_OK;

        struct dns_event *ev = bpf_ringbuf_reserve(&dns_events, sizeof(*ev), 0);
        if (!ev) return TC_ACT_OK;

        ev->timestamp_ns = bpf_ktime_get_ns();
        /* Copy 16-byte IPv6 addresses verbatim */
        bpf_probe_read_kernel(ev->src_addr, 16, &ip6->saddr);
        bpf_probe_read_kernel(ev->dst_addr, 16, &ip6->daddr);
        ev->src_port    = src_port;
        ev->dst_port    = dst_port;
        ev->event_type  = DNS_EVENT_QUERY;
        ev->suspicious  = 0;
        ev->label_count = 0;
        ev->addr_family = AF_INET6;

        int suspicious_rate = check_rate_limit_v6((__u8 *)&ip6->saddr);
        parse_dns_labels(data_end, (char *)(dns + 1), ev);

        if (suspicious_rate && ev->event_type == DNS_EVENT_QUERY) {
            ev->suspicious = 1;
            ev->event_type = DNS_EVENT_TUNNEL;
        }

        bpf_ringbuf_submit(ev, 0);
        return TC_ACT_OK;
    }

    /* Not IP — pass through */
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
