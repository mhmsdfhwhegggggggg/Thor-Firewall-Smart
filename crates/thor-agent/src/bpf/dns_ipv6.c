// SPDX-License-Identifier: GPL-2.0
// ThorFirewall BPF — IPv6 DNS Monitor
//
// Extends the IPv4 DNS monitor to support IPv6 packets, including:
//   ▸ IPv6 fixed header parsing (RFC 2460)
//   ▸ Extension header chaining (Hop-by-Hop, Routing, Fragment, Dest)
//   ▸ UDP/DNS extraction from IPv6 payload
//   ▸ DNS query name extraction (same logic as IPv4)
//   ▸ Submission to the same perf event ring as IPv4 DNS events

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ─── Constants ─────────────────────────────────────────────────────────────

#define DNS_PORT        53
#define MAX_DNS_NAME    128
#define MAX_LABELS      16

// IPv6 extension header next-protocol values (RFC 2460)
#define IPPROTO_HOPOPTS  0   // Hop-by-Hop
#define IPPROTO_ROUTING  43  // Routing
#define IPPROTO_FRAGMENT 44  // Fragment (fixed 8-byte header, no len field)
#define IPPROTO_ESP      50  // Encapsulating Security Payload
#define IPPROTO_AH       51  // Authentication Header
#define IPPROTO_DSTOPTS  60  // Destination Options
#define IPPROTO_MH       135 // Mobility Header

// ─── Data Structures ───────────────────────────────────────────────────────

struct dns_event {
    __u8  query[MAX_DNS_NAME]; // null-terminated DNS name
    __u16 qtype;               // QTYPE (A=1, AAAA=28, TXT=16, MX=15, ...)
    __u16 qclass;              // QCLASS (IN=1)
    __u32 src_ip4;             // 0 if IPv6
    __u32 dst_ip4;             // 0 if IPv6
    __u8  src_ip6[16];         // IPv6 source (zeroed if IPv4)
    __u8  dst_ip6[16];         // IPv6 destination
    __u16 src_port;
    __u16 dst_port;
    __u8  is_ipv6;             // 1 if IPv6, 0 if IPv4
    __u8  is_response;         // 1 if QR bit set
    __u16 transaction_id;
};

// ─── Maps ─────────────────────────────────────────────────────────────────

// Shared with IPv4 DNS monitor — same perf buffer
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} dns_events SEC(".maps");

// Scratch space for event building (per-CPU)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dns_event);
} dns_scratch SEC(".maps");

// ─── Helper: Extract DNS name from wire format ────────────────────────────

// Returns number of bytes consumed from payload, or -1 on error.
// Writes up to MAX_DNS_NAME-1 bytes of the decoded name to buf.
static __always_inline int
extract_dns_name(const void *data, const void *data_end,
                 int offset, char *buf, int buflen)
{
    int written = 0;
    int hops = 0;

    #pragma unroll
    for (int i = 0; i < MAX_LABELS; i++) {
        if (offset + 1 > (int)(data_end - data)) break;

        __u8 len = *((__u8 *)(data + offset));
        offset++;

        if (len == 0) break; // end of name

        // Compression pointer check (top 2 bits = 0b11)
        if ((len & 0xC0) == 0xC0) {
            // Compression: skip 1 more byte
            offset++;
            break;
        }

        // Add dot separator
        if (written > 0 && written < buflen - 1) {
            buf[written++] = '.';
        }

        // Copy label bytes
        #pragma unroll
        for (int j = 0; j < 64; j++) {
            if (j >= len) break;
            if (offset + 1 > (int)(data_end - data)) break;
            if (written >= buflen - 1) break;
            buf[written++] = *((__u8 *)(data + offset));
            offset++;
        }

        if (++hops >= MAX_LABELS) break;
    }

    if (written < buflen) buf[written] = '\0';
    return offset;
}

// ─── Helper: Skip IPv6 extension headers ─────────────────────────────────

// Returns the offset of the first non-extension payload byte,
// and writes the transport protocol to *proto.
// Returns -1 on parse error.
static __always_inline int
skip_ipv6_ext_headers(const void *data, const void *data_end,
                      int offset, __u8 start_proto, __u8 *out_proto)
{
    __u8 proto = start_proto;

    // Allow at most 8 extension headers to prevent infinite loops
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        switch (proto) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
        case IPPROTO_MH: {
            // Variable-length: [next_hdr][hdr_ext_len][6 bytes + (hdr_ext_len * 8) bytes]
            if (offset + 2 > (int)(data_end - data)) return -1;
            __u8 next_hdr = *((__u8 *)(data + offset));
            __u8 ext_len  = *((__u8 *)(data + offset + 1));
            proto  = next_hdr;
            offset += 8 + (ext_len * 8);
            break;
        }
        case IPPROTO_FRAGMENT: {
            // Fixed 8-byte fragment header
            if (offset + 2 > (int)(data_end - data)) return -1;
            __u8 next_hdr = *((__u8 *)(data + offset));
            proto  = next_hdr;
            offset += 8;
            break;
        }
        case IPPROTO_AH: {
            // AH: [next_hdr][payload_len][...], length in 4-byte units + 2
            if (offset + 2 > (int)(data_end - data)) return -1;
            __u8 next_hdr = *((__u8 *)(data + offset));
            __u8 pl_len   = *((__u8 *)(data + offset + 1));
            proto  = next_hdr;
            offset += 8 + ((pl_len - 1) * 4);
            break;
        }
        default:
            // No more extension headers
            goto done;
        }

        if (offset >= (int)(data_end - data)) return -1;
    }

done:
    *out_proto = proto;
    return offset;
}

// ─── TC Hook: IPv6 Ingress DNS Capture ───────────────────────────────────

SEC("tc/ipv6_dns_ingress")
int thor_ipv6_dns_ingress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Must have Ethernet + IPv6 headers
    if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
        return TC_ACT_OK;

    struct ethhdr  *eth  = data;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IPV6)
        return TC_ACT_OK;

    struct ipv6hdr *ip6  = data + sizeof(struct ethhdr);
    int payload_offset   = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

    // Skip extension headers to find UDP
    __u8 proto = 0;
    int udp_offset = skip_ipv6_ext_headers(data, data_end,
                                            payload_offset, ip6->nexthdr, &proto);
    if (udp_offset < 0 || proto != IPPROTO_UDP) return TC_ACT_OK;

    // Must have UDP header
    if ((void *)(data + udp_offset) + sizeof(struct udphdr) > data_end)
        return TC_ACT_OK;

    struct udphdr *udp = data + udp_offset;
    __u16 dst_port = bpf_ntohs(udp->dest);
    __u16 src_port = bpf_ntohs(udp->source);

    if (dst_port != DNS_PORT && src_port != DNS_PORT) return TC_ACT_OK;

    // DNS payload starts 8 bytes after UDP header start
    int dns_offset = udp_offset + sizeof(struct udphdr);
    if (data + dns_offset + 12 > data_end) return TC_ACT_OK; // DNS header = 12 bytes

    // Get scratch event slot
    __u32 zero = 0;
    struct dns_event *ev = bpf_map_lookup_elem(&dns_scratch, &zero);
    if (!ev) return TC_ACT_OK;

    // Zero out the event
    __builtin_memset(ev, 0, sizeof(*ev));

    // Parse DNS header
    ev->transaction_id = bpf_ntohs(*(__u16 *)(data + dns_offset));
    __u16 flags        = bpf_ntohs(*(__u16 *)(data + dns_offset + 2));
    ev->is_response    = (flags >> 15) & 1;

    // Copy IPv6 addresses
    __builtin_memcpy(ev->src_ip6, &ip6->saddr, 16);
    __builtin_memcpy(ev->dst_ip6, &ip6->daddr, 16);
    ev->src_port = src_port;
    ev->dst_port = dst_port;
    ev->is_ipv6  = 1;

    // Extract DNS query name (starts at offset 12 from DNS header start)
    int name_off = extract_dns_name(data, data_end,
                                    dns_offset + 12,
                                    (char *)ev->query, MAX_DNS_NAME);

    // Extract QTYPE + QCLASS (4 bytes after the name's null terminator)
    if (name_off > 0 && data + name_off + 4 <= data_end) {
        ev->qtype  = bpf_ntohs(*(__u16 *)(data + name_off));
        ev->qclass = bpf_ntohs(*(__u16 *)(data + name_off + 2));
    }

    // Submit event to userspace ring
    bpf_perf_event_output(skb, &dns_events, BPF_F_CURRENT_CPU, ev, sizeof(*ev));
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
