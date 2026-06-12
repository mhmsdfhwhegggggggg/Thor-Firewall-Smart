// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_BLOCKLIST_ENTRIES 65536
#define RINGBUF_SIZE (1 << 24) // 16 MB

// هيكل الحدث المرسل لمساحة المستخدم (Zero-Copy)
struct xdp_drop_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 reason; // 1=Blocklist, 2=RateLimit
    __u64 timestamp_ns;
};

// خريطة LPM Trie للحظر السريع (تدعم CIDR مثل 10.0.0.0/8)
struct lpm_key {
    __u32 prefixlen;
    __u32 ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(max_entries, MAX_BLOCKLIST_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} thor_blocklist SEC(".maps");

// Ring Buffer للإبلاغ عن الحظر لمساحة المستخدم بأقصى سرعة
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} thor_xdp_events SEC(".maps");

SEC("xdp")
int thor_xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. تحليل Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; // Fail-Open: إذا كانت الحزمة مشوهة، اسمح لها لتجنب تعطيل الشبكة

    if (bpf_ntohs(eth->h_proto) != 0x0800) // IPv4 only for this example
        return XDP_PASS;

    // 2. تحليل IP Header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    __u8 protocol = ip->protocol;

    // 3. فحص قائمة الحظر (LPM Trie Lookup - O(1) تقريباً)
    struct lpm_key key = { .prefixlen = 32, .ip = src_ip };
    if (bpf_map_lookup_elem(&thor_blocklist, &key)) {
        // إرسال حدث لمساحة المستخدم قبل الحظر
        struct xdp_drop_event *e = bpf_ringbuf_reserve(&thor_xdp_events, sizeof(*e), 0);
        if (e) {
            e->src_ip = src_ip;
            e->dst_ip = dst_ip;
            e->protocol = protocol;
            e->reason = 1; // Blocklist
            e->timestamp_ns = bpf_ktime_get_ns();
            bpf_ringbuf_submit(e, 0);
        }
        return XDP_DROP; // الحظر الفعلي في مستوى الـ NIC Driver
    }

    // 4. تحليل TCP/UDP Ports (للفحص المتقدم لاحقاً)
    __u32 ip_hdr_len = ip->ihl * 4;
    void *l4_hdr = (void *)ip + ip_hdr_len;
    
    if (protocol == 6) { // TCP
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) <= data_end) {
            // يمكن إضافة فحص SYN Flood هنا
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
