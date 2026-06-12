// SPDX-License-Identifier: GPL-2.0
// Placeholder for vmlinux.h or necessary linux headers
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

// Forward declarations to avoid complex vmlinux.h dependency in lightweight setup
struct sock {
    struct {
        __u16 skc_dport;
        __u32 skc_daddr;
    } __sk_common;
};

struct msghdr {
    void *msg_name;
};

struct pt_regs;

#define TASK_COMM_LEN 16
#define MAX_TLS_PAYLOAD 256

struct tls_hello_event {
    __u32 pid;
    __u8 comm[TASK_COMM_LEN];
    __u32 dst_ip;
    __u16 dst_port;
    __u16 payload_len;
    __u8 payload[MAX_TLS_PAYLOAD];
    __u64 timestamp_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} tls_events SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    __u16 dport = bpf_ntohs(sk->__sk_common.skc_dport);
    
    // Monitors only standard HTTPS ports
    if (dport != 443 && dport != 8443) return 0;

    struct tls_hello_event *e;
    e = bpf_ringbuf_reserve(&tls_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->dst_ip = sk->__sk_common.skc_daddr;
    e->dst_port = dport;
    e->timestamp_ns = bpf_ktime_get_ns();
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
