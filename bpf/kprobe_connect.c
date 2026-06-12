// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define RINGBUF_SIZE (1 << 24)

struct process_net_event {
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    __u32 dst_ip;
    __u16 dst_port;
    __u8 protocol;
    __u64 timestamp_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} thor_process_events SEC(".maps");

// نربط هذا بـ tcp_v4_connect لرصد محاولات الاتصال الصادرة
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(thor_monitor_connect, struct sock *sk) {
    struct process_net_event *e;
    e = bpf_ringbuf_reserve(&thor_process_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->protocol = 6; // TCP

    // استخدام BPF CO-RE لقراءة الحقول بأمان بغض النظر عن إصدار النواة
    e->dst_ip = bpf_core_read(&sk->__sk_common.skc_daddr);
    e->dst_port = bpf_ntohs(bpf_core_read(&sk->__sk_common.skc_dport));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
