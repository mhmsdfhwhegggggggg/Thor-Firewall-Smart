// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PAYLOAD 512

struct ssl_event {
    __u32 pid;
    char comm[16];
    __u8 direction; // 0 = Read (Incoming), 1 = Write (Outgoing)
    __u16 len;
    char payload[MAX_PAYLOAD];
    __u64 timestamp_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} ssl_events SEC(".maps");

// تخزين وسيط لربط دخول الدالة بخروجها (لأن SSL_read تعود بحجم البيانات المقروءة)
struct ssl_args {
    __u64 buf_ptr;
    __u64 len;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64); // pid_tgid
    __type(value, struct ssl_args);
} active_ssl_args SEC(".maps");

// 1. عند دخول SSL_read: نحفظ مؤشر المخزن (Buffer)
SEC("uprobe/SSL_read")
int BPF_UPROBE(uprobe_ssl_read_enter, void *ssl, void *buf, int num) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args args = { .buf_ptr = (__u64)buf, .len = num };
    bpf_map_update_elem(&active_ssl_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// 2. عند خروج SSL_read: نقرأ البيانات المفكوكة من الذاكرة بأمان
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(uretprobe_ssl_read_exit, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args *args = bpf_map_lookup_elem(&active_ssl_args, &pid_tgid);
    if (!args || ret <= 0) {
        bpf_map_delete_elem(&active_ssl_args, &pid_tgid);
        return 0;
    }

    struct ssl_event *e = bpf_ringbuf_reserve(&ssl_events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&active_ssl_args, &pid_tgid);
        return 0; // RingBuffer ممتلئ، سنتعامل مع هذا لاحقاً (Backpressure)
    }

    e->pid = pid_tgid >> 32;
    e->direction = 0; // Read
    e->len = (ret > MAX_PAYLOAD) ? MAX_PAYLOAD : ret;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // القراءة الآمنة من مساحة المستخدم (CRITICAL for Kernel Stability)
    bpf_probe_read_user(&e->payload, e->len, (void *)args->buf_ptr);

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&active_ssl_args, &pid_tgid);
    return 0;
}

// (نفس المنطق يطبق على SSL_write لكشف تسرب البيانات Data Exfiltration)

char _license[] SEC("license") = "GPL";
