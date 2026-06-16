// SPDX-License-Identifier: GPL-2.0
// Placeholder for vmlinux.h or necessary linux headers
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_PAYLOAD_LEN 512 // nأخذ عينة من البداية لكشف أنماط مثل SQLi أو XSS

struct l7_event {
    __u32 pid;
    __u8 comm[TASK_COMM_LEN];
    __u32 fd;          // File Descriptor
    __u8 direction;    // 0 = Read (Incoming), 1 = Write (Outgoing)
    __u16 payload_len;
    __u8 payload[MAX_PAYLOAD_LEN];
    __u64 timestamp_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} l7_events SEC(".maps");

// Intermediate storage to link function entry and exit
struct ssl_args {
    __u64 buf;
    __u64 len;
};

/* Intermediate storage for in-flight SSL_{read,write} args keyed by pid_tgid.
 * LRU_HASH: SSL entries from killed/hung processes are auto-evicted,
 * preventing unbounded growth when SSL probes miss their uretprobe exit. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64); // pid_tgid
    __type(value, struct ssl_args);
} active_ssl_args SEC(".maps");

// 1. Upon entering SSL_read: we save the buffer pointer and its size
SEC("uprobe/SSL_read")
int BPF_UPROBE(uprobe_ssl_read_enter, void *ssl, void *buf, int num) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args args = {};
    args.buf = (__u64)buf;
    args.len = num;
    bpf_map_update_elem(&active_ssl_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// 2. Upon exiting SSL_read: we read the decrypted data from the buffer
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(uretprobe_ssl_read_exit, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args *args = bpf_map_lookup_elem(&active_ssl_args, &pid_tgid);
    if (!args) return 0;

    if (ret <= 0) {
        bpf_map_delete_elem(&active_ssl_args, &pid_tgid);
        return 0; // Error or connection closed
    }

    struct l7_event *e = bpf_ringbuf_reserve(&l7_events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&active_ssl_args, &pid_tgid);
        return 0;
    }

    e->pid = pid_tgid >> 32;
    e->direction = 0; // Read
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Safe read from user space (CRITICAL for stability)
    __u64 len = (args->len > MAX_PAYLOAD_LEN) ? MAX_PAYLOAD_LEN : args->len;
    bpf_probe_read_user(&e->payload, len, (void *)args->buf);
    e->payload_len = len;

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&active_ssl_args, &pid_tgid);
    return 0;
}

// 3. Same logic for SSL_write (to monitor Data Exfiltration)
SEC("uprobe/SSL_write")
int BPF_UPROBE(uprobe_ssl_write_enter, void *ssl, const void *buf, int num) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args args = {};
    args.buf = (__u64)buf;
    args.len = num;
    bpf_map_update_elem(&active_ssl_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(uretprobe_ssl_write_exit, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args *args = bpf_map_lookup_elem(&active_ssl_args, &pid_tgid);
    if (!args) return 0;

    if (ret <= 0) {
        bpf_map_delete_elem(&active_ssl_args, &pid_tgid);
        return 0;
    }

    struct l7_event *e = bpf_ringbuf_reserve(&l7_events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&active_ssl_args, &pid_tgid);
        return 0;
    }

    e->pid = pid_tgid >> 32;
    e->direction = 1; // Write
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u64 len = (args->len > MAX_PAYLOAD_LEN) ? MAX_PAYLOAD_LEN : args->len;
    bpf_probe_read_user(&e->payload, len, (void *)args->buf);
    e->payload_len = len;

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&active_ssl_args, &pid_tgid);
    return 0;
}

char _license[] SEC("license") = "GPL";
