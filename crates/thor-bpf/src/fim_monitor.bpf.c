// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// ThorFIM eBPF — Kernel-level File Integrity Monitor
// Hooks: sys_enter_openat, sys_enter_unlinkat, sys_enter_renameat2,
//        sys_enter_chmod, sys_enter_fchmodat, sys_enter_chown, sys_enter_write
// Delivers events via Ring Buffer (zero-copy) to user-space FIM engine.

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/limits.h>
#include <linux/fcntl.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

// ─── Event structure ──────────────────────────────────────────────────────────

#define FIM_PATH_LEN  256
#define FIM_COMM_LEN  16

#define FIM_OP_OPEN       0
#define FIM_OP_CREATE     1
#define FIM_OP_WRITE      2
#define FIM_OP_UNLINK     3
#define FIM_OP_RENAME     4
#define FIM_OP_CHMOD      5
#define FIM_OP_CHOWN      6

struct fim_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u8  operation;        // FIM_OP_*
    __u8  pad[3];
    __u64 inode;
    char  path[FIM_PATH_LEN];
    char  comm[FIM_COMM_LEN];
    __u32 flags;            // open flags (O_CREAT etc.)
    __u32 mode;             // chmod mode
};

// ─── BPF Maps ──────────────────────────────────────────────────────────────────

/* Ring buffer for delivering events to user-space (zero-copy) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); // 4 MB
} thor_fim_events SEC(".maps");

/* Path prefix filter — only monitor specified path prefixes */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key,   char[64]);
    __type(value, __u8);
} thor_fim_watch_prefixes SEC(".maps");

/* Per-CPU scratch for path building */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct fim_event);
} thor_fim_scratch SEC(".maps");

/* UID allowlist — never generate events for UIDs in this set */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key,   __u32);
    __type(value, __u8);
} thor_fim_uid_skip SEC(".maps");

// ─── Helpers ──────────────────────────────────────────────────────────────────

static __always_inline int is_interesting_path(const char *path) {
    // Fast prefix check for monitored directories
    // Check /etc/, /bin/, /sbin/, /usr/bin/, /usr/sbin/, /root/, /lib/, /boot/
    char buf[8];
    if (bpf_probe_read_user_str(buf, sizeof(buf), path) < 0)
        return 0;

    if (buf[0] != '/')
        return 0;

    // /etc, /bin, /sbin, /lib, /usr, /root, /boot
    if (buf[1] == 'e' || buf[1] == 'b' || buf[1] == 's' ||
        buf[1] == 'l' || buf[1] == 'u' || buf[1] == 'r' || buf[1] == 'b')
        return 1;

    return 0;
}

static __always_inline void emit_fim_event(
    struct pt_regs *ctx,
    const char     *path,
    __u8            op,
    __u32           flags,
    __u32           mode
) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid & 0xFFFFFFFF;
    __u32 gid = uid_gid >> 32;

    // Skip kernel threads (uid 0 is root, but we may want to skip kernel uid)
    // Check if this UID is in the skip list
    __u8 *skip = bpf_map_lookup_elem(&thor_fim_uid_skip, &uid);
    if (skip && *skip) return;

    // Quick path interest check
    if (!is_interesting_path(path)) return;

    struct fim_event *evt = bpf_ringbuf_reserve(&thor_fim_events, sizeof(*evt), 0);
    if (!evt) return;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid       = pid;
    evt->uid       = uid;
    evt->gid       = gid;
    evt->operation = op;
    evt->flags     = flags;
    evt->mode      = mode;
    evt->inode     = 0;

    bpf_probe_read_user_str(evt->path, sizeof(evt->path), path);
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
}

// ─── Tracepoints ──────────────────────────────────────────────────────────────

// openat(2) — catch file opens with O_CREAT|O_WRONLY for create/write detection
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[1];
    __u32 flags = (__u32)ctx->args[2];
    __u32 mode  = (__u32)ctx->args[3];

    __u8 op;
    if (flags & O_CREAT) {
        op = FIM_OP_CREATE;
    } else if (flags & O_WRONLY || flags & O_RDWR) {
        op = FIM_OP_WRITE;
    } else {
        op = FIM_OP_OPEN;
    }

    emit_fim_event(NULL, filename, op, flags, mode);
    return 0;
}

// unlinkat(2) — file deletion
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    const char *pathname = (const char *)ctx->args[1];
    emit_fim_event(NULL, pathname, FIM_OP_UNLINK, 0, 0);
    return 0;
}

// renameat2(2) — file rename/move
SEC("tracepoint/syscalls/sys_enter_renameat2")
int tracepoint__syscalls__sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx) {
    const char *oldpath = (const char *)ctx->args[1];
    emit_fim_event(NULL, oldpath, FIM_OP_RENAME, 0, 0);
    return 0;
}

// fchmodat(2) — permission change
SEC("tracepoint/syscalls/sys_enter_fchmodat")
int tracepoint__syscalls__sys_enter_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    const char *pathname = (const char *)ctx->args[1];
    __u32 mode = (__u32)ctx->args[2];
    emit_fim_event(NULL, pathname, FIM_OP_CHMOD, 0, mode);
    return 0;
}

// fchownat(2) — ownership change
SEC("tracepoint/syscalls/sys_enter_fchownat")
int tracepoint__syscalls__sys_enter_fchownat(struct trace_event_raw_sys_enter *ctx) {
    const char *pathname = (const char *)ctx->args[1];
    emit_fim_event(NULL, pathname, FIM_OP_CHOWN, 0, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
