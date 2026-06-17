// SPDX-License-Identifier: GPL-2.0
//
// syscall_profiler.bpf.c — eBPF syscall profiling probe for Thor Axis 4.
//
// This probe attaches to raw_tracepoint/sys_enter and raw_tracepoint/sys_exit
// to intercept ALL syscalls on Linux x86-64.  For each syscall it:
//
//   1. Increments per-PID, per-syscall counters in an LRU_PERCPU_HASH map.
//   2. Tracks child spawns (execve, fork, vfork, clone).
//   3. Tracks memory allocation events (mmap, brk, mprotect).
//   4. Records dangerous syscall events (ptrace, memfd_create, process_vm_writev).
//   5. Sends a ring-buffer event to userspace for real-time analysis.
//
// # Maps
//
// ┌──────────────────────────┬──────────────────────────────────────────────┐
// │ Map name                 │ Purpose                                      │
// ├──────────────────────────┼──────────────────────────────────────────────┤
// │ syscall_count_map        │ LRU_PERCPU_HASH: (pid,syscall_nr) → count   │
// │ pid_meta_map             │ LRU_HASH: pid → PidMeta struct               │
// │ syscall_events           │ RINGBUF: stream of SyscallEvent to userspace │
// └──────────────────────────┴──────────────────────────────────────────────┘
//
// # Safety
// * The ring buffer uses BPF_RB_NO_WAKEUP for performance; userspace polls.
// * Maximum event rate is capped by the ring buffer size (64 MB).
// * LRU maps evict the oldest entries automatically under memory pressure.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ── Constants ──────────────────────────────────────────────────────────────────

// Linux x86-64 syscall numbers (key ones we care about)
#define SYS_READ                0
#define SYS_WRITE               1
#define SYS_OPEN                2
#define SYS_CLOSE               3
#define SYS_MMAP                9
#define SYS_MPROTECT            10
#define SYS_MUNMAP              11
#define SYS_BRK                 12
#define SYS_IOCTL               16
#define SYS_SOCKET              41
#define SYS_CONNECT             42
#define SYS_SENDMSG             46
#define SYS_RECVMSG             47
#define SYS_CLONE               56
#define SYS_FORK                57
#define SYS_VFORK               58
#define SYS_EXECVE              59
#define SYS_PTRACE              101
#define SYS_INIT_MODULE         175
#define SYS_CREATE_MODULE       174
#define SYS_PROCESS_VM_READV    310
#define SYS_PROCESS_VM_WRITEV   311
#define SYS_MEMFD_CREATE        319
#define SYS_EXECVEAT            322

#define TASK_COMM_LEN           16
#define MAX_PIDS                65536
#define MAX_SYSCALL_NR          512

// ── Map key / value types ──────────────────────────────────────────────────────

struct syscall_key {
    __u32 pid;
    __u32 syscall_nr;
};

struct pid_meta {
    __u32 pid;
    __u32 tgid;
    __u64 child_spawns;
    __u64 memory_alloc_events;
    __u64 dangerous_syscall_count;
    __u64 total_syscalls;
    char  comm[TASK_COMM_LEN];
};

// Userspace ring-buffer event (must match Rust struct SyscallEvent layout).
struct syscall_event {
    __u32 pid;
    __u32 tgid;
    __u32 syscall_nr;
    __s64 ret_val;
    __u64 byte_count;    // populated on sys_exit for read/write/send/recv
    __u64 ts_ns;
    char  comm[TASK_COMM_LEN];
    __u8  is_kernel;     // 1 if kernel-space context
    __u8  _pad[7];
};

// ── Maps ───────────────────────────────────────────────────────────────────────

// Per-(PID, syscall_nr) call count — LRU_PERCPU_HASH for per-CPU efficiency.
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_PIDS * 32);
    __type(key,         struct syscall_key);
    __type(value,       __u64);
} syscall_count_map SEC(".maps");

// Per-PID aggregate metadata.
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key,         __u32);         // pid
    __type(value,       struct pid_meta);
} pid_meta_map SEC(".maps");

// Ring buffer for streaming events to userspace.
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024); // 64 MB
} syscall_events SEC(".maps");

// Scratch map: store syscall_nr at sys_enter to retrieve at sys_exit.
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key,         __u32);         // pid
    __type(value,       __u32);         // syscall_nr
} inflight_map SEC(".maps");

// ── Helper: classify syscall ──────────────────────────────────────────────────

static __always_inline int is_exec_syscall(__u32 nr) {
    return nr == SYS_EXECVE || nr == SYS_EXECVEAT ||
           nr == SYS_FORK   || nr == SYS_VFORK    || nr == SYS_CLONE;
}

static __always_inline int is_memory_syscall(__u32 nr) {
    return nr == SYS_MMAP   || nr == SYS_MPROTECT  ||
           nr == SYS_BRK    || nr == SYS_MUNMAP;
}

static __always_inline int is_dangerous_syscall(__u32 nr) {
    return nr == SYS_PTRACE           ||
           nr == SYS_INIT_MODULE      ||
           nr == SYS_CREATE_MODULE    ||
           nr == SYS_PROCESS_VM_READV ||
           nr == SYS_PROCESS_VM_WRITEV||
           nr == SYS_MEMFD_CREATE;
}

static __always_inline int is_io_syscall(__u32 nr) {
    return nr == SYS_READ    || nr == SYS_WRITE   ||
           nr == SYS_SENDMSG || nr == SYS_RECVMSG;
}

// ── sys_enter probe ────────────────────────────────────────────────────────────

SEC("raw_tracepoint/sys_enter")
int thor_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    // ctx->args[0] = pt_regs*, ctx->args[1] = syscall_nr
    __u32 syscall_nr = (__u32)ctx->args[1];
    if (syscall_nr >= MAX_SYSCALL_NR)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    __u32 tgid     = (__u32)(pid_tgid & 0xFFFFFFFF);

    // Skip kernel threads (pid == 0)
    if (pid == 0)
        return 0;

    // ── 1. Increment per-(pid, syscall_nr) counter ───────────────────────────
    struct syscall_key key = { .pid = pid, .syscall_nr = syscall_nr };
    __u64 *cnt = bpf_map_lookup_elem(&syscall_count_map, &key);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&syscall_count_map, &key, &one, BPF_NOEXIST);
    }

    // ── 2. Update aggregate pid metadata ─────────────────────────────────────
    struct pid_meta *meta = bpf_map_lookup_elem(&pid_meta_map, &pid);
    if (!meta) {
        struct pid_meta new_meta = {};
        new_meta.pid  = pid;
        new_meta.tgid = tgid;
        bpf_get_current_comm(&new_meta.comm, sizeof(new_meta.comm));
        bpf_map_update_elem(&pid_meta_map, &pid, &new_meta, BPF_NOEXIST);
        meta = bpf_map_lookup_elem(&pid_meta_map, &pid);
        if (!meta)
            return 0;
    }

    __sync_fetch_and_add(&meta->total_syscalls, 1);

    if (is_exec_syscall(syscall_nr))
        __sync_fetch_and_add(&meta->child_spawns, 1);
    if (is_memory_syscall(syscall_nr))
        __sync_fetch_and_add(&meta->memory_alloc_events, 1);
    if (is_dangerous_syscall(syscall_nr))
        __sync_fetch_and_add(&meta->dangerous_syscall_count, 1);

    // ── 3. Record inflight syscall nr for retrieval at sys_exit ──────────────
    bpf_map_update_elem(&inflight_map, &pid, &syscall_nr, BPF_ANY);

    // ── 4. Emit ring-buffer event (only for interesting syscalls to limit rate)
    if (!is_io_syscall(syscall_nr) || is_dangerous_syscall(syscall_nr) ||
        is_exec_syscall(syscall_nr) || is_memory_syscall(syscall_nr))
    {
        struct syscall_event *ev = bpf_ringbuf_reserve(
            &syscall_events, sizeof(struct syscall_event), 0
        );
        if (ev) {
            ev->pid        = pid;
            ev->tgid       = tgid;
            ev->syscall_nr = syscall_nr;
            ev->ret_val    = 0;          // filled at sys_exit
            ev->byte_count = 0;
            ev->ts_ns      = bpf_ktime_get_ns();
            ev->is_kernel  = 0;
            bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
            bpf_ringbuf_submit(ev, BPF_RB_NO_WAKEUP);
        }
    }

    return 0;
}

// ── sys_exit probe — captures return values for I/O byte counts ───────────────

SEC("raw_tracepoint/sys_exit")
int thor_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    // ctx->args[0] = pt_regs*, ctx->args[1] = return value
    __s64 ret = (__s64)ctx->args[1];

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);

    if (pid == 0)
        return 0;

    __u32 *syscall_nr_ptr = bpf_map_lookup_elem(&inflight_map, &pid);
    if (!syscall_nr_ptr)
        return 0;
    __u32 syscall_nr = *syscall_nr_ptr;

    // Only emit byte-count events for I/O syscalls with positive return values
    if (!is_io_syscall(syscall_nr) || ret <= 0)
        return 0;

    struct syscall_event *ev = bpf_ringbuf_reserve(
        &syscall_events, sizeof(struct syscall_event), 0
    );
    if (!ev)
        return 0;

    ev->pid        = pid;
    ev->tgid       = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->syscall_nr = syscall_nr;
    ev->ret_val    = ret;
    ev->byte_count = (ret > 0) ? (__u64)ret : 0;
    ev->ts_ns      = bpf_ktime_get_ns();
    ev->is_kernel  = 0;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);  // wakeup on I/O events for lower latency

    return 0;
}

// ── mmap permission change probe (for ROP chain detection) ────────────────────

SEC("tracepoint/syscalls/sys_enter_mprotect")
int thor_mprotect_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    if (pid == 0)
        return 0;

    // arg0 = addr, arg1 = len, arg2 = prot
    unsigned long prot = ctx->args[2];

    // PROT_EXEC = 0x4 — flag changes to executable memory
    if (!(prot & 0x4))
        return 0;

    struct syscall_event *ev = bpf_ringbuf_reserve(
        &syscall_events, sizeof(struct syscall_event), 0
    );
    if (!ev)
        return 0;

    ev->pid        = pid;
    ev->tgid       = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->syscall_nr = SYS_MPROTECT;
    ev->ret_val    = 0;
    ev->byte_count = (__u64)ctx->args[1]; // len
    ev->ts_ns      = bpf_ktime_get_ns();
    ev->is_kernel  = 0;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);

    return 0;
}

// ── ptrace target-PID probe ───────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_ptrace")
int thor_ptrace_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    if (pid == 0)
        return 0;

    // arg0 = request (PTRACE_POKETEXT=4, PTRACE_ATTACH=16, etc.)
    // arg1 = target PID
    long  request   = ctx->args[0];
    __u32 target_pid = (__u32)ctx->args[1];

    // Only emit for writes (POKETEXT, POKEDATA) and attaches
    if (request != 4 && request != 5 && request != 16 && request != 17)
        return 0;

    struct syscall_event *ev = bpf_ringbuf_reserve(
        &syscall_events, sizeof(struct syscall_event), 0
    );
    if (!ev)
        return 0;

    ev->pid        = pid;
    ev->tgid       = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->syscall_nr = SYS_PTRACE;
    ev->ret_val    = 0;
    ev->byte_count = (__u64)target_pid; // encode target PID in byte_count field
    ev->ts_ns      = bpf_ktime_get_ns();
    ev->is_kernel  = 0;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);

    return 0;
}

// ── memfd_create probe ────────────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int thor_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    if (pid == 0)
        return 0;

    struct syscall_event *ev = bpf_ringbuf_reserve(
        &syscall_events, sizeof(struct syscall_event), 0
    );
    if (!ev)
        return 0;

    ev->pid        = pid;
    ev->tgid       = (__u32)(pid_tgid & 0xFFFFFFFF);
    ev->syscall_nr = SYS_MEMFD_CREATE;
    ev->ret_val    = 0;
    ev->byte_count = ctx->args[1]; // flags
    ev->ts_ns      = bpf_ktime_get_ns();
    ev->is_kernel  = 0;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
