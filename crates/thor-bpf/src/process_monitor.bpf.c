// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Thor Process Monitor — sched tracepoints for exec/exit tracking
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} thor_process_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct thor_stats);
} thor_stats SEC(".maps");

/* Tracked process whitelist (pid → 1)
 * Phase 5 Hardening: PERCPU_LRU_HASH eliminates cross-core locking at high exec rates.
 * Each CPU maintains its own LRU entry set → zero contention on write-heavy workloads.
 * Trade-off: a process tracked on CPU-0 may not be visible on CPU-1 lookup,
 * but for exec-rate monitoring the per-CPU view is sufficient and far faster.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_PROCS);
    __type(key, __u32);
    __type(value, __u8);
} thor_tracked_procs SEC(".maps");

struct sched_process_exec_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int data_loc_filename;
    pid_t pid;
    pid_t old_pid;
};

struct sched_process_exit_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int data_loc_comm;
    pid_t pid;
    int prio;
};

SEC("tracepoint/sched/sched_process_exec")
int thor_trace_exec(struct sched_process_exec_args *ctx) {
    struct thor_process_event *e = bpf_ringbuf_reserve(&thor_process_events, sizeof(*e), 0);
    if (!e) return 0;
    e->event_type = EVENT_PROCESS_EXEC;
    e->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->tgid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid = bpf_get_current_uid_gid() >> 32;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    BPF_CORE_READ_INTO(&parent, task, real_parent);
    if (parent) BPF_CORE_READ_INTO(&e->ppid, parent, tgid);

    /* Read filename from tracepoint offset */
    int offset = ctx->data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + offset);

    /* Track process */
    __u8 val = 1;
    bpf_map_update_elem(&thor_tracked_procs, &e->pid, &val, BPF_ANY);

    __u32 zero = 0;
    struct thor_stats *stats = bpf_map_lookup_elem(&thor_stats, &zero);
    /* Phase 5: PERCPU_ARRAY stats — no atomic ops needed, each CPU writes its own slot */
    if (stats) stats->process_exec_events++;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int thor_trace_exit(struct sched_process_exit_args *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_map_delete_elem(&thor_tracked_procs, &pid);

    struct thor_process_event *e = bpf_ringbuf_reserve(&thor_process_events, sizeof(*e), 0);
    if (!e) return 0;
    e->event_type = EVENT_PROCESS_EXIT;
    e->pid = pid;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 zero = 0;
    struct thor_stats *stats = bpf_map_lookup_elem(&thor_stats, &zero);
    /* Phase 5: PERCPU_ARRAY stats — per-CPU write, aggregated in userspace */
    if (stats) stats->process_exit_events++;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
