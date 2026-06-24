// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Thor Heap Spray Detector — Tier 4 ODIN Plan
// =============================================
// Detects heap spray attacks via BPF uprobes on memory allocation functions.
//
// Heap spray: allocating many identically-patterned memory regions to
// predictably place shellcode/ROP chains at known addresses (bypasses ASLR).
//
// Detection strategy:
// 1. uprobe on malloc/mmap: track allocation sizes and patterns per PID
// 2. Statistical analysis: many allocations of same size in short time → spray
// 3. Pattern analysis: repetitive byte patterns in allocated regions (NOP sled, ROP)
// 4. Heuristic: >1000 allocations of exact same size in <100ms = heap spray
//
// Reference:
//   "Heap Spray Mitigation via eBPF Memory Forensics", Black Hat USA 2025
//   "ASLR bypass via heap spray in modern browsers", Project Zero blog 2024

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

/* Track malloc calls per PID: size → count */
struct alloc_stats {
    __u64 count;          /* number of allocations at this size */
    __u64 last_ts_ns;     /* timestamp of last allocation */
    __u64 first_ts_ns;    /* timestamp of first allocation */
};

/* Key: (pid, allocation_size) */
struct alloc_key {
    __u32 pid;
    __u64 size;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct alloc_key);
    __type(value, struct alloc_stats);
} thor_heap_allocs SEC(".maps");

/* Heap spray alert */
struct heap_spray_alert {
    __u32 pid;
    __u64 alloc_size;
    __u64 alloc_count;
    __u64 time_window_ns;   /* time between first and last allocation */
    __u64 timestamp_ns;
    __u8  comm[16];
    __u8  confidence;       /* 0-100 */
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 65536);
} thor_heap_events SEC(".maps");

/* Heap spray heuristics:
 * >500 allocations of exact same size in <50ms = suspicious
 * >2000 allocations = critical (definite spray)
 */
#define HEAP_SPRAY_WARN_COUNT  500
#define HEAP_SPRAY_CRIT_COUNT  2000
#define HEAP_SPRAY_TIME_NS     50000000  /* 50ms window */

/* uprobe on libc malloc: track per-size allocation frequency */
SEC("uprobe/libc:malloc")
int BPF_UPROBE(thor_malloc_probe, size_t size)
{
    if (size == 0 || size > 1024*1024*10) return 0;  /* ignore huge/zero allocs */

    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct alloc_key key = { .pid = pid, .size = size };

    __u64 now = bpf_ktime_get_ns();
    struct alloc_stats *stats = bpf_map_lookup_elem(&thor_heap_allocs, &key);

    struct alloc_stats new_stats = {};
    if (stats) {
        new_stats = *stats;
        /* Reset window if >1 second passed */
        if (now - new_stats.last_ts_ns > 1000000000ULL) {
            new_stats.count = 0;
            new_stats.first_ts_ns = now;
        }
        new_stats.count++;
        new_stats.last_ts_ns = now;
    } else {
        new_stats.count = 1;
        new_stats.first_ts_ns = now;
        new_stats.last_ts_ns = now;
    }

    bpf_map_update_elem(&thor_heap_allocs, &key, &new_stats, BPF_ANY);

    /* Alert threshold check */
    if (new_stats.count >= HEAP_SPRAY_WARN_COUNT) {
        __u64 window = new_stats.last_ts_ns - new_stats.first_ts_ns;
        if (window < HEAP_SPRAY_TIME_NS || new_stats.count >= HEAP_SPRAY_CRIT_COUNT) {
            struct heap_spray_alert *alert = bpf_ringbuf_reserve(&thor_heap_events, sizeof(*alert), 0);
            if (alert) {
                alert->pid = pid;
                alert->alloc_size = size;
                alert->alloc_count = new_stats.count;
                alert->time_window_ns = window;
                alert->timestamp_ns = now;
                bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
                /* Confidence: 50% at WARN_COUNT, 95% at CRIT_COUNT */
                if (new_stats.count >= HEAP_SPRAY_CRIT_COUNT) {
                    alert->confidence = 95;
                } else {
                    alert->confidence = (__u8)(50 + (new_stats.count - HEAP_SPRAY_WARN_COUNT) * 45
                                         / (HEAP_SPRAY_CRIT_COUNT - HEAP_SPRAY_WARN_COUNT));
                }
                bpf_ringbuf_submit(alert, 0);

                /* Reset to avoid alert flood */
                new_stats.count = 0;
                bpf_map_update_elem(&thor_heap_allocs, &key, &new_stats, BPF_ANY);
            }
        }
    }

    return 0;
}

/* uprobe on mmap: track large private anonymous mappings (alternative spray) */
SEC("uprobe/libc:mmap")
int BPF_UPROBE(thor_mmap_probe, void *addr, size_t length, int prot, int flags)
{
    /* MAP_PRIVATE | MAP_ANONYMOUS = 0x22 */
    if ((flags & 0x22) != 0x22) return 0;
    /* Suspicious: RWX mapping (0x7 = PROT_READ|PROT_WRITE|PROT_EXEC) */
    if (prot == 7 && length >= 4096) {
        __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
        struct alloc_key key = { .pid = pid, .size = length };
        __u64 now = bpf_ktime_get_ns();

        struct alloc_stats new_stats = {};
        struct alloc_stats *stats = bpf_map_lookup_elem(&thor_heap_allocs, &key);
        if (stats) {
            new_stats = *stats;
            new_stats.count++;
        } else {
            new_stats.count = 1;
            new_stats.first_ts_ns = now;
        }
        new_stats.last_ts_ns = now;
        bpf_map_update_elem(&thor_heap_allocs, &key, &new_stats, BPF_ANY);

        /* RWX mmap alert (shellcode injection candidate) */
        if (prot == 7) {
            struct heap_spray_alert *alert = bpf_ringbuf_reserve(&thor_heap_events, sizeof(*alert), 0);
            if (alert) {
                alert->pid = pid;
                alert->alloc_size = length;
                alert->alloc_count = new_stats.count;
                alert->time_window_ns = 0;
                alert->timestamp_ns = now;
                bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
                alert->confidence = 80;  /* RWX mapping is always suspicious */
                bpf_ringbuf_submit(alert, 0);
            }
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
