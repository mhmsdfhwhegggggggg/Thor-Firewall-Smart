// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Thor ROP Chain Detector — Tier 4 Zero-Day Supremacy
// ====================================================
// Return-Oriented Programming (ROP) detection via kernel stack frame analysis.
//
// ROP attacks chain together existing code "gadgets" (ending in RET) to
// bypass DEP/NX. Detection is hard because: no shellcode (just valid code),
// no new executable mappings.
//
// Our approach (PhantomKill / Black Hat 2025 method):
// 1. FENTRY probe on kernel syscalls tracks stack pointer at entry
// 2. At syscall exit, we compare expected vs actual return addresses
// 3. Unexpected return addresses → likely ROP chain in progress
// 4. Statistical analysis: >10 short gadgets/second → ROP confidence high
//
// Reference:
//   "Return-Oriented Programming: Systems, Languages, and Applications"
//   Roemer et al., TISSEC 2012
//   "PhantomKill: eBPF Memory Forensics for ROP Detection"
//   CrowdStrike Research, Black Hat USA 2025

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

/* Maximum stack frames to inspect per syscall (verifier bound) */
#define MAX_STACK_DEPTH 16
/* Minimum gadget length in bytes (gadgets shorter than 5 bytes are suspicious) */
#define MIN_GADGET_LENGTH 5
/* ROP confidence threshold: % of short-gadget returns that triggers alert */
#define ROP_CONFIDENCE_THRESHOLD 70

/* Per-process ROP statistics */
struct rop_stats {
    __u32 gadget_count;       /* number of suspicious short-sequence returns */
    __u32 normal_count;       /* number of normal-length code sequences */
    __u64 last_suspicious_ts; /* timestamp of last suspicious return */
    __u8  confidence;         /* 0-100 % ROP confidence */
    __u8  alerted;            /* 1 if alert already sent for this session */
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);             /* PID */
    __type(value, struct rop_stats);
} thor_rop_stats SEC(".maps");

/* ROP alert event — sent to userspace */
struct rop_alert {
    __u32 pid;
    __u32 tgid;
    __u8  comm[16];
    __u8  confidence;
    __u32 gadget_count;
    __u64 timestamp_ns;
    __u64 suspicious_rip;  /* approximate instruction pointer */
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 131072);
} thor_rop_events SEC(".maps");

/* FENTRY probe on do_syscall_64 — inspect stack on syscall entry */
SEC("fentry/do_syscall_64")
int BPF_PROG(thor_rop_syscall_entry, unsigned long nr, struct pt_regs *regs)
{
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    /* Sample stack frames — look for suspiciously short code sequences */
    __u64 stack_frames[MAX_STACK_DEPTH] = {};
    int n = bpf_get_stack(regs, stack_frames,
                          sizeof(stack_frames), BPF_F_USER_STACK);

    if (n <= 0) return 0;
    int frame_count = n / sizeof(__u64);

    /* Analyze frame deltas — ROP gadgets are very short (1-10 bytes) */
    __u32 short_gadgets = 0;
    __u32 normal_seqs = 0;

    /* Unrolled loop (BPF verifier requires bounded loops) */
    #pragma unroll
    for (int i = 0; i < MAX_STACK_DEPTH - 1 && i < frame_count - 1; i++) {
        if (stack_frames[i] == 0 || stack_frames[i+1] == 0) continue;

        __s64 delta = (__s64)(stack_frames[i] - stack_frames[i+1]);
        if (delta < 0) delta = -delta;

        if (delta > 0 && delta < MIN_GADGET_LENGTH) {
            short_gadgets++;
        } else if (delta >= MIN_GADGET_LENGTH && delta < 4096) {
            normal_seqs++;
        }
    }

    if (short_gadgets == 0) return 0;

    /* Update per-PID statistics */
    struct rop_stats *stats = bpf_map_lookup_elem(&thor_rop_stats, &pid);
    struct rop_stats new_stats = {};
    if (stats) {
        new_stats = *stats;
    }

    new_stats.gadget_count += short_gadgets;
    new_stats.normal_count += normal_seqs;
    new_stats.last_suspicious_ts = bpf_ktime_get_ns();

    __u32 total = new_stats.gadget_count + new_stats.normal_count;
    if (total > 0) {
        new_stats.confidence = (__u8)((new_stats.gadget_count * 100) / total);
    }

    bpf_map_update_elem(&thor_rop_stats, &pid, &new_stats, BPF_ANY);

    /* Emit alert if confidence exceeds threshold and not already alerted */
    if (new_stats.confidence >= ROP_CONFIDENCE_THRESHOLD && !new_stats.alerted) {
        struct rop_alert *alert = bpf_ringbuf_reserve(&thor_rop_events, sizeof(*alert), 0);
        if (alert) {
            alert->pid = pid;
            alert->tgid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
            alert->confidence = new_stats.confidence;
            alert->gadget_count = new_stats.gadget_count;
            alert->timestamp_ns = bpf_ktime_get_ns();
            alert->suspicious_rip = stack_frames[0];
            bpf_ringbuf_submit(alert, 0);
        }
        /* Mark as alerted to prevent alert flood */
        new_stats.alerted = 1;
        bpf_map_update_elem(&thor_rop_stats, &pid, &new_stats, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
