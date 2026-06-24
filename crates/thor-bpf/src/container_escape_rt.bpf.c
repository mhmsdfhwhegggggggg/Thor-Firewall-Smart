// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Thor Container Escape — Real-Time kprobe Detection
// Replaces polling-based /proc scan with sub-millisecond kernel hooks
// Coverage: setns, unshare, clone(CLONE_NEWNS), pivot_root
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define CLONE_NEWNS   0x00020000
#define CLONE_NEWNET  0x40000000
#define CLONE_NEWPID  0x20000000

struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,4096);
         __type(key,__u32); __type(value,__u8); } thor_container_pids SEC(".maps");

struct escape_event { __u32 pid; __u8 comm[16]; __u32 type; __u64 flags; __u64 ts; __u8 confidence; };
struct { __uint(type,BPF_MAP_TYPE_RINGBUF); __uint(max_entries,131072); } thor_escape_events SEC(".maps");

static __always_inline void emit(__u32 pid, __u32 type, __u64 flags, __u8 conf) {
    struct escape_event *ev = bpf_ringbuf_reserve(&thor_escape_events, sizeof(*ev), 0);
    if (!ev) return;
    ev->pid=pid; bpf_get_current_comm(&ev->comm,sizeof(ev->comm));
    ev->type=type; ev->flags=flags; ev->ts=bpf_ktime_get_ns(); ev->confidence=conf;
    bpf_ringbuf_submit(ev,0);
}

SEC("kprobe/__x64_sys_setns")
int BPF_KPROBE(kp_setns) {
    __u32 pid=bpf_get_current_pid_tgid()&0xFFFFFFFF;
    __u8 *c=bpf_map_lookup_elem(&thor_container_pids,&pid);
    if(c && *c) emit(pid,0,0,98); // setns from container = critical
    return 0;
}
SEC("kprobe/__x64_sys_unshare")
int BPF_KPROBE(kp_unshare) {
    __u32 pid=bpf_get_current_pid_tgid()&0xFFFFFFFF;
    __u8 *c=bpf_map_lookup_elem(&thor_container_pids,&pid);
    if(!c||!*c) return 0;
    __u64 flags=PT_REGS_PARM1_CORE((struct pt_regs*)PT_REGS_PARM1(ctx));
    emit(pid,1,flags,(flags&(CLONE_NEWNS|CLONE_NEWNET))?88:40);
    return 0;
}
SEC("kprobe/__x64_sys_clone")
int BPF_KPROBE(kp_clone) {
    __u32 pid=bpf_get_current_pid_tgid()&0xFFFFFFFF;
    __u8 *c=bpf_map_lookup_elem(&thor_container_pids,&pid);
    if(!c||!*c) return 0;
    __u64 flags=PT_REGS_PARM1_CORE((struct pt_regs*)PT_REGS_PARM1(ctx));
    if(flags&(CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWPID)) emit(pid,2,flags,92);
    return 0;
}
SEC("kprobe/__x64_sys_pivot_root")
int BPF_KPROBE(kp_pivot) {
    __u32 pid=bpf_get_current_pid_tgid()&0xFFFFFFFF;
    __u8 *c=bpf_map_lookup_elem(&thor_container_pids,&pid);
    if(c&&*c) emit(pid,3,0,99); // pivot_root from container = definite escape
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
