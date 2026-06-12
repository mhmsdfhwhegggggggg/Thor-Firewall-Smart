// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Thor Network Correlator — kprobe tcp_v4_connect for connection tracking
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} thor_network_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct thor_stats);
} thor_stats SEC(".maps");

/* Temporary storage for kprobe/kretprobe handoff */
struct tcp_connect_state { __u32 dst_ip; __u16 dst_port; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, struct tcp_connect_state);
} tcp_connect_store SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int thor_kprobe_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sockaddr_in *usin = (struct sockaddr_in *)PT_REGS_PARM2(ctx);
    if (!usin) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct tcp_connect_state state = {};
    bpf_probe_read_user(&state.dst_ip, sizeof(state.dst_ip), &usin->sin_addr.s_addr);
    bpf_probe_read_user(&state.dst_port, sizeof(state.dst_port), &usin->sin_port);
    bpf_map_update_elem(&tcp_connect_store, &pid_tgid, &state, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int thor_kretprobe_connect(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret != 0) return 0; /* Only track successful connects */

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct tcp_connect_state *state = bpf_map_lookup_elem(&tcp_connect_store, &pid_tgid);
    if (!state) return 0;
    bpf_map_delete_elem(&tcp_connect_store, &pid_tgid);

    struct thor_network_event *e = bpf_ringbuf_reserve(&thor_network_events, sizeof(*e), 0);
    if (!e) return 0;
    e->event_type = EVENT_NET_CONNECT;
    e->pid = pid_tgid & 0xFFFFFFFF;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->dst_ip4 = state->dst_ip;
    e->dst_port = bpf_ntohs(state->dst_port);
    e->protocol = IPPROTO_TCP;
    e->direction = 1; /* outbound */
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 zero = 0;
    struct thor_stats *stats = bpf_map_lookup_elem(&thor_stats, &zero);
    if (stats) __sync_fetch_and_add(&stats->network_connect_events, 1);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
