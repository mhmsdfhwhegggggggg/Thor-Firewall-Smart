/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Thor Firewall Smart — Shared BPF ↔ User-space Structures */
#pragma once

#define MAX_BLOCKLIST_IPS   1000000
#define MAX_BLOCKLIST_PORTS 65536
#define MAX_TRACKED_PROCS   100000
#define RINGBUF_SIZE        (64 * 1024 * 1024)  /* 64MB */

#define EVENT_XDP_DROP      1
#define EVENT_PROCESS_EXEC  2
#define EVENT_PROCESS_EXIT  3
#define EVENT_NET_CONNECT   4

#define DROP_REASON_BLOCKLIST   1
#define DROP_REASON_RATE_LIMIT  2
#define DROP_REASON_MALFORMED   3

#define ETH_P_IP 0x0800

/* Per-CPU statistics */
struct thor_stats {
    __u64 packets_processed;
    __u64 packets_dropped;
    __u64 events_generated;
    __u64 ip_blocklist_hits;
    __u64 port_blocklist_hits;
    __u64 rate_limit_hits;
    __u64 malformed_packets;
    __u64 process_exec_events;
    __u64 process_exit_events;
    __u64 network_connect_events;
    __u64 errors;
};

/* XDP drop event */
struct thor_xdp_drop_event {
    __u8  event_type;
    __u32 src_ip4;
    __u32 dst_ip4;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  reason;
    __u32 packet_len;
    __u64 timestamp_ns;
};

/* Process event */
struct thor_process_event {
    __u8  event_type;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 exit_code;
    __u64 timestamp_ns;
    char  comm[16];
    char  filename[256];
};

/* Network event */
struct thor_network_event {
    __u8  event_type;
    __u32 pid;
    __u32 uid;
    __u32 src_ip4;
    __u32 dst_ip4;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  direction;
    __u64 bytes_transferred;
    __u64 timestamp_ns;
    char  comm[16];
    char  filename[256];
};
