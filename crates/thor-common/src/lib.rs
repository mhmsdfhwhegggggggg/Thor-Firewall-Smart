//! Thor Common — Shared POD types for BPF ↔ User-space communication.
//! no_std compatible so these types can be used in both kernel-space BPF
//! programs and user-space Rust code.

#![cfg_attr(target_arch = "bpf", no_std)]

// ============================================================
// Event Type Constants
// ============================================================
pub const EVENT_XDP_DROP: u8 = 1;
pub const EVENT_PROCESS_EXEC: u8 = 2;
pub const EVENT_PROCESS_EXIT: u8 = 3;
pub const EVENT_NET_CONNECT: u8 = 4;

// ============================================================
// Map Constants
// ============================================================
pub const MAX_BLOCKLIST_IPS: u32 = 1_000_000;
pub const MAX_BLOCKLIST_PORTS: u32 = 65_536;
pub const MAX_TRACKED_PROCS: u32 = 100_000;
pub const RINGBUF_SIZE: u32 = 64 * 1024 * 1024; // 64MB
pub const STATS_MAP_KEY: u32 = 0;
pub const DEFAULT_RATE_LIMIT_PPS: u32 = 10_000;
pub const DEFAULT_RATE_WINDOW_NS: u64 = 1_000_000_000;

// Drop reason codes
pub const DROP_REASON_BLOCKLIST: u8 = 1;
pub const DROP_REASON_RATE_LIMIT: u8 = 2;
pub const DROP_REASON_MALFORMED: u8 = 3;

// ============================================================
// Shared POD Structs (repr(C) for BPF compatibility)
// ============================================================

/// Aggregated statistics tracked by XDP program per CPU
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ThorStats {
    pub packets_processed: u64,
    pub packets_dropped: u64,
    pub events_generated: u64,
    pub ip_blocklist_hits: u64,
    pub port_blocklist_hits: u64,
    pub rate_limit_hits: u64,
    pub malformed_packets: u64,
    pub process_exec_events: u64,
    pub process_exit_events: u64,
    pub network_connect_events: u64,
    pub errors: u64,
}

/// XDP drop event sent from kernel to user-space
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ThorXdpDropEvent {
    pub event_type: u8,
    pub src_ip4: u32,
    pub dst_ip4: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub reason: u8,
    pub packet_len: u32,
    pub timestamp_ns: u64,
}

/// Process execution/exit event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessExecEvent {
    pub event_type: u8,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub exit_code: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

/// Network connection event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NetworkEvent {
    pub event_type: u8,
    pub pid: u32,
    pub uid: u32,
    pub src_ip4: u32,
    pub dst_ip4: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub direction: u8,
    pub bytes_transferred: u64,
    pub timestamp_ns: u64,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

// ============================================================
// Flow Key (Hash key for DashMap)
// ============================================================
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

// ============================================================
// Threat Intelligence Types
// ============================================================
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ThreatLevel {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatLevel {
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s >= 0.9 => ThreatLevel::Critical,
            s if s >= 0.7 => ThreatLevel::High,
            s if s >= 0.4 => ThreatLevel::Medium,
            s if s >= 0.1 => ThreatLevel::Low,
            _ => ThreatLevel::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ResponseActionType {
    None,
    Alert,
    BlockIp,
    KillProcess,
    IsolateNetwork,
    QuarantineFile,
    CaptureForensics,
}
