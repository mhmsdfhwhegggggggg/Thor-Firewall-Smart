//! Flow tracking record — stored in DashMap keyed by 5-tuple

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub key: FlowKey,
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub threat_score: f32,
}

impl FlowRecord {
    pub fn duration_secs(&self) -> f64 {
        (self.last_seen - self.first_seen).num_milliseconds() as f64 / 1000.0
    }

    pub fn packets_per_sec(&self) -> f64 {
        let dur = self.duration_secs();
        if dur > 0.0 { self.packet_count as f64 / dur } else { 0.0 }
    }
}
