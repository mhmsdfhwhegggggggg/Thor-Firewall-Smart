//! Event types and pipeline orchestration

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thor_common::ThreatLevel;
use thor_bpf::process_monitor::ThorProcessEvent;
use thor_bpf::network_correlator::ThorNetworkEvent;

pub mod pipeline;
pub mod enrichment;
pub mod dedup;

/// Unified raw event from any eBPF source
#[derive(Debug, Clone)]
pub enum RawEvent {
    Process(ThorProcessEvent),
    Network(ThorNetworkEvent),
    XdpDrop { src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, reason: u8, timestamp_ns: u64 },
}

impl RawEvent {
    pub fn timestamp_ns(&self) -> u64 {
        match self {
            Self::Process(e) => e.timestamp_ns(),
            Self::Network(e) => e.timestamp_ns,
            Self::XdpDrop { timestamp_ns, .. } => *timestamp_ns,
        }
    }
    pub fn source(&self) -> &'static str {
        match self { Self::Process(_) => "process", Self::Network(_) => "network", Self::XdpDrop { .. } => "xdp" }
    }
}

/// Enriched alert (output of detection pipeline)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub rule_name: String,
    pub rule_type: RuleType,
    pub threat_level: ThreatLevel,
    pub description: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub ml_score: Option<f32>,
    pub soar_actions_taken: Vec<String>,
    pub raw_event_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleType {
    Sigma,
    Yara,
    Ioc,
    Ml,
    Xdp,
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatLevel::Critical => write!(f, "CRITICAL"),
            ThreatLevel::High => write!(f, "HIGH"),
            ThreatLevel::Medium => write!(f, "MEDIUM"),
            ThreatLevel::Low => write!(f, "LOW"),
            ThreatLevel::Unknown => write!(f, "UNKNOWN"),
        }
    }
}
