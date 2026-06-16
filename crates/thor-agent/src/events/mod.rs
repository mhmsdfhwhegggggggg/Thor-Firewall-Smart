//! Event types and pipeline orchestration

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thor_common::ThreatLevel;
use thor_bpf::process_monitor::ThorProcessEvent;
use thor_bpf::network_correlator::ThorNetworkEvent;

pub mod dedup;
pub mod enrichment;
pub mod pipeline;
pub mod siem_exporter;

/// Unified raw event from any eBPF source
#[derive(Debug, Clone)]
pub enum RawEvent {
    Process(ThorProcessEvent),
    Network(ThorNetworkEvent),
    XdpDrop { src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, reason: u8, timestamp_ns: u64 },
    Dns(DnsEvent),
    Tls(TlsEvent),
    Fim(FimRawEvent),
}

impl RawEvent {
    pub fn timestamp_ns(&self) -> u64 {
        match self {
            Self::Process(e)   => e.timestamp_ns(),
            Self::Network(e)   => e.timestamp_ns,
            Self::XdpDrop { timestamp_ns, .. } => *timestamp_ns,
            Self::Dns(e)       => e.timestamp_ns,
            Self::Tls(e)       => e.timestamp_ns,
            Self::Fim(e)       => e.timestamp_ns,
        }
    }
    pub fn source(&self) -> &'static str {
        match self {
            Self::Process(_) => "process",
            Self::Network(_) => "network",
            Self::XdpDrop { .. } => "xdp",
            Self::Dns(_) => "dns",
            Self::Tls(_) => "tls",
            Self::Fim(_) => "fim",
        }
    }
}

// ─── Supplementary event types ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub query: String,
    pub record_type: String,
    pub response_ips: Vec<String>,
    pub ttl: u32,
}

#[derive(Debug, Clone)]
pub struct TlsEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub sni: Option<String>,
    pub ja4_hash: Option<String>,
    pub ja3_hash: Option<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub not_after: Option<String>,
    pub cipher_suite: Option<String>,
    pub tls_version: Option<String>,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub dst_port: u16,
}

#[derive(Debug, Clone)]
pub struct FimRawEvent {
    pub timestamp_ns: u64,
    pub path: String,
    pub operation: FimOperation,
    pub pid: u32,
    pub inode: u64,
}

#[derive(Debug, Clone)]
pub enum FimOperation {
    Open,
    Create,
    Write,
    Rename,
    Unlink,
    Chmod,
    Chown,
}

// ─── Alert (output of detection engine) ──────────────────────────────────────

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleType {
    Sigma,
    Yara,
    Ioc,
    Ml,
    Xdp,
    Ids,
    Fim,
    Ueba,
    ThreatIntel,
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatLevel::Critical => write!(f, "CRITICAL"),
            ThreatLevel::High     => write!(f, "HIGH"),
            ThreatLevel::Medium   => write!(f, "MEDIUM"),
            ThreatLevel::Low      => write!(f, "LOW"),
            ThreatLevel::Unknown  => write!(f, "UNKNOWN"),
        }
    }
}
