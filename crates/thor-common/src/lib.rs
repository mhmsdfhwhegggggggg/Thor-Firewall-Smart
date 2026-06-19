//! Thor Common — shared types, unified event schema, and Zero-Trust utilities
//!
//! All crates in the Thor workspace import from here.  Nothing in this crate
//! should have side-effects at crate-init time.

pub mod crypto;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Threat Level ─────────────────────────────────────────────────────────────

/// Unified threat severity level used across detection, alerts, and SOAR
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatLevel {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatLevel {
    /// Derive threat level from an ML anomaly score (0.0–1.0)
    pub fn from_score(score: f32) -> Self {
        if score >= 0.95 { ThreatLevel::Critical }
        else if score >= 0.85 { ThreatLevel::High }
        else if score >= 0.70 { ThreatLevel::Medium }
        else if score >= 0.50 { ThreatLevel::Low }
        else { ThreatLevel::Unknown }
    }

    /// Numeric severity (0=unknown, 4=critical) for sorting/scoring
    pub fn severity(&self) -> u8 {
        match self {
            ThreatLevel::Unknown  => 0,
            ThreatLevel::Low      => 1,
            ThreatLevel::Medium   => 2,
            ThreatLevel::High     => 3,
            ThreatLevel::Critical => 4,
        }
    }

    pub fn is_critical_or_high(&self) -> bool {
        matches!(self, ThreatLevel::Critical | ThreatLevel::High)
    }

    pub fn from_str_level(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => ThreatLevel::Critical,
            "high"     => ThreatLevel::High,
            "medium"   => ThreatLevel::Medium,
            "low"      => ThreatLevel::Low,
            _          => ThreatLevel::Unknown,
        }
    }
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ThreatLevel::Critical => "CRITICAL",
            ThreatLevel::High     => "HIGH",
            ThreatLevel::Medium   => "MEDIUM",
            ThreatLevel::Low      => "LOW",
            ThreatLevel::Unknown  => "UNKNOWN",
        };
        write!(f, "{}", s)
    }
}

// ─── MITRE ATT&CK ─────────────────────────────────────────────────────────────

/// MITRE ATT&CK Tactic IDs — used for alert enrichment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MitreTactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl MitreTactic {
    pub fn tactic_id(&self) -> &'static str {
        match self {
            MitreTactic::Reconnaissance      => "TA0043",
            MitreTactic::ResourceDevelopment => "TA0042",
            MitreTactic::InitialAccess       => "TA0001",
            MitreTactic::Execution           => "TA0002",
            MitreTactic::Persistence         => "TA0003",
            MitreTactic::PrivilegeEscalation => "TA0004",
            MitreTactic::DefenseEvasion      => "TA0005",
            MitreTactic::CredentialAccess    => "TA0006",
            MitreTactic::Discovery           => "TA0007",
            MitreTactic::LateralMovement     => "TA0008",
            MitreTactic::Collection          => "TA0009",
            MitreTactic::CommandAndControl   => "TA0011",
            MitreTactic::Exfiltration        => "TA0010",
            MitreTactic::Impact              => "TA0040",
        }
    }
}

// ─── Unified Event Schema (Phase 0 — Protobuf-equivalent in Rust) ────────────

/// The canonical event emitted by all Thor agents to the Control-Plane.
///
/// Designed so the SOC can ingest events from:
/// - `thor-agent-net`  → fill `network`
/// - `thor-agent-web`  → fill `web`
/// - `thor-agent-srv`  → fill `server`
///
/// Only the relevant variant is populated; others are `None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedThorEvent {
    /// Globally-unique event ID (UUID v4)
    pub event_id: String,

    /// ISO-8601 timestamp when the event was generated on the agent
    pub timestamp: DateTime<Utc>,

    /// Hostname / agent identifier that generated this event
    pub agent_id: String,

    /// OS platform of the agent
    pub platform: AgentPlatform,

    /// Computed threat level
    pub threat_level: ThreatLevel,

    /// Rule or detection source that triggered this event
    pub rule_name: Option<String>,

    /// MITRE ATT&CK tactic annotation (if known)
    pub mitre_tactic: Option<MitreTactic>,

    /// Details depending on which agent generated the event
    pub details: EventDetails,

    /// Optional SOAR action already taken (e.g. "XDP_DROP", "PROCESS_KILLED")
    pub soar_action_taken: Option<String>,

    /// Short human-readable description (for SOC dashboard)
    pub description: String,
}

impl UnifiedThorEvent {
    /// Create a new event with auto-generated ID and current timestamp.
    pub fn new(agent_id: impl Into<String>, platform: AgentPlatform, details: EventDetails) -> Self {
        let threat = match &details {
            EventDetails::Network(n) => n.threat_level.clone(),
            EventDetails::Web(w)     => ThreatLevel::from_score(w.anomaly_score),
            EventDetails::Server(s)  => ThreatLevel::from_str_level(&s.severity),
        };
        let description = match &details {
            EventDetails::Network(n) => format!("Network event from {}:{} → severity {}", n.src_ip, n.src_port, threat),
            EventDetails::Web(w)     => format!("WAF alert on {} {} score={:.2}", w.method, w.uri, w.anomaly_score),
            EventDetails::Server(s)  => format!("EDR: {} PID={} — {}", s.process_name, s.pid, s.alert_cause),
        };
        Self {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            agent_id: agent_id.into(),
            platform,
            threat_level: threat,
            rule_name: None,
            mitre_tactic: None,
            details,
            soar_action_taken: None,
            description,
        }
    }
}

/// OS platform of the reporting agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentPlatform {
    Linux,
    Windows,
    Container,
    Unknown,
}

/// Polymorphic event payload — exactly one variant is populated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "agent_type", rename_all = "snake_case")]
pub enum EventDetails {
    Network(NetworkEventDetails),
    Web(WebEventDetails),
    Server(ServerEventDetails),
}

// ─── Network Agent (thor-agent-net) ──────────────────────────────────────────

/// Details emitted by the L3/L4 XDP network agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEventDetails {
    pub src_ip:       String,
    pub dst_ip:       String,
    pub src_port:     u16,
    pub dst_port:     u16,
    pub protocol:     String,   // "TCP" | "UDP" | "ICMP"
    pub tcp_flags:    Option<u8>,
    pub packet_count: u64,
    pub byte_count:   u64,
    pub action:       NetworkAction,
    pub threat_level: ThreatLevel,
    pub ioc_matched:  Option<String>, // IOC feed entry that matched
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkAction {
    Allowed,
    Dropped,    // XDP_DROP
    Redirected, // XDP_REDIRECT to honeypot
    RateLimited,
}

// ─── Web Agent (thor-agent-web) ───────────────────────────────────────────────

/// Details emitted by the L7 WAF web agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebEventDetails {
    pub src_ip:        String,
    pub method:        String,
    pub uri:           String,
    pub status_code:   Option<u16>,
    pub category:      WebThreatCategory,
    pub anomaly_score: f32,
    pub signatures:    Vec<String>, // triggered rule IDs
    pub payload_hash:  Option<String>, // SHA256 of raw payload for forensics
    pub action:        WebAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebThreatCategory {
    SqlInjection,
    CrossSiteScripting,
    PathTraversal,
    CommandInjection,
    ProtocolViolation,
    RateLimit,
    BotActivity,
    Log4Shell,
    WebShell,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebAction {
    Allowed,
    Blocked,
    Challenged,
    Logged,
}

// ─── Server Agent (thor-agent-srv) ────────────────────────────────────────────

/// Details emitted by the EDR server agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEventDetails {
    pub pid:          u32,
    pub ppid:         Option<u32>,
    pub process_name: String,
    pub cmd_line:     String,
    pub user:         String,
    pub severity:     String, // maps to ThreatLevel
    pub alert_cause:  String,
    pub action:       ServerAction,
    pub file_path:    Option<String>, // for FIM events
    pub file_hash:    Option<String>, // Blake3 hash for FIM
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerAction {
    Detected,
    ProcessKilled,
    FileQuarantined,
    NetworkIsolated,
    Logged,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Critical > ThreatLevel::High);
        assert!(ThreatLevel::High > ThreatLevel::Low);
        assert_eq!(ThreatLevel::from_score(0.96), ThreatLevel::Critical);
        assert_eq!(ThreatLevel::from_score(0.30), ThreatLevel::Unknown);
    }

    #[test]
    fn test_unified_event_network() {
        let details = EventDetails::Network(NetworkEventDetails {
            src_ip:       "192.168.1.1".into(),
            dst_ip:       "10.0.0.1".into(),
            src_port:     54321,
            dst_port:     443,
            protocol:     "TCP".into(),
            tcp_flags:    Some(0x02),
            packet_count: 10,
            byte_count:   1024,
            action:       NetworkAction::Dropped,
            threat_level: ThreatLevel::High,
            ioc_matched:  Some("Feodo-C2".into()),
        });
        let event = UnifiedThorEvent::new("agent-net-01", AgentPlatform::Linux, details);
        assert!(!event.event_id.is_empty());
        assert_eq!(event.threat_level, ThreatLevel::High);
    }

    #[test]
    fn test_unified_event_web() {
        let details = EventDetails::Web(WebEventDetails {
            src_ip:        "203.0.113.5".into(),
            method:        "POST".into(),
            uri:           "/login".into(),
            status_code:   Some(403),
            category:      WebThreatCategory::SqlInjection,
            anomaly_score: 0.93,
            signatures:    vec!["SQLI-001".into()],
            payload_hash:  None,
            action:        WebAction::Blocked,
        });
        let event = UnifiedThorEvent::new("agent-web-01", AgentPlatform::Linux, details);
        assert_eq!(event.threat_level, ThreatLevel::Critical);
        assert!(event.description.contains("WAF alert"));
    }

    #[test]
    fn test_mitre_tactic_ids() {
        assert_eq!(MitreTactic::CommandAndControl.tactic_id(), "TA0011");
        assert_eq!(MitreTactic::Exfiltration.tactic_id(), "TA0010");
    }
}
