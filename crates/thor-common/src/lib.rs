//! Thor Common — shared types across all crates

pub mod crypto;

use serde::{Deserialize, Serialize};

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

    /// Numeric severity (1=low, 4=critical) for sorting/scoring
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
