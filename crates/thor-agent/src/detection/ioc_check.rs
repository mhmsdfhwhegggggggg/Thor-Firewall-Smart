//! IOC checker — matches events against IOC database (Bloom + DashMap)

use uuid::Uuid;
use chrono::Utc;
use std::net::Ipv4Addr;
use crate::events::{Alert, RuleType};
use crate::events::enrichment::EnrichedEvent;
use crate::events::RawEvent;
use thor_common::ThreatLevel;

pub struct IocChecker;

impl IocChecker {
    pub fn new() -> Self { Self }

    pub fn check(&self, event: &EnrichedEvent) -> Option<Alert> {
        let (ip_to_check, dst_port) = match &event.raw {
            RawEvent::Network(e) => (Some(e.dst_ip.to_string()), Some(e.dst_port)),
            RawEvent::XdpDrop { dst_ip, dst_port, .. } => {
                (Some(Ipv4Addr::from(*dst_ip).to_string()), Some(*dst_port))
            }
            _ => return None,
        };

        // In production: check against self.ioc_db.check(&ip)
        // Here we demonstrate the pattern
        let ip = ip_to_check?;

        // Stub: threat intel feed check
        let is_known_bad = is_known_c2(&ip);
        if !is_known_bad { return None; }

        Some(Alert {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            source: event.hostname.clone().unwrap_or_default(),
            rule_name: "IOC:ThreatIntel".to_string(),
            rule_type: RuleType::Ioc,
            threat_level: ThreatLevel::High,
            description: format!("Known malicious IP: {}", ip),
            pid: None,
            process_name: None,
            src_ip: event.src_ip_str.clone(),
            dst_ip: Some(ip),
            dst_port,
            ml_score: None,
            soar_actions_taken: vec![],
            raw_event_type: event.raw.source().to_string(),
        })
    }
}

/// Stub: in production this queries the IocDatabase
fn is_known_c2(ip: &str) -> bool {
    // Known-bad C2 IPs from threat feeds (stub list — replace with real TI)
    const KNOWN_BAD: &[&str] = &[
        "192.168.100.200",  // Example only — not real malicious IP
    ];
    KNOWN_BAD.contains(&ip)
}
