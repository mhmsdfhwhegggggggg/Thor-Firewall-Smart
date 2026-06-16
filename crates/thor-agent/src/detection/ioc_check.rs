//! IOC checker — matches events against IOC database (Bloom + DashMap)
//! Uses enrichment.ioc_matched (set by EventEnricher via IocDatabase.check())

use uuid::Uuid;
use chrono::Utc;
use std::sync::Arc;
use crate::events::{Alert, RuleType};
use crate::events::enrichment::EnrichedEvent;
use crate::state::ioc::{IocDatabase, IocEntry};
use thor_common::ThreatLevel;

pub struct IocChecker {
    db: Option<Arc<IocDatabase>>,
}

impl IocChecker {
    pub fn new() -> Self {
        Self { db: None }
    }

    pub fn with_db(db: Arc<IocDatabase>) -> Self {
        Self { db: Some(db) }
    }

    pub fn check(&self, event: &EnrichedEvent) -> Option<Alert> {
        // Fast path: enrichment already resolved IOC during enrichment
        if !event.ioc_matched {
            return None;
        }

        // Find which value matched for the alert description
        let (matched_value, dst_port) = match &event.raw {
            crate::events::RawEvent::Network(e) => {
                let ip = event.dst_ip_str.clone().unwrap_or_default();
                (ip, Some(e.dst_port))
            }
            crate::events::RawEvent::Dns(e) => (e.query.clone(), None),
            crate::events::RawEvent::Tls(e) => {
                let sni = e.sni.clone().unwrap_or_default();
                (sni, None)
            }
            _ => (event.dst_ip_str.clone().unwrap_or_default(), None),
        };

        if matched_value.is_empty() {
            return None;
        }

        // Look up threat level from DB if available
        let (threat_level, source, tags) = if let Some(db) = &self.db {
            if let Some(entry) = db.check(&matched_value) {
                let tl = thor_common::ThreatLevel::from_str_level(&entry.threat_level);
                (tl, entry.source.clone(), entry.tags.clone())
            } else {
                (ThreatLevel::High, "ThreatIntel".to_string(), vec![])
            }
        } else {
            (ThreatLevel::High, "ThreatIntel".to_string(), vec![])
        };

        Some(Alert {
            id:           Uuid::new_v4().to_string(),
            timestamp:    Utc::now(),
            source:       event.hostname.clone().unwrap_or_default(),
            rule_name:    format!("IOC:{}:{}", source, matched_value),
            rule_type:    RuleType::ThreatIntel,
            threat_level,
            description:  format!(
                "IOC match: {} (source: {}, tags: {})",
                matched_value,
                source,
                tags.join(",")
            ),
            pid:          None,
            process_name: None,
            src_ip:       event.src_ip_str.clone(),
            dst_ip:       event.dst_ip_str.clone(),
            dst_port,
            ml_score:     None,
            soar_actions_taken: vec![],
            raw_event_type: event.raw.source().to_string(),
        })
    }
}
