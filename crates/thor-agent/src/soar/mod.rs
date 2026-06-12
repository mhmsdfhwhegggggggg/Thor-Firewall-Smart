//! SOAR Engine — autonomous threat response (Isolation, Quarantine, Forensics, TheHive)

pub mod isolation;
pub mod quarantine;
pub mod forensics;

use std::sync::Arc;
use tracing::{info, warn};

use crate::events::Alert;
use crate::state::ThorState;
use thor_common::{ThreatLevel, ResponseActionType};

use isolation::NetworkIsolator;
use quarantine::FileQuarantiner;
use forensics::ForensicCollector;

pub struct SoarEngine {
    state: Arc<ThorState>,
    thehive_url: Option<String>,
    isolator: NetworkIsolator,
    quarantiner: FileQuarantiner,
    forensics: ForensicCollector,
}

impl SoarEngine {
    pub fn new(state: Arc<ThorState>, thehive_url: Option<String>) -> Self {
        Self {
            state,
            thehive_url,
            isolator: NetworkIsolator::new(),
            quarantiner: FileQuarantiner::new("/var/lib/thor/quarantine"),
            forensics: ForensicCollector::new("/var/lib/thor/forensics"),
        }
    }

    /// Execute SOAR playbook for an alert — returns list of actions taken
    pub async fn respond(&self, alert: &Alert) -> Vec<String> {
        let mut actions = Vec::new();

        match alert.threat_level {
            ThreatLevel::Critical => {
                // Critical: Forensics → Isolate → Quarantine
                if let Some(pid) = alert.pid {
                    match self.forensics.capture(pid).await {
                        Ok(path) => { actions.push(format!("forensics_captured:{}", path)); }
                        Err(e) => { warn!("Forensics failed: {}", e); }
                    }
                    match self.isolator.isolate_process(pid).await {
                        Ok(_) => { actions.push(format!("network_isolated:pid={}", pid)); }
                        Err(e) => { warn!("Isolation failed: {}", e); }
                    }
                }
                actions.push("soar_playbook:critical".to_string());
            }
            ThreatLevel::High => {
                // High: Block IP + optional file quarantine
                if let Some(ip) = &alert.src_ip {
                    actions.push(format!("ip_blocked:{}", ip));
                }
                actions.push("soar_playbook:high".to_string());
            }
            ThreatLevel::Medium => {
                actions.push("soar_playbook:medium_alert".to_string());
            }
            ThreatLevel::Low | ThreatLevel::Unknown => {
                actions.push("soar_playbook:log_only".to_string());
            }
        }

        // TheHive integration
        if let Some(hive_url) = &self.thehive_url {
            match self.create_thehive_alert(hive_url, alert).await {
                Ok(case_id) => { actions.push(format!("thehive_case:{}", case_id)); }
                Err(e) => { warn!("TheHive alert failed: {}", e); }
            }
        }

        // Update alert counter
        self.state.total_alerts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        info!("🎯 SOAR response for '{}': {:?}", alert.rule_name, actions);
        actions
    }

    async fn create_thehive_alert(&self, url: &str, alert: &Alert) -> anyhow::Result<String> {
        let client = reqwest::Client::new();
        let body = serde_json::json!({
            "title": format!("Thor Alert: {}", alert.rule_name),
            "description": alert.description,
            "severity": match alert.threat_level {
                ThreatLevel::Critical => 3,
                ThreatLevel::High => 2,
                _ => 1,
            },
            "source": "thor-firewall-smart",
            "sourceRef": alert.id,
            "type": "thor-detection",
            "observables": alert.src_ip.as_ref().map(|ip| vec![
                serde_json::json!({"dataType": "ip", "data": ip})
            ]).unwrap_or_default()
        });
        let res = client.post(format!("{}/api/alert", url))
            .json(&body)
            .send().await?;
        let data: serde_json::Value = res.json().await?;
        Ok(data["id"].as_str().unwrap_or("unknown").to_string())
    }
}
