//! Notification Engine — Phase 4: Multi-channel alert delivery.
//!
//! Channels: Slack, PagerDuty, Teams webhook (Email via SMTP planned)
//! Triggered on: Critical/High alert, Campaign detected, Agent health events

use anyhow::{Context, Result};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

use thor_common::ThreatLevel;
use crate::events::Alert;

// ─── Notification Config ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NotifyConfig {
    pub slack_webhook_url:  Option<String>,
    pub slack_channel:      String,
    pub pagerduty_key:      Option<String>,
    pub teams_webhook_url:  Option<String>,
    pub min_severity:       ThreatLevel,
}

impl NotifyConfig {
    pub fn from_env() -> Self {
        Self {
            slack_webhook_url: std::env::var("THOR_SLACK_WEBHOOK").ok(),
            slack_channel:     std::env::var("THOR_SLACK_CHANNEL").unwrap_or_else(|_| "#soc-alerts".into()),
            pagerduty_key:     std::env::var("THOR_PAGERDUTY_KEY").ok(),
            teams_webhook_url: std::env::var("THOR_TEAMS_WEBHOOK").ok(),
            min_severity:      ThreatLevel::High,
        }
    }
}

// ─── Notification Engine ──────────────────────────────────────────────────────

#[derive(Clone)]
pub struct NotificationEngine {
    config: Arc<NotifyConfig>,
    client: reqwest::Client,
}

impl NotificationEngine {
    pub fn new(config: NotifyConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("ThorFirewallSmart/0.2")
            .build()
            .expect("reqwest client");
        Self { config: Arc::new(config), client }
    }

    pub async fn notify_alert(&self, alert: &Alert) {
        if alert.threat_level < self.config.min_severity { return; }
        if let Some(ref url) = self.config.slack_webhook_url {
            if let Err(e) = self.send_slack(url, alert).await {
                warn!("Slack notification failed: {}", e);
            }
        }
        if alert.threat_level == ThreatLevel::Critical {
            if let Some(ref key) = self.config.pagerduty_key {
                if let Err(e) = self.send_pagerduty(key, alert).await {
                    warn!("PagerDuty notification failed: {}", e);
                }
            }
        }
        if let Some(ref url) = self.config.teams_webhook_url {
            if let Err(e) = self.send_teams(url, alert).await {
                warn!("Teams notification failed: {}", e);
            }
        }
    }

    async fn send_slack(&self, url: &str, alert: &Alert) -> Result<()> {
        let color = match alert.threat_level {
            ThreatLevel::Critical => "danger",
            ThreatLevel::High     => "warning",
            _                     => "good",
        };
        let payload = json!({
            "channel": self.config.slack_channel,
            "attachments": [{
                "color": color,
                "title": format!("{} Thor Alert: {}", alert.threat_level, alert.rule_name),
                "text": alert.message,
                "fields": [
                    { "title": "Severity", "value": alert.threat_level.to_string(), "short": true },
                    { "title": "Source IP", "value": alert.src_ip.clone().unwrap_or_else(|| "N/A".into()), "short": true },
                    { "title": "Process", "value": alert.process_name.clone().unwrap_or_else(|| "N/A".into()), "short": true },
                    { "title": "MITRE", "value": alert.mitre_technique.clone().unwrap_or_else(|| "N/A".into()), "short": true },
                ],
                "footer": "Thor Firewall Smart",
                "ts": alert.detected_at.timestamp(),
            }]
        });
        self.post_json(url, &payload).await
    }

    async fn send_pagerduty(&self, key: &str, alert: &Alert) -> Result<()> {
        let payload = json!({
            "routing_key": key,
            "event_action": "trigger",
            "dedup_key": alert.id.to_string(),
            "payload": {
                "summary": format!("Thor CRITICAL: {}", alert.rule_name),
                "severity": "critical",
                "source": alert.hostname.clone().unwrap_or_else(|| "thor-agent".into()),
                "timestamp": alert.detected_at.to_rfc3339(),
                "custom_details": {
                    "message": alert.message,
                    "src_ip": alert.src_ip,
                    "process": alert.process_name,
                    "mitre": alert.mitre_technique,
                }
            }
        });
        self.post_json("https://events.pagerduty.com/v2/enqueue", &payload).await
    }

    async fn send_teams(&self, url: &str, alert: &Alert) -> Result<()> {
        let payload = json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF0000",
            "summary": format!("Thor Alert: {}", alert.rule_name),
            "sections": [{
                "activityTitle": format!("🚨 {} — {}", alert.threat_level, alert.rule_name),
                "activityText": alert.message,
                "facts": [
                    { "name": "Severity", "value": alert.threat_level.to_string() },
                    { "name": "Source IP", "value": alert.src_ip.clone().unwrap_or_else(|| "N/A".into()) },
                    { "name": "MITRE", "value": alert.mitre_technique.clone().unwrap_or_else(|| "N/A".into()) },
                ]
            }]
        });
        self.post_json(url, &payload).await
    }

    async fn post_json(&self, url: &str, payload: &serde_json::Value) -> Result<()> {
        let resp = self.client.post(url).json(payload).send().await
            .context("notification HTTP request")?;
        if !resp.status().is_success() {
            warn!("Notification HTTP {}: {}", resp.status(), url);
        }
        Ok(())
    }
}
