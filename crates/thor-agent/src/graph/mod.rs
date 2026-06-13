//! Attack Graph — Multi-event correlation engine.
//! Chains individual alerts into a unified attack timeline (kill chain).
//!
//! Identifies:
//!   - Campaigns: same source attacking multiple targets over time
//!   - Kill chains: progression through MITRE ATT&CK stages
//!   - Lateral movement: source IP changing mid-attack
//!   - Staging patterns: recon → exploit → persist → exfil
//!
//! Output: Attack Campaign objects with full timeline + MITRE progression.

use crate::events::Alert;
use crate::mitre::{AttackTag, Tactic};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

// ─── Campaign ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    pub id:             String,
    pub first_seen:     u64,
    pub last_seen:      u64,
    pub source_ips:     HashSet<String>,
    pub target_ips:     HashSet<String>,
    pub alert_ids:      Vec<String>,
    pub alert_count:    usize,
    pub tactics_seen:   Vec<String>,
    pub techniques:     HashSet<String>,
    pub kill_chain_max: u8,
    pub stage:          CampaignStage,
    pub severity:       CampaignSeverity,
    pub description:    String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CampaignStage {
    Reconnaissance,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    LateralMovement,
    CommandAndControl,
    Exfiltration,
    Impact,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CampaignSeverity { Low, Medium, High, Critical }

impl Campaign {
    fn new(id: String, alert: &Alert, tag: &AttackTag) -> Self {
        let now = now_unix();
        let src = alert.src_ip.clone().unwrap_or_default();
        let dst = alert.dst_ip.clone().unwrap_or_default();
        let tactics = tag.techniques.iter().map(|t| t.tactic.name().to_string()).collect();
        let techniques: HashSet<String> = tag.techniques.iter().map(|t| t.id.clone()).collect();
        let kill_chain = tag.kill_chain_phase.unwrap_or(0);

        Self {
            id,
            first_seen: now,
            last_seen: now,
            source_ips: if src.is_empty() { HashSet::new() } else { [src].into() },
            target_ips: if dst.is_empty() { HashSet::new() } else { [dst].into() },
            alert_ids: vec![alert.id.clone()],
            alert_count: 1,
            tactics_seen: tactics,
            techniques,
            kill_chain_max: kill_chain,
            stage: kill_chain_to_stage(kill_chain),
            severity: CampaignSeverity::Low,
            description: format!("Campaign started with: {}", alert.rule_name),
        }
    }

    fn absorb(&mut self, alert: &Alert, tag: &AttackTag) {
        let now = now_unix();
        self.last_seen = now;
        self.alert_ids.push(alert.id.clone());
        self.alert_count += 1;

        if let Some(src) = &alert.src_ip { self.source_ips.insert(src.clone()); }
        if let Some(dst) = &alert.dst_ip { self.target_ips.insert(dst.clone()); }

        for t in &tag.techniques {
            let tactic_name = t.tactic.name().to_string();
            if !self.tactics_seen.contains(&tactic_name) {
                self.tactics_seen.push(tactic_name);
            }
            self.techniques.insert(t.id.clone());
        }

        if let Some(phase) = tag.kill_chain_phase {
            if phase > self.kill_chain_max {
                self.kill_chain_max = phase;
                self.stage = kill_chain_to_stage(phase);
            }
        }

        self.severity = self.compute_severity();
    }

    fn compute_severity(&self) -> CampaignSeverity {
        match (self.alert_count, self.kill_chain_max) {
            (_, p) if p >= 13               => CampaignSeverity::Critical,
            (c, p) if c > 50 || p >= 10     => CampaignSeverity::Critical,
            (c, p) if c > 20 || p >= 7      => CampaignSeverity::High,
            (c, p) if c > 5  || p >= 4      => CampaignSeverity::Medium,
            _                               => CampaignSeverity::Low,
        }
    }

    pub fn duration_secs(&self) -> u64 {
        self.last_seen.saturating_sub(self.first_seen)
    }
}

fn kill_chain_to_stage(phase: u8) -> CampaignStage {
    match phase {
        1  => CampaignStage::Reconnaissance,
        3  => CampaignStage::InitialAccess,
        4  => CampaignStage::Execution,
        5  => CampaignStage::Persistence,
        6  => CampaignStage::PrivilegeEscalation,
        10 => CampaignStage::LateralMovement,
        12 => CampaignStage::CommandAndControl,
        13 => CampaignStage::Exfiltration,
        14 => CampaignStage::Impact,
        _  => CampaignStage::Unknown,
    }
}

// ─── Alert node (lightweight graph vertex) ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertNode {
    pub alert_id:      String,
    pub ts:            u64,
    pub src_ip:        Option<String>,
    pub dst_ip:        Option<String>,
    pub rule:          String,
    pub technique_ids: Vec<String>,
    pub kill_chain:    Option<u8>,
}

// ─── Graph engine ─────────────────────────────────────────────────────────────

pub struct AttackGraph {
    campaigns:       DashMap<String, Campaign>,
    ip_to_campaign:  DashMap<String, String>,
    nodes:           DashMap<String, AlertNode>,
    campaign_window: Duration,
}

impl AttackGraph {
    pub fn new() -> Arc<Self> {
        let window_mins: u64 = std::env::var("THOR_CAMPAIGN_WINDOW_MINS")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(60);

        info!("🕸️  Attack Graph initialized (campaign window: {}m)", window_mins);
        Arc::new(Self {
            campaigns: DashMap::new(),
            ip_to_campaign: DashMap::new(),
            nodes: DashMap::new(),
            campaign_window: Duration::from_secs(window_mins * 60),
        })
    }

    /// Ingest an alert and correlate it into campaigns.
    /// Returns the campaign ID if correlation occurred.
    pub fn ingest(&self, alert: &Alert, tag: &AttackTag) -> Option<String> {
        // Create alert node
        let node = AlertNode {
            alert_id: alert.id.clone(),
            ts: alert.timestamp.timestamp() as u64,
            src_ip: alert.src_ip.clone(),
            dst_ip: alert.dst_ip.clone(),
            rule: alert.rule_name.clone(),
            technique_ids: tag.techniques.iter().map(|t| t.id.clone()).collect(),
            kill_chain: tag.kill_chain_phase,
        };
        self.nodes.insert(alert.id.clone(), node);

        // Try to find an existing campaign for this source IP
        let campaign_id = alert.src_ip.as_deref()
            .and_then(|ip| self.ip_to_campaign.get(ip).map(|id| id.clone()));

        match campaign_id {
            Some(cid) => {
                if let Some(mut campaign) = self.campaigns.get_mut(&cid) {
                    let now = now_unix();
                    let age = now.saturating_sub(campaign.last_seen);
                    if age <= self.campaign_window.as_secs() {
                        campaign.absorb(alert, tag);
                        if campaign.severity == CampaignSeverity::Critical {
                            warn!(
                                "🚨 CRITICAL CAMPAIGN: id={} alerts={} stage={:?} techniques={}",
                                cid, campaign.alert_count,
                                campaign.stage, campaign.techniques.len()
                            );
                        }
                        return Some(cid);
                    }
                }
                // Campaign expired — create new one
                self.new_campaign(alert, tag)
            }
            None => self.new_campaign(alert, tag),
        }
    }

    fn new_campaign(&self, alert: &Alert, tag: &AttackTag) -> Option<String> {
        if tag.techniques.is_empty() { return None; }

        let id = format!("CAM-{}", &alert.id[..8.min(alert.id.len())]);
        let campaign = Campaign::new(id.clone(), alert, tag);

        if let Some(src) = &alert.src_ip {
            self.ip_to_campaign.insert(src.clone(), id.clone());
        }
        self.campaigns.insert(id.clone(), campaign);
        Some(id)
    }

    pub fn get_campaign(&self, id: &str) -> Option<Campaign> {
        self.campaigns.get(id).map(|c| c.clone())
    }

    pub fn active_campaigns(&self) -> Vec<Campaign> {
        let cutoff = now_unix().saturating_sub(self.campaign_window.as_secs());
        let mut v: Vec<Campaign> = self.campaigns.iter()
            .filter(|c| c.last_seen >= cutoff)
            .map(|c| c.clone())
            .collect();
        v.sort_by(|a, b| b.severity.partial_cmp(&a.severity)
            .unwrap_or(std::cmp::Ordering::Equal));
        v
    }

    pub fn critical_campaigns(&self) -> Vec<Campaign> {
        self.active_campaigns().into_iter()
            .filter(|c| c.severity == CampaignSeverity::Critical)
            .collect()
    }

    /// Evict campaigns older than 2x the window.
    pub fn evict_expired(&self) {
        let cutoff = now_unix().saturating_sub(self.campaign_window.as_secs() * 2);
        self.campaigns.retain(|_, c| c.last_seen >= cutoff);
        self.nodes.retain(|_, n| n.ts >= cutoff);
    }

    pub fn stats(&self) -> serde_json::Value {
        let active = self.active_campaigns();
        let critical = active.iter().filter(|c| c.severity == CampaignSeverity::Critical).count();
        let high = active.iter().filter(|c| c.severity == CampaignSeverity::High).count();
        serde_json::json!({
            "total_campaigns": self.campaigns.len(),
            "active_campaigns": active.len(),
            "critical": critical,
            "high": high,
            "alert_nodes": self.nodes.len(),
        })
    }
}

impl PartialOrd for CampaignSeverity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let rank = |s: &CampaignSeverity| match s {
            CampaignSeverity::Low => 0, CampaignSeverity::Medium => 1,
            CampaignSeverity::High => 2, CampaignSeverity::Critical => 3,
        };
        rank(self).partial_cmp(&rank(other))
    }
}

pub type SharedAttackGraph = Arc<AttackGraph>;

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
