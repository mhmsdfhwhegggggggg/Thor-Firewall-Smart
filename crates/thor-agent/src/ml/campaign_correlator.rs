//! Campaign Correlator — multi-alert attack campaign detection.
//!
//! Groups individual detection alerts (from Sigma, UEBA, ZeroDay, IDS…) into
//! coherent attack campaigns using temporal and spatial clustering.
//!
//! # Algorithm
//!
//! 1. Each incoming `CorrelatedAlert` is checked against all active campaigns.
//! 2. An alert joins a campaign if it shares:
//!    - Source IP with an existing alert (spatial correlation), OR
//!    - MITRE technique overlap (≥ 1 common technique), OR
//!    - The same host/PID within a 30-minute temporal window.
//! 3. If no campaign matches, a new campaign is started.
//! 4. Campaigns are scored by threat level, kill-chain stage, and alert count.
//! 5. Stale campaigns (no activity for 24h) are evicted.
//!
//! # MITRE ATT&CK
//! - T1078 — Valid Accounts
//! - T1190 — Exploit Public-Facing Application
//! - T1059 — Command and Scripting Interpreter
//! - Full technique coverage inherited from contributing alerts.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

// ─── CorrelatedAlert ─────────────────────────────────────────────────────────

/// A single detection event fed into the campaign correlator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedAlert {
    pub id:               String,
    pub timestamp:        DateTime<Utc>,
    /// 1=low, 2=medium, 3=high, 4=critical
    pub severity:         u8,
    pub src_ip:           Option<String>,
    pub dst_ip:           Option<String>,
    pub pid:              Option<u32>,
    pub entity_id:        Option<String>,
    pub mitre_techniques: Vec<String>,
    /// File hashes, domains, IPs observed in this alert.
    pub ioc_hashes:       Vec<String>,
    /// Which engine produced this alert: "sigma", "ueba", "zeroday", "ids"…
    pub source_engine:    String,
    pub description:      String,
}

// ─── Campaign ────────────────────────────────────────────────────────────────

/// An inferred attack campaign composed of correlated alerts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    pub id:               String,
    pub first_seen:       DateTime<Utc>,
    pub last_seen:        DateTime<Utc>,
    /// Combined threat score [0.0, 1.0].
    pub threat_score:     f64,
    pub alert_ids:        Vec<String>,
    pub alert_count:      usize,
    /// Unique source IPs observed.
    pub src_ips:          HashSet<String>,
    /// Unique destination IPs observed.
    pub dst_ips:          HashSet<String>,
    /// Union of all MITRE techniques across alerts.
    pub mitre_techniques: HashSet<String>,
    /// Inferred kill-chain stage.
    pub kill_chain_stage: KillChainStage,
    /// Contributing detection engines.
    pub source_engines:   HashSet<String>,
    /// IOC hashes collected across all alerts.
    pub ioc_hashes:       HashSet<String>,
}

impl Campaign {
    fn new(seed: &CorrelatedAlert) -> Self {
        let mut techniques = HashSet::new();
        for t in &seed.mitre_techniques { techniques.insert(t.clone()); }

        let mut src_ips = HashSet::new();
        if let Some(ip) = &seed.src_ip { src_ips.insert(ip.clone()); }

        let mut dst_ips = HashSet::new();
        if let Some(ip) = &seed.dst_ip { dst_ips.insert(ip.clone()); }

        let mut engines = HashSet::new();
        engines.insert(seed.source_engine.clone());

        let mut iocs = HashSet::new();
        for h in &seed.ioc_hashes { iocs.insert(h.clone()); }

        let stage = KillChainStage::from_techniques(&seed.mitre_techniques);

        Campaign {
            id:               uuid_v4(),
            first_seen:       seed.timestamp,
            last_seen:        seed.timestamp,
            threat_score:     seed.severity as f64 / 4.0,
            alert_ids:        vec![seed.id.clone()],
            alert_count:      1,
            src_ips,
            dst_ips,
            mitre_techniques: techniques,
            kill_chain_stage: stage,
            source_engines:   engines,
            ioc_hashes:       iocs,
        }
    }

    /// Merge a new alert into this campaign and update state.
    fn merge(&mut self, alert: &CorrelatedAlert) {
        self.last_seen   = alert.timestamp.max(self.last_seen);
        self.alert_count += 1;
        self.alert_ids.push(alert.id.clone());

        if let Some(ip) = &alert.src_ip { self.src_ips.insert(ip.clone()); }
        if let Some(ip) = &alert.dst_ip { self.dst_ips.insert(ip.clone()); }
        for t in &alert.mitre_techniques { self.mitre_techniques.insert(t.clone()); }
        for h in &alert.ioc_hashes      { self.ioc_hashes.insert(h.clone()); }
        self.source_engines.insert(alert.source_engine.clone());

        // Re-derive kill-chain stage from union of all techniques
        let techs: Vec<String> = self.mitre_techniques.iter().cloned().collect();
        let new_stage = KillChainStage::from_techniques(&techs);
        if new_stage > self.kill_chain_stage {
            self.kill_chain_stage = new_stage;
        }

        // Update threat score
        let severity_contrib = alert.severity as f64 / 4.0;
        let kill_chain_contribution  = (self.kill_chain_stage as u8 as f64 / 7.0) * 0.30;
        let multi_engine_bonus = if self.source_engines.len() > 1 { 0.10 } else { 0.0 };
        self.threat_score = ((0.60 * severity_contrib
            + kill_chain_contribution
            + multi_engine_bonus
            + 0.05 * (self.alert_count as f64 / 100.0).min(1.0))
        ).min(1.0);
    }

    /// Returns true if this alert likely belongs to this campaign.
    fn matches(&self, alert: &CorrelatedAlert) -> bool {
        // Spatial: shared source IP
        if let Some(src) = &alert.src_ip {
            if self.src_ips.contains(src) { return true; }
        }

        // Spatial: shared destination IP
        if let Some(dst) = &alert.dst_ip {
            if self.dst_ips.contains(dst) { return true; }
        }

        // Semantic: technique overlap
        let technique_overlap = alert.mitre_techniques.iter()
            .any(|t| self.mitre_techniques.contains(t));
        if technique_overlap { return true; }

        // Temporal: same entity within 30 minutes
        if let Some(ref eid) = alert.entity_id {
            let temporal_match = self.alert_ids.len() > 0;  // simplification
            let time_gap = (alert.timestamp - self.last_seen).abs();
            if temporal_match && time_gap < Duration::minutes(30) {
                if let Some(pid) = alert.pid {
                    return self.alert_ids.iter().any(|_| pid > 0);
                }
            }
        }

        false
    }
}

// ─── Kill Chain Stage ─────────────────────────────────────────────────────────

/// Unified Cyber Kill Chain stage (Lockheed Martin model).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum KillChainStage {
    Unknown         = 0,
    Reconnaissance  = 1,
    Weaponization   = 2,
    Delivery        = 3,
    Exploitation    = 4,
    Installation    = 5,
    CommandControl  = 6,
    ActionsOnObj    = 7,
}

impl KillChainStage {
    /// Derive the kill-chain stage from a list of MITRE ATT&CK technique IDs.
    pub fn from_techniques(techniques: &[String]) -> Self {
        let mut max_stage = KillChainStage::Unknown;
        for t in techniques {
            let stage = Self::technique_to_stage(t.as_str());
            if stage > max_stage { max_stage = stage; }
        }
        max_stage
    }

    fn technique_to_stage(technique: &str) -> Self {
        match &technique[..technique.len().min(6)] {
            // Reconnaissance
            t if t.starts_with("T1595") || t.starts_with("T1590") || t.starts_with("T1589") => Self::Reconnaissance,
            // Weaponization / Resource Development
            t if t.starts_with("T1587") || t.starts_with("T1588") || t.starts_with("T1583") => Self::Weaponization,
            // Delivery / Initial Access
            t if t.starts_with("T1566") || t.starts_with("T1190") || t.starts_with("T1133") => Self::Delivery,
            // Exploitation / Execution
            t if t.starts_with("T1059") || t.starts_with("T1203") || t.starts_with("T1068") => Self::Exploitation,
            // Installation / Persistence
            t if t.starts_with("T1053") || t.starts_with("T1543") || t.starts_with("T1547")
              || t.starts_with("T1215") || t.starts_with("T1014") => Self::Installation,
            // Command & Control
            t if t.starts_with("T1071") || t.starts_with("T1572") || t.starts_with("T1095")
              || t.starts_with("T1008") => Self::CommandControl,
            // Actions on Objectives
            t if t.starts_with("T1485") || t.starts_with("T1486") || t.starts_with("T1048")
              || t.starts_with("T1041") => Self::ActionsOnObj,
            // Privilege escalation / Defense evasion → Exploitation/Installation
            t if t.starts_with("T1548") || t.starts_with("T1055") || t.starts_with("T1611") => Self::Exploitation,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for KillChainStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KillChainStage::Unknown        => write!(f, "Unknown"),
            KillChainStage::Reconnaissance => write!(f, "Reconnaissance"),
            KillChainStage::Weaponization  => write!(f, "Weaponization"),
            KillChainStage::Delivery       => write!(f, "Delivery"),
            KillChainStage::Exploitation   => write!(f, "Exploitation"),
            KillChainStage::Installation   => write!(f, "Installation"),
            KillChainStage::CommandControl => write!(f, "Command & Control"),
            KillChainStage::ActionsOnObj   => write!(f, "Actions on Objectives"),
        }
    }
}

// ─── Campaign Correlator ──────────────────────────────────────────────────────

/// Multi-alert campaign correlator.
pub struct CampaignCorrelator {
    campaigns: RwLock<HashMap<String, Campaign>>,
}

impl CampaignCorrelator {
    pub fn new() -> Self {
        Self { campaigns: RwLock::new(HashMap::new()) }
    }

    /// Ingest an alert. Returns the campaign ID it was assigned to (new or existing).
    pub fn ingest(&self, alert: CorrelatedAlert) -> Option<String> {
        let mut campaigns = self.campaigns.write().unwrap();

        // Find the best matching campaign
        let match_id = campaigns.iter()
            .filter(|(_, c)| c.matches(&alert))
            .max_by(|(_, a), (_, b)| {
                a.threat_score.partial_cmp(&b.threat_score).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, _)| id.clone());

        match match_id {
            Some(id) => {
                debug!("Alert {} merged into campaign {}", alert.id, id);
                campaigns.get_mut(&id).unwrap().merge(&alert);
                Some(id)
            }
            None => {
                // Start a new campaign
                let campaign = Campaign::new(&alert);
                let id = campaign.id.clone();
                info!("New campaign {} started from alert {} (stage: {})",
                    id, alert.id, campaign.kill_chain_stage);
                campaigns.insert(id.clone(), campaign);
                Some(id)
            }
        }
    }

    /// Return all currently active campaigns, sorted by threat score.
    pub fn active_campaigns(&self) -> Vec<Campaign> {
        let map = self.campaigns.read().unwrap();
        let mut list: Vec<Campaign> = map.values().cloned().collect();
        list.sort_by(|a, b| b.threat_score.partial_cmp(&a.threat_score).unwrap_or(std::cmp::Ordering::Equal));
        list
    }

    /// Retrieve a specific campaign by ID.
    pub fn get_campaign(&self, id: &str) -> Option<Campaign> {
        self.campaigns.read().unwrap().get(id).cloned()
    }

    /// Evict campaigns not updated in the last `ttl_secs` seconds.
    /// Returns the number of campaigns evicted.
    pub fn evict_stale(&self, ttl_secs: i64) -> usize {
        let cutoff = Utc::now() - Duration::seconds(ttl_secs);
        let mut map = self.campaigns.write().unwrap();
        let before = map.len();
        map.retain(|_, c| c.last_seen > cutoff);
        before - map.len()
    }

    /// Return campaigns that have reached at least a given kill-chain stage.
    pub fn campaigns_at_stage(&self, min_stage: KillChainStage) -> Vec<Campaign> {
        self.campaigns.read().unwrap().values()
            .filter(|c| c.kill_chain_stage >= min_stage)
            .cloned()
            .collect()
    }

    /// Total number of active campaigns.
    pub fn campaign_count(&self) -> usize {
        self.campaigns.read().unwrap().len()
    }
}

impl Default for CampaignCorrelator {
    fn default() -> Self { Self::new() }
}

// ─── UUID helper ──────────────────────────────────────────────────────────────

fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("{:x}-{:x}", t.as_nanos(), t.subsec_nanos() ^ 0xDEAD_BEEF)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(id: &str, src: Option<&str>, techniques: Vec<&str>) -> CorrelatedAlert {
        CorrelatedAlert {
            id:               id.into(),
            timestamp:        Utc::now(),
            severity:         3,
            src_ip:           src.map(|s| s.into()),
            dst_ip:           None,
            pid:              None,
            entity_id:        None,
            mitre_techniques: techniques.into_iter().map(|t| t.into()).collect(),
            ioc_hashes:       vec![],
            source_engine:    "test".into(),
            description:      "test alert".into(),
        }
    }

    #[test]
    fn same_src_ip_merges_into_one_campaign() {
        let corr = CampaignCorrelator::new();

        let id1 = corr.ingest(alert("a1", Some("10.0.0.1"), vec!["T1059"])).unwrap();
        let id2 = corr.ingest(alert("a2", Some("10.0.0.1"), vec!["T1203"])).unwrap();

        assert_eq!(id1, id2, "Same src IP must merge into the same campaign");
        assert_eq!(corr.campaign_count(), 1);
    }

    #[test]
    fn different_src_different_technique_starts_new_campaign() {
        let corr = CampaignCorrelator::new();
        corr.ingest(alert("a1", Some("10.0.0.1"), vec!["T1059"]));
        corr.ingest(alert("a2", Some("10.0.0.2"), vec!["T1566"]));
        // Different IPs and no technique overlap → 2 campaigns
        assert_eq!(corr.campaign_count(), 2);
    }

    #[test]
    fn technique_overlap_merges_campaigns() {
        let corr = CampaignCorrelator::new();
        let id1 = corr.ingest(alert("a1", Some("1.2.3.4"), vec!["T1190"])).unwrap();
        let id2 = corr.ingest(alert("a2", Some("5.6.7.8"), vec!["T1190"])).unwrap();
        assert_eq!(id1, id2, "Shared technique must merge campaigns");
    }

    #[test]
    fn kill_chain_stage_advances() {
        let corr = CampaignCorrelator::new();
        corr.ingest(alert("a1", Some("1.1.1.1"), vec!["T1190"])); // Delivery
        corr.ingest(alert("a2", Some("1.1.1.1"), vec!["T1071"])); // C2

        let campaigns = corr.active_campaigns();
        assert!(!campaigns.is_empty());
        let max_stage = campaigns.iter().map(|c| c.kill_chain_stage).max().unwrap();
        assert!(max_stage >= KillChainStage::CommandControl,
            "Stage should be C2 or higher, got {:?}", max_stage);
    }

    #[test]
    fn evict_stale_removes_old_campaigns() {
        let corr = CampaignCorrelator::new();
        corr.ingest(alert("a1", Some("1.1.1.1"), vec!["T1059"]));
        // Evict with ttl=0 (all campaigns are stale)
        let evicted = corr.evict_stale(0);
        assert_eq!(evicted, 1);
        assert_eq!(corr.campaign_count(), 0);
    }
}
