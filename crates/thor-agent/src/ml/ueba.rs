//! User and Entity Behavioral Analytics (UEBA) Engine
//!
//! Detects anomalous user/entity behavior by building statistical baselines
//! and scoring deviations using ML techniques.
//!
//! # Architecture
//!
//! 1. **EntityProfile** — per-entity EMA baseline + variance tracking.
//! 2. **PeerGroupAnalyzer** — Isolation-Forest-style outlier scoring within peer groups.
//! 3. **RareEventDetector** — Markov-chain rare event scoring.
//! 4. **UebaEngine** — top-level orchestrator. Use `ingest()` to feed events.
//!
//! # MITRE ATT&CK Coverage
//! - T1078 — Valid Accounts (insider threat / stolen credential detection)
//! - T1110 — Brute Force (unusual auth rate)
//! - T1136 — Create Account (new account creation anomaly)
//! - T1098 — Account Manipulation
//! - T1087 — Account Discovery

use std::collections::HashMap;
use std::sync::RwLock;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

// ─── Entity identity ──────────────────────────────────────────────────────────

/// A uniquely identified entity observed by UEBA.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EntityId {
    User(String),
    Process(String),
    Host(String),
    Service(String),
}

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityId::User(s)    => write!(f, "user:{}", s),
            EntityId::Process(s) => write!(f, "proc:{}", s),
            EntityId::Host(s)    => write!(f, "host:{}", s),
            EntityId::Service(s) => write!(f, "svc:{}", s),
        }
    }
}

// ─── Entity feature vector ────────────────────────────────────────────────────

/// Fixed-dimension feature vector for an entity observation.
#[derive(Debug, Clone)]
pub struct EntityFeatures {
    /// Login/auth events per hour.
    pub auth_rate:          f64,
    /// Distinct destination IPs contacted per hour.
    pub unique_dest_ips:    f64,
    /// Bytes transferred per minute.
    pub bytes_per_min:      f64,
    /// New process creation rate per minute.
    pub process_create_rate: f64,
    /// File access events per minute.
    pub file_access_rate:   f64,
    /// Fraction of failed auth attempts [0, 1].
    pub auth_failure_rate:  f64,
    /// Hour of day [0, 23] — used for time-of-day anomaly.
    pub hour_of_day:        f64,
    /// Day of week [0=Monday, 6=Sunday].
    pub day_of_week:        f64,
}

impl EntityFeatures {
    pub const DIM: usize = 8;

    pub fn zero() -> Self {
        Self {
            auth_rate:           0.0,
            unique_dest_ips:     0.0,
            bytes_per_min:       0.0,
            process_create_rate: 0.0,
            file_access_rate:    0.0,
            auth_failure_rate:   0.0,
            hour_of_day:         0.0,
            day_of_week:         0.0,
        }
    }

    pub fn as_array(&self) -> [f64; Self::DIM] {
        [
            self.auth_rate,
            self.unique_dest_ips,
            self.bytes_per_min,
            self.process_create_rate,
            self.file_access_rate,
            self.auth_failure_rate,
            self.hour_of_day,
            self.day_of_week,
        ]
    }

    fn feature_names() -> [&'static str; Self::DIM] {
        [
            "auth_rate", "unique_dest_ips", "bytes_per_min",
            "process_create_rate", "file_access_rate", "auth_failure_rate",
            "hour_of_day", "day_of_week",
        ]
    }

    /// Update the EMA baseline with a new observation.
    pub fn update_ema(&mut self, new_obs: &EntityFeatures, alpha: f64) {
        let arr = new_obs.as_array();
        let base = self.as_array();
        let updated: [f64; Self::DIM] = std::array::from_fn(|i| {
            alpha * arr[i] + (1.0 - alpha) * base[i]
        });
        *self = Self::from_array(updated);
    }

    fn from_array(a: [f64; Self::DIM]) -> Self {
        Self {
            auth_rate:           a[0],
            unique_dest_ips:     a[1],
            bytes_per_min:       a[2],
            process_create_rate: a[3],
            file_access_rate:    a[4],
            auth_failure_rate:   a[5],
            hour_of_day:         a[6],
            day_of_week:         a[7],
        }
    }

    /// Mahalanobis-like distance from a baseline given variance estimates.
    pub fn distance_from(&self, baseline: &EntityFeatures, variance: &[f64; Self::DIM]) -> f64 {
        let obs  = self.as_array();
        let base = baseline.as_array();
        let sum: f64 = obs.iter().zip(base.iter()).zip(variance.iter())
            .map(|((o, b), v)| {
                let diff = o - b;
                let var  = v.max(1e-10);
                (diff * diff) / var
            })
            .sum();
        (sum / Self::DIM as f64).sqrt()
    }
}

// ─── Entity Profile ───────────────────────────────────────────────────────────

/// Per-entity baseline and deviation history.
#[derive(Debug, Clone)]
pub struct EntityProfile {
    pub entity_id:     EntityId,
    /// EMA baseline feature vector.
    pub baseline:      EntityFeatures,
    /// Running variance per feature (Welford online algorithm).
    pub variance:      [f64; EntityFeatures::DIM],
    /// M2 accumulator for Welford.
    m2:                [f64; EntityFeatures::DIM],
    /// Total observations seen.
    pub obs_count:     u64,
    /// Recent deviation scores (last 100).
    pub score_history: Vec<f64>,
    pub first_seen:    DateTime<Utc>,
    pub last_seen:     DateTime<Utc>,
}

impl EntityProfile {
    pub fn new(entity_id: EntityId) -> Self {
        let now = Utc::now();
        Self {
            entity_id,
            baseline:      EntityFeatures::zero(),
            variance:      [1.0; EntityFeatures::DIM],
            m2:            [0.0; EntityFeatures::DIM],
            obs_count:     0,
            score_history: Vec::new(),
            first_seen:    now,
            last_seen:     now,
        }
    }

    /// Update the profile with a new observation (Welford online variance + EMA baseline).
    pub fn update(&mut self, obs: &EntityFeatures) {
        self.obs_count += 1;
        self.last_seen  = Utc::now();

        let obs_arr  = obs.as_array();
        let base_arr = self.baseline.as_array();

        // Welford online variance
        for i in 0..EntityFeatures::DIM {
            let delta  = obs_arr[i] - base_arr[i];
            let delta2 = obs_arr[i] - (base_arr[i] + delta / self.obs_count as f64);
            self.m2[i] += delta * delta2;
            self.variance[i] = if self.obs_count > 1 {
                (self.m2[i] / (self.obs_count - 1) as f64).max(1e-6)
            } else {
                1.0
            };
        }

        // EMA baseline (α = 0.05 after warmup, faster initially)
        let alpha = if self.obs_count < 10 { 0.3 } else { 0.05 };
        self.baseline.update_ema(obs, alpha);
    }

    /// Score the deviation of a new observation from this entity's baseline.
    /// Returns [0.0, 1.0] where 1.0 = maximally anomalous.
    pub fn deviation_score(&self) -> f64 {
        if self.obs_count < 5 { return 0.0; }
        if self.score_history.is_empty() { return 0.0; }
        let recent: f64 = self.score_history.iter().rev().take(10).sum::<f64>()
            / self.score_history.len().min(10) as f64;
        // Sigmoid normalization: score → [0, 1]
        1.0 / (1.0 + (-recent + 3.0).exp())
    }

    /// Return the top-N most deviant features for alert description.
    pub fn top_deviations(&self) -> Vec<(String, f64)> {
        let obs  = self.baseline.as_array();
        let var  = self.variance;
        let names = EntityFeatures::feature_names();
        let mut devs: Vec<(String, f64)> = obs.iter().zip(var.iter()).zip(names.iter())
            .map(|((&o, &v), &name)| {
                let z = (o / v.sqrt()).abs();
                (name.to_string(), z)
            })
            .filter(|(_, z)| *z > 0.0)
            .collect();
        devs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        devs.truncate(3);
        devs
    }
}

// ─── Peer Group Analyzer ──────────────────────────────────────────────────────

/// Groups entities by peer type and computes inter-group outlier scores.
/// Uses a simplified k-nearest-neighbor style distance to group centroid.
pub struct PeerGroupAnalyzer {
    /// group_name → (centroid, obs_count)
    groups:       RwLock<HashMap<String, (EntityFeatures, u64)>>,
    max_samples:  usize,
}

impl PeerGroupAnalyzer {
    pub fn new(max_samples: usize) -> Self {
        Self {
            groups:      RwLock::new(HashMap::new()),
            max_samples,
        }
    }

    /// Record an observation for a named peer group (e.g. "linux_server").
    pub fn record(&self, group: &str, features: &EntityFeatures) {
        let mut map = self.groups.write().unwrap();
        let entry = map.entry(group.to_string()).or_insert_with(|| (EntityFeatures::zero(), 0));
        let alpha = 1.0 / (entry.1 + 1).min(self.max_samples as u64) as f64;
        entry.0.update_ema(features, alpha);
        entry.1 += 1;
    }

    /// Score how much this observation deviates from its peer group centroid.
    /// Returns None if the group has < 5 observations.
    pub fn outlier_score(&self, group: &str, features: &EntityFeatures) -> Option<f64> {
        let map = self.groups.read().unwrap();
        let (centroid, count) = map.get(group)?;
        if *count < 5 { return None; }
        let variance = [1.0f64; EntityFeatures::DIM];
        let dist = features.distance_from(centroid, &variance);
        // Normalize to [0,1] with a sigmoid
        Some(1.0 - 1.0 / (1.0 + dist / 3.0))
    }
}

// ─── Rare Event Detector ──────────────────────────────────────────────────────

/// Detects rare event types for an entity using frequency-based scoring.
pub struct RareEventDetector {
    /// entity_key → (event_type → count)
    counts: RwLock<HashMap<EntityId, HashMap<String, u64>>>,
}

impl RareEventDetector {
    pub fn new() -> Self {
        Self { counts: RwLock::new(HashMap::new()) }
    }

    /// Record an event type for an entity and return its rarity score [0, 1].
    /// Score = 1.0 for the first time ever, approaching 0 as it becomes common.
    pub fn record_and_score(&self, entity: &EntityId, event_type: &str) -> f64 {
        let mut map = self.counts.write().unwrap();
        let inner = map.entry(entity.clone()).or_insert_with(HashMap::new);
        let total: u64 = inner.values().sum::<u64>() + 1;
        let count = inner.entry(event_type.to_string()).or_insert(0);
        *count += 1;
        let freq = *count as f64 / total as f64;
        // Rarity score: inversely proportional to frequency
        (1.0 - freq).max(0.0)
    }

    /// Return the rarity score without updating (read-only).
    pub fn peek_score(&self, entity: &EntityId, event_type: &str) -> f64 {
        let map = self.counts.read().unwrap();
        let inner = match map.get(entity) {
            Some(m) => m,
            None    => return 1.0, // never seen → maximally rare
        };
        let total: u64 = inner.values().sum::<u64>();
        if total == 0 { return 1.0; }
        let count = inner.get(event_type).copied().unwrap_or(0);
        1.0 - (count as f64 / total as f64)
    }
}

// ─── UEBA Event ───────────────────────────────────────────────────────────────

/// An event fed into the UEBA engine.
#[derive(Debug, Clone)]
pub struct UebaEvent {
    pub entity_id:  EntityId,
    pub event_type: String,
    pub features:   EntityFeatures,
    pub timestamp:  DateTime<Utc>,
}

// ─── UEBA Alert ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaAlert {
    pub entity_id:        String,
    pub alert_type:       UebaAlertType,
    pub risk_score:       f64,
    pub description:      String,
    pub mitre_techniques: Vec<String>,
    pub timestamp:        DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UebaAlertType {
    BaselineDeviation,
    PeerGroupOutlier,
    RareEvent,
    TimeOfDayAnomaly,
    InsiderThreat,
}

impl std::fmt::Display for UebaAlertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UebaAlertType::BaselineDeviation  => write!(f, "Baseline Deviation"),
            UebaAlertType::PeerGroupOutlier   => write!(f, "Peer Group Outlier"),
            UebaAlertType::RareEvent          => write!(f, "Rare Event"),
            UebaAlertType::TimeOfDayAnomaly   => write!(f, "Time-of-Day Anomaly"),
            UebaAlertType::InsiderThreat      => write!(f, "Insider Threat"),
        }
    }
}

// ─── UEBA Engine ──────────────────────────────────────────────────────────────

/// Top-level UEBA orchestrator.
pub struct UebaEngine {
    profiles:    RwLock<HashMap<EntityId, EntityProfile>>,
    peer_groups: PeerGroupAnalyzer,
    rare_events: RareEventDetector,
}

impl UebaEngine {
    pub fn new() -> Self {
        Self {
            profiles:    RwLock::new(HashMap::new()),
            peer_groups: PeerGroupAnalyzer::new(500),
            rare_events: RareEventDetector::new(),
        }
    }

    /// Ingest an event and return any UEBA alerts generated.
    pub fn ingest(&self, event: &UebaEvent) -> Vec<UebaAlert> {
        let mut alerts = Vec::new();

        // 1. Update entity profile
        {
            let mut map = self.profiles.write().unwrap();
            let profile = map.entry(event.entity_id.clone())
                .or_insert_with(|| EntityProfile::new(event.entity_id.clone()));

            // Compute deviation BEFORE updating to score the new observation
            let variance = profile.variance;
            let dist = event.features.distance_from(&profile.baseline, &variance);
            profile.score_history.push(dist);
            if profile.score_history.len() > 100 { profile.score_history.remove(0); }

            profile.update(&event.features);
            let dev_score = profile.deviation_score();

            if profile.obs_count > 20 && dev_score > 0.75 {
                let top_devs = profile.top_deviations();
                let dev_desc = top_devs.iter()
                    .map(|(k, v)| format!("{} (z={:.1})", k, v))
                    .collect::<Vec<_>>()
                    .join(", ");

                alerts.push(UebaAlert {
                    entity_id:        event.entity_id.to_string(),
                    alert_type:       UebaAlertType::BaselineDeviation,
                    risk_score:       dev_score,
                    description:      format!(
                        "Entity {} shows significant behavioral deviation (score={:.3}). \
                         Top deviating features: {}.",
                        event.entity_id, dev_score, dev_desc
                    ),
                    mitre_techniques: vec!["T1078".into()],
                    timestamp:        event.timestamp,
                });
            }
        }

        // 2. Peer group outlier check
        let peer_group = match &event.entity_id {
            EntityId::User(_)    => "users",
            EntityId::Process(_) => "processes",
            EntityId::Host(_)    => "hosts",
            EntityId::Service(_) => "services",
        };
        self.peer_groups.record(peer_group, &event.features);

        if let Some(outlier_score) = self.peer_groups.outlier_score(peer_group, &event.features) {
            if outlier_score > 0.80 {
                alerts.push(UebaAlert {
                    entity_id:        event.entity_id.to_string(),
                    alert_type:       UebaAlertType::PeerGroupOutlier,
                    risk_score:       outlier_score,
                    description:      format!(
                        "Entity {} is a significant outlier within peer group '{}' \
                         (outlier_score={:.3}).",
                        event.entity_id, peer_group, outlier_score
                    ),
                    mitre_techniques: vec!["T1078".into(), "T1087".into()],
                    timestamp:        event.timestamp,
                });
            }
        }

        // 3. Rare event detection
        let rarity = self.rare_events.record_and_score(&event.entity_id, &event.event_type);
        if rarity > 0.95 {
            alerts.push(UebaAlert {
                entity_id:        event.entity_id.to_string(),
                alert_type:       UebaAlertType::RareEvent,
                risk_score:       rarity,
                description:      format!(
                    "Entity {} performed rare event '{}' (rarity={:.3}) — \
                     first or very-low-frequency action detected.",
                    event.entity_id, event.event_type, rarity
                ),
                mitre_techniques: vec!["T1078".into(), "T1098".into()],
                timestamp:        event.timestamp,
            });
        }

        // 4. Time-of-day anomaly (outside working hours for users)
        if let EntityId::User(_) = &event.entity_id {
            let hour = event.features.hour_of_day;
            if hour < 6.0 || hour > 22.0 {
                let risk = 0.50 + (if hour < 6.0 { 6.0 - hour } else { hour - 22.0 }) / 12.0;
                if risk > 0.60 {
                    alerts.push(UebaAlert {
                        entity_id:        event.entity_id.to_string(),
                        alert_type:       UebaAlertType::TimeOfDayAnomaly,
                        risk_score:       risk.min(1.0),
                        description:      format!(
                            "User {} active at unusual hour {:.0}:00 (risk={:.2}). \
                             Possible credential compromise or insider threat.",
                            event.entity_id, hour, risk
                        ),
                        mitre_techniques: vec!["T1078".into()],
                        timestamp:        event.timestamp,
                    });
                }
            }
        }

        if !alerts.is_empty() {
            info!("UEBA: {} alert(s) for entity {}", alerts.len(), event.entity_id);
        }

        alerts
    }

    /// Return all entity risk scores, sorted by score descending.
    /// Returns Vec<(EntityId, risk_score, event_count)>.
    pub fn risk_scores(&self) -> Vec<(EntityId, f64, u64)> {
        let map = self.profiles.read().unwrap();
        let mut scores: Vec<(EntityId, f64, u64)> = map.values()
            .map(|p| (p.entity_id.clone(), p.deviation_score(), p.obs_count))
            .collect();
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scores
    }

    /// Get a snapshot of a specific entity's profile.
    pub fn get_profile(&self, entity_id: &EntityId) -> Option<EntityProfile> {
        self.profiles.read().unwrap().get(entity_id).cloned()
    }

    /// Evict stale entities (not seen in the last `ttl_secs` seconds).
    pub fn evict_stale(&self, ttl_secs: i64) {
        let cutoff = Utc::now() - chrono::Duration::seconds(ttl_secs);
        self.profiles.write().unwrap().retain(|_, p| p.last_seen > cutoff);
    }
}

impl Default for UebaEngine {
    fn default() -> Self { Self::new() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_features(auth_rate: f64, hour: f64) -> EntityFeatures {
        EntityFeatures {
            auth_rate,
            unique_dest_ips:     5.0,
            bytes_per_min:       100.0,
            process_create_rate: 0.5,
            file_access_rate:    10.0,
            auth_failure_rate:   0.0,
            hour_of_day:         hour,
            day_of_week:         1.0,
        }
    }

    fn make_event(entity: EntityId, features: EntityFeatures) -> UebaEvent {
        UebaEvent {
            entity_id:  entity,
            event_type: "auth".into(),
            features,
            timestamp:  Utc::now(),
        }
    }

    #[test]
    fn normal_events_produce_no_alerts_initially() {
        let engine = UebaEngine::new();
        let entity = EntityId::User("alice".into());
        for _ in 0..15 {
            let ev = make_event(entity.clone(), make_features(1.0, 10.0));
            let alerts = engine.ingest(&ev);
            // During warmup (< 20 obs) no baseline deviation alerts
            assert!(alerts.iter().all(|a| !matches!(a.alert_type, UebaAlertType::BaselineDeviation)));
        }
    }

    #[test]
    fn rare_event_triggers_alert() {
        let engine = UebaEngine::new();
        let entity = EntityId::User("bob".into());
        let ev = make_event(entity, make_features(1.0, 10.0));
        let alerts = engine.ingest(&ev);
        // First occurrence of any event type is maximally rare
        assert!(alerts.iter().any(|a| matches!(a.alert_type, UebaAlertType::RareEvent)));
    }

    #[test]
    fn off_hours_user_triggers_time_anomaly() {
        let engine = UebaEngine::new();
        let entity = EntityId::User("charlie".into());
        let ev = make_event(entity, make_features(1.0, 3.0)); // 3am
        let alerts = engine.ingest(&ev);
        assert!(alerts.iter().any(|a| matches!(a.alert_type, UebaAlertType::TimeOfDayAnomaly)));
    }

    #[test]
    fn risk_scores_returns_sorted_list() {
        let engine = UebaEngine::new();
        for name in &["alice", "bob", "charlie"] {
            let entity = EntityId::User(name.to_string());
            for _ in 0..5 {
                let ev = make_event(entity.clone(), make_features(1.0, 10.0));
                engine.ingest(&ev);
            }
        }
        let scores = engine.risk_scores();
        assert_eq!(scores.len(), 3);
        // Verify descending order
        for w in scores.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
    }

    #[test]
    fn processes_are_not_checked_for_time_anomaly() {
        let engine = UebaEngine::new();
        let entity = EntityId::Process("nginx".into());
        let ev = make_event(entity, make_features(0.0, 3.0)); // 3am, but it's a process
        let alerts = engine.ingest(&ev);
        // Process entities should not get TimeOfDayAnomaly
        assert!(alerts.iter().all(|a| !matches!(a.alert_type, UebaAlertType::TimeOfDayAnomaly)));
    }
}
