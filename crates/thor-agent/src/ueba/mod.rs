//! UEBA — User and Entity Behavior Analytics
//! Builds a statistical baseline for every IP/user/process,
//! then scores deviations in real-time using Z-score analysis.
//!
//! This is the core Darktrace-style "self-learning" capability:
//! the system learns what "normal" looks like and flags anomalies
//! without needing predefined rules.
//!
//! Metrics tracked per entity:
//!   - Bytes per minute (upload/download)
//!   - Connections per minute
//!   - Unique destination IPs per hour
//!   - Unique ports accessed per hour
//!   - Failed auth attempts per hour
//!   - Active hours (time-of-day pattern)

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

// ─── Config ───────────────────────────────────────────────────────────────────

const WINDOW_MINUTES: usize = 60;       // rolling window for baseline
const MIN_SAMPLES: usize = 20;          // min samples before scoring
const ANOMALY_THRESHOLD: f64 = 3.5;    // Z-score above this = anomalous
const CRITICAL_THRESHOLD: f64 = 6.0;   // Z-score above this = critical

// ─── Entity observation ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct TimedSample {
    value: f64,
    ts_unix: u64,
}

#[derive(Debug, Clone, Default)]
struct MetricWindow {
    samples: VecDeque<TimedSample>,
    window_secs: u64,
}

impl MetricWindow {
    fn new(window_secs: u64) -> Self { Self { samples: VecDeque::new(), window_secs } }

    fn add(&mut self, value: f64) {
        let now = now_unix();
        self.prune(now);
        self.samples.push_back(TimedSample { value, ts_unix: now });
    }

    fn prune(&mut self, now: u64) {
        while self.samples.front()
            .map(|s| now.saturating_sub(s.ts_unix) > self.window_secs)
            .unwrap_or(false)
        { self.samples.pop_front(); }
    }

    fn stats(&self) -> Option<(f64, f64)> {
        if self.samples.len() < MIN_SAMPLES { return None; }
        let n = self.samples.len() as f64;
        let mean = self.samples.iter().map(|s| s.value).sum::<f64>() / n;
        let variance = self.samples.iter().map(|s| (s.value - mean).powi(2)).sum::<f64>() / n;
        Some((mean, variance.sqrt()))
    }

    fn z_score(&self, new_value: f64) -> Option<f64> {
        self.stats().map(|(mean, std)| {
            if std < 1e-9 { 0.0 } else { (new_value - mean).abs() / std }
        })
    }

    fn count(&self) -> usize { self.samples.len() }
}

// ─── Entity profile ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct EntityProfile {
    pub entity_id:    String,
    pub entity_type:  EntityType,
    bytes_per_min:    MetricWindow,
    conns_per_min:    MetricWindow,
    unique_dsts_hour: MetricWindow,
    unique_ports_hour: MetricWindow,
    auth_failures:    MetricWindow,
    hour_buckets:     [u32; 24],        // active hour histogram
    pub sample_count: u64,
    pub first_seen:   u64,
    pub last_seen:    u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntityType { Ip, User, Process, Host }

impl EntityProfile {
    pub fn new(entity_id: String, entity_type: EntityType) -> Self {
        let now = now_unix();
        let w = WINDOW_MINUTES as u64 * 60;
        Self {
            entity_id,
            entity_type,
            bytes_per_min:    MetricWindow::new(60),
            conns_per_min:    MetricWindow::new(60),
            unique_dsts_hour: MetricWindow::new(3600),
            unique_ports_hour: MetricWindow::new(3600),
            auth_failures:    MetricWindow::new(3600),
            hour_buckets:     [0u32; 24],
            sample_count:     0,
            first_seen:       now,
            last_seen:        now,
        }
    }

    pub fn observe(&mut self, event: &EntityEvent) {
        let now = now_unix();
        self.last_seen = now;
        self.sample_count += 1;

        let hour = ((now % 86400) / 3600) as usize;
        self.hour_buckets[hour] = self.hour_buckets[hour].saturating_add(1);

        self.bytes_per_min.add(event.bytes as f64);
        self.conns_per_min.add(1.0);
        self.unique_dsts_hour.add(event.unique_dsts as f64);
        self.unique_ports_hour.add(event.unique_ports as f64);
        self.auth_failures.add(event.auth_failures as f64);
    }

    /// Score this observation against the entity's baseline.
    pub fn anomaly_score(&mut self, event: &EntityEvent) -> AnomalyScore {
        self.observe(event);

        let byte_z    = self.bytes_per_min.z_score(event.bytes as f64);
        let conn_z    = self.conns_per_min.z_score(1.0);
        let dst_z     = self.unique_dsts_hour.z_score(event.unique_dsts as f64);
        let port_z    = self.unique_ports_hour.z_score(event.unique_ports as f64);
        let auth_z    = self.auth_failures.z_score(event.auth_failures as f64);

        let scores = [byte_z, conn_z, dst_z, port_z, auth_z];
        let max_z = scores.iter()
            .filter_map(|s| *s)
            .fold(0.0_f64, f64::max);

        let reasons = self.build_reasons(byte_z, conn_z, dst_z, port_z, auth_z);
        let is_anomalous = max_z >= ANOMALY_THRESHOLD;
        let is_critical  = max_z >= CRITICAL_THRESHOLD;
        let baseline_mature = self.sample_count >= MIN_SAMPLES as u64;

        AnomalyScore {
            entity_id: self.entity_id.clone(),
            entity_type: format!("{:?}", self.entity_type),
            max_z_score: max_z,
            is_anomalous: is_anomalous && baseline_mature,
            is_critical:  is_critical  && baseline_mature,
            baseline_samples: self.sample_count,
            baseline_mature,
            reasons,
        }
    }

    fn build_reasons(
        &self, byte_z: Option<f64>, conn_z: Option<f64>, dst_z: Option<f64>,
        port_z: Option<f64>, auth_z: Option<f64>,
    ) -> Vec<String> {
        let mut r = Vec::new();
        let check = |z: Option<f64>, msg: &str| -> Option<String> {
            z.filter(|&v| v >= ANOMALY_THRESHOLD).map(|v| format!("{msg} (Z={v:.1})"))
        };
        if let Some(s) = check(byte_z,  "Abnormal data volume") { r.push(s); }
        if let Some(s) = check(conn_z,  "Abnormal connection rate") { r.push(s); }
        if let Some(s) = check(dst_z,   "Unusually many unique destinations") { r.push(s); }
        if let Some(s) = check(port_z,  "Unusually many unique ports (possible scan)") { r.push(s); }
        if let Some(s) = check(auth_z,  "Abnormal authentication failures") { r.push(s); }
        r
    }

    pub fn baseline_summary(&self) -> BaselineSummary {
        BaselineSummary {
            entity_id:      self.entity_id.clone(),
            sample_count:   self.sample_count,
            first_seen:     self.first_seen,
            last_seen:      self.last_seen,
            avg_bytes_pm:   self.bytes_per_min.stats().map(|(m,_)| m),
            avg_conns_pm:   self.conns_per_min.stats().map(|(m,_)| m),
            peak_hour:      self.hour_buckets.iter().enumerate()
                .max_by_key(|(_,c)| *c).map(|(h,_)| h as u8),
        }
    }
}

// ─── Event input ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EntityEvent {
    pub entity_id:    String,
    pub entity_type:  EntityType,
    pub bytes:        u64,
    pub unique_dsts:  u32,
    pub unique_ports: u32,
    pub auth_failures: u32,
}

// ─── Anomaly scoring output ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    pub entity_id:       String,
    pub entity_type:     String,
    pub max_z_score:     f64,
    pub is_anomalous:    bool,
    pub is_critical:     bool,
    pub baseline_samples: u64,
    pub baseline_mature: bool,
    pub reasons:         Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSummary {
    pub entity_id:    String,
    pub sample_count: u64,
    pub first_seen:   u64,
    pub last_seen:    u64,
    pub avg_bytes_pm: Option<f64>,
    pub avg_conns_pm: Option<f64>,
    pub peak_hour:    Option<u8>,
}

// ─── UEBA Engine ─────────────────────────────────────────────────────────────

pub struct UebaEngine {
    profiles: DashMap<String, EntityProfile>,
}

impl UebaEngine {
    pub fn new() -> Self {
        info!("🧠 UEBA engine initialized — building behavioral baselines");
        Self { profiles: DashMap::with_capacity(100_000) }
    }

    /// Score an entity event. Returns anomaly score if baseline is mature.
    pub fn observe(&self, event: EntityEvent) -> AnomalyScore {
        let key = format!("{}:{:?}", event.entity_id, event.entity_type);
        let mut profile = self.profiles.entry(key)
            .or_insert_with(|| EntityProfile::new(event.entity_id.clone(), event.entity_type.clone()));
        profile.anomaly_score(&event)
    }

    /// Get baseline summary for a specific entity.
    pub fn baseline(&self, entity_id: &str) -> Option<BaselineSummary> {
        self.profiles.iter()
            .find(|p| p.entity_id == entity_id)
            .map(|p| p.baseline_summary())
    }

    /// Get all entities with mature baselines.
    pub fn all_baselines(&self) -> Vec<BaselineSummary> {
        self.profiles.iter()
            .filter(|p| p.sample_count >= MIN_SAMPLES as u64)
            .map(|p| p.baseline_summary())
            .collect()
    }

    /// Entity count.
    pub fn entity_count(&self) -> usize { self.profiles.len() }

    /// Evict entities not seen in >7 days (prevent memory growth).
    pub fn evict_stale(&self) {
        let cutoff = now_unix().saturating_sub(7 * 86400);
        let before = self.profiles.len();
        self.profiles.retain(|_, p| p.last_seen >= cutoff);
        let evicted = before - self.profiles.len();
        if evicted > 0 { info!("UEBA: evicted {} stale profiles", evicted); }
    }
}

impl Default for UebaEngine { fn default() -> Self { Self::new() } }

pub type SharedUeba = Arc<UebaEngine>;

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(id: &str, bytes: u64) -> EntityEvent {
        EntityEvent { entity_id: id.to_string(), entity_type: EntityType::Ip, bytes, unique_dsts: 1, unique_ports: 1, auth_failures: 0 }
    }

    #[test]
    fn test_baseline_immature_before_min_samples() {
        let engine = UebaEngine::new();
        for i in 0..10 {
            let score = engine.observe(make_event("10.0.0.1", 1000));
            assert!(!score.baseline_mature, "Should not be mature before {} samples", MIN_SAMPLES);
        }
    }

    #[test]
    fn test_baseline_matures_after_samples() {
        let engine = UebaEngine::new();
        for _ in 0..MIN_SAMPLES {
            engine.observe(make_event("10.0.0.2", 1000));
        }
        let score = engine.observe(make_event("10.0.0.2", 1000));
        assert!(score.baseline_mature);
    }

    #[test]
    fn test_massive_spike_triggers_anomaly() {
        let engine = UebaEngine::new();
        // Establish baseline of 1000 bytes/min
        for _ in 0..MIN_SAMPLES + 5 {
            engine.observe(make_event("10.0.0.3", 1000));
        }
        // Sudden 100x spike
        let score = engine.observe(EntityEvent {
            entity_id: "10.0.0.3".to_string(),
            entity_type: EntityType::Ip,
            bytes: 100_000,
            unique_dsts: 1, unique_ports: 1, auth_failures: 0,
        });
        assert!(score.baseline_mature);
        assert!(score.is_anomalous || score.max_z_score > 2.0,
                "Spike should show elevated Z-score, got {}", score.max_z_score);
    }

    #[test]
    fn test_separate_entities_independent_baselines() {
        let engine = UebaEngine::new();
        for _ in 0..MIN_SAMPLES { engine.observe(make_event("10.0.0.10", 500)); }
        for _ in 0..MIN_SAMPLES { engine.observe(make_event("10.0.0.11", 50_000)); }
        assert_eq!(engine.entity_count(), 2);
    }
}
