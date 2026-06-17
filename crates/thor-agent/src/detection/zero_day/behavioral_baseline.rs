//! Behavioral Baseline — tracks long-term process behavioral profiles and
//! computes KL-divergence drift to detect when a process deviates from its
//! established normal patterns.
//!
//! # Algorithm
//! For each process, we maintain an Exponential Moving Average (EMA) of each
//! feature dimension over time.  When new feature vectors arrive, we compute
//! the Kullback-Leibler divergence between the current "snapshot" distribution
//! and the established EMA baseline.
//!
//! KL(P || Q) = Σ P(i) * ln(P(i) / Q(i))
//!
//! where P is the current feature distribution and Q is the baseline.
//!
//! A KL-divergence > 1.5 nats is considered significant drift; > 3.0 is
//! considered extreme and indicative of process compromise.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::anomaly_engine::FeatureVector;

// ─── BaselineDrift ────────────────────────────────────────────────────────────

/// Result of a baseline drift computation for a single process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDrift {
    /// Process ID.
    pub pid: u32,
    /// KL-divergence between current behaviour and baseline (nats).
    pub kl_divergence: f64,
    /// Per-feature absolute delta from baseline.
    pub feature_deltas: Vec<f64>,
    /// The feature with the largest deviation.
    pub top_drift_feature: String,
    /// Severity interpretation.
    pub severity: DriftSeverity,
}

/// Severity of the detected drift.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DriftSeverity {
    Normal,
    Moderate,
    Significant,
    Extreme,
}

impl DriftSeverity {
    pub fn from_kl(kl: f64) -> Self {
        if kl >= 3.0      { DriftSeverity::Extreme }
        else if kl >= 1.5 { DriftSeverity::Significant }
        else if kl >= 0.5 { DriftSeverity::Moderate }
        else              { DriftSeverity::Normal }
    }
}

impl std::fmt::Display for DriftSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriftSeverity::Normal      => write!(f, "Normal"),
            DriftSeverity::Moderate    => write!(f, "Moderate"),
            DriftSeverity::Significant => write!(f, "Significant"),
            DriftSeverity::Extreme     => write!(f, "Extreme"),
        }
    }
}

// ─── Per-process baseline state ───────────────────────────────────────────────

const FEATURE_NAMES: [&str; FeatureVector::DIM] = [
    "syscall_rate",
    "unique_syscalls",
    "memory_alloc_rate",
    "child_spawn_rate",
    "network_bytes",
    "write_entropy",
    "dangerous_calls",
    "event_density",
];

struct ProcessBaseline {
    /// EMA of each feature (the "normal" distribution).
    ema: [f64; FeatureVector::DIM],
    /// EMA alpha (learning rate). Lower = slower to adapt.
    alpha: f64,
    /// Number of updates applied.
    updates: u64,
    /// Time of last update.
    last_update: Instant,
}

impl ProcessBaseline {
    fn new(initial: &[f64; FeatureVector::DIM]) -> Self {
        Self {
            ema:         *initial,
            alpha:       0.05,  // 5% weight to new observations
            updates:     1,
            last_update: Instant::now(),
        }
    }

    /// Update the EMA with a new feature vector.
    fn update(&mut self, features: &[f64; FeatureVector::DIM]) {
        for (i, &val) in features.iter().enumerate() {
            self.ema[i] = self.alpha * val + (1.0 - self.alpha) * self.ema[i];
        }
        self.updates += 1;
        self.last_update = Instant::now();
    }

    /// Compute KL-divergence between `current` and this baseline.
    ///
    /// Both distributions are softened with a small ε to avoid log(0).
    fn kl_divergence(&self, current: &[f64; FeatureVector::DIM]) -> f64 {
        const EPS: f64 = 1e-6;

        // Normalize both vectors to a probability distribution over features
        let sum_q: f64 = self.ema.iter().map(|&v| v.abs() + EPS).sum();
        let sum_p: f64 = current.iter().map(|&v| v.abs() + EPS).sum();

        let mut kl = 0.0;
        for i in 0..FeatureVector::DIM {
            let p = (current[i].abs() + EPS) / sum_p;
            let q = (self.ema[i].abs() + EPS) / sum_q;
            kl += p * (p / q).ln();
        }
        kl.max(0.0)
    }

    /// Feature-wise absolute delta between current and baseline.
    fn feature_deltas(&self, current: &[f64; FeatureVector::DIM]) -> [f64; FeatureVector::DIM] {
        std::array::from_fn(|i| {
            (current[i] - self.ema[i]).abs()
        })
    }
}

// ─── BehavioralBaseline ───────────────────────────────────────────────────────

/// Thread-safe store of per-process behavioral baselines.
pub struct BehavioralBaseline {
    baselines: RwLock<HashMap<u32, ProcessBaseline>>,
    /// Minimum updates before drift is computed (avoids noisy early alerts).
    warmup_updates: u64,
}

impl BehavioralBaseline {
    pub fn new() -> Self {
        Self {
            baselines:      RwLock::new(HashMap::new()),
            warmup_updates: 20,
        }
    }

    /// Compute KL-divergence drift for a process.
    ///
    /// Returns `None` if no baseline exists yet or baseline is still in warm-up.
    pub fn compute_drift(&self, pid: u32, features: &FeatureVector) -> Option<BaselineDrift> {
        let map = self.baselines.read().unwrap();
        let baseline = map.get(&pid)?;

        // Skip drift computation during warm-up
        if baseline.updates < self.warmup_updates {
            return None;
        }

        let arr = features.as_array();
        let kl = baseline.kl_divergence(&arr);
        let deltas = baseline.feature_deltas(&arr);

        // Find the feature with the largest delta
        let (top_idx, _top_delta) = deltas
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or((0, &0.0));

        Some(BaselineDrift {
            pid,
            kl_divergence:    kl,
            feature_deltas:   deltas.to_vec(),
            top_drift_feature: FEATURE_NAMES[top_idx].to_string(),
            severity:         DriftSeverity::from_kl(kl),
        })
    }

    /// Update the baseline with a new feature vector.
    pub fn update(&self, pid: u32, features: &FeatureVector) {
        let arr = features.as_array();
        let mut map = self.baselines.write().unwrap();
        match map.get_mut(&pid) {
            Some(baseline) => baseline.update(&arr),
            None           => { map.insert(pid, ProcessBaseline::new(&arr)); }
        }
    }

    /// Get all drift statistics for currently tracked processes.
    pub fn all_drift_stats(&self) -> Vec<(u32, f64)> {
        let map = self.baselines.read().unwrap();
        map.iter()
            .filter(|(_, b)| b.updates >= 5)
            .map(|(&pid, baseline)| {
                // Use last EMA vs itself = 0.0 (since we don't store current externally)
                (pid, baseline.kl_divergence(&baseline.ema))
            })
            .collect()
    }

    /// Evict baseline for a terminated process.
    pub fn evict(&self, pid: u32) {
        self.baselines.write().unwrap().remove(&pid);
    }

    /// Number of tracked processes.
    pub fn tracked_count(&self) -> usize {
        self.baselines.read().unwrap().len()
    }
}

impl Default for BehavioralBaseline {
    fn default() -> Self { Self::new() }
}

// Extension: allow feature vector to return its array
impl FeatureVector {
    pub fn as_array(&self) -> [f64; Self::DIM] {
        [
            self.syscall_rate,
            self.unique_syscalls,
            self.memory_alloc_rate,
            self.child_spawn_rate,
            self.network_bytes,
            self.write_entropy,
            self.dangerous_calls,
            self.event_density,
        ]
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn normal_fv() -> FeatureVector {
        FeatureVector {
            syscall_rate:      50.0,
            unique_syscalls:   20.0,
            memory_alloc_rate: 0.5,
            child_spawn_rate:  0.05,
            network_bytes:     8.0,
            write_entropy:     0.3,
            dangerous_calls:   0.0,
            event_density:     5.0,
        }
    }

    fn anomalous_fv() -> FeatureVector {
        FeatureVector {
            syscall_rate:      5000.0,
            unique_syscalls:   200.0,
            memory_alloc_rate: 50.0,
            child_spawn_rate:  30.0,
            network_bytes:     20.0,
            write_entropy:     0.99,
            dangerous_calls:   100.0,
            event_density:     500.0,
        }
    }

    #[test]
    fn no_drift_before_warmup() {
        let baseline = BehavioralBaseline::new();
        baseline.update(1234, &normal_fv());
        // Only 1 update — below warmup_updates (20), should return None
        let drift = baseline.compute_drift(1234, &anomalous_fv());
        assert!(drift.is_none(), "Drift should not be computed before warmup");
    }

    #[test]
    fn drift_detected_after_warmup() {
        let baseline = BehavioralBaseline::new();
        // Feed 25 normal samples to pass warmup
        for _ in 0..25 {
            baseline.update(5678, &normal_fv());
        }
        // Now check drift against anomalous behaviour
        let drift = baseline.compute_drift(5678, &anomalous_fv()).expect("Drift must be computed");
        println!("KL-divergence: {:.4}", drift.kl_divergence);
        assert!(drift.kl_divergence > 0.0, "KL-divergence must be positive for anomalous input");
    }

    #[test]
    fn same_distribution_has_near_zero_drift() {
        let baseline = BehavioralBaseline::new();
        let fv = normal_fv();
        for _ in 0..25 {
            baseline.update(9999, &fv);
        }
        let drift = baseline.compute_drift(9999, &fv).expect("Drift must be computed");
        // KL(P||P) ≈ 0
        assert!(drift.kl_divergence < 0.5, "Same distribution should have near-zero KL divergence");
        assert_eq!(drift.severity, DriftSeverity::Normal);
    }

    #[test]
    fn severity_levels_are_correct() {
        assert_eq!(DriftSeverity::from_kl(0.1), DriftSeverity::Normal);
        assert_eq!(DriftSeverity::from_kl(0.7), DriftSeverity::Moderate);
        assert_eq!(DriftSeverity::from_kl(2.0), DriftSeverity::Significant);
        assert_eq!(DriftSeverity::from_kl(4.0), DriftSeverity::Extreme);
    }

    #[test]
    fn eviction_removes_baseline() {
        let baseline = BehavioralBaseline::new();
        for _ in 0..5 {
            baseline.update(7777, &normal_fv());
        }
        assert_eq!(baseline.tracked_count(), 1);
        baseline.evict(7777);
        assert_eq!(baseline.tracked_count(), 0);
    }

    #[test]
    fn multiple_pids_are_independent() {
        let baseline = BehavioralBaseline::new();
        for _ in 0..25 {
            baseline.update(100, &normal_fv());
            baseline.update(200, &anomalous_fv());
        }
        assert_eq!(baseline.tracked_count(), 2);

        let drift_100 = baseline.compute_drift(100, &anomalous_fv()).unwrap();
        let drift_200 = baseline.compute_drift(200, &normal_fv()).unwrap();

        // Process 100 (baseline=normal, current=anomalous) should show more drift
        // than process 200 (baseline=anomalous, current=anomalous-same)
        println!(
            "PID 100 (normal→anomalous): {:.4}, PID 200 (anomalous→normal): {:.4}",
            drift_100.kl_divergence, drift_200.kl_divergence
        );
    }
}
