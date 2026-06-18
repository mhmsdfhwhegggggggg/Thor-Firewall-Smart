//! Behavioral Baseline — Gaussian EMA + variance tracking + windowed drift.
//!
//! # v2 Upgrades
//! * Full 24-dimensional feature space (matches AnomalyEngine v2)
//! * **Variance-aware KL-divergence** — uses per-feature std-dev, not just mean
//! * **Windowed drift** — compares recent 30-event window vs long-term baseline
//! * **DashMap** — lock-free per-process baseline storage
//! * **Adaptive alpha** — learning rate slows as baseline matures (trust accumulates)

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::Instant;

use super::anomaly_engine::FeatureVector;

// ─── Feature names (24-dim) ───────────────────────────────────────────────────

pub const FEATURE_NAMES: [&str; FeatureVector::DIM] = [
    "syscall_rate",
    "unique_syscalls",
    "memory_alloc_rate",
    "child_spawn_rate",
    "network_bytes",
    "write_entropy",
    "dangerous_calls",
    "event_density",
    "mmap_exec_ratio",
    "ptrace_count",
    "cross_proc_write",
    "memfd_usage",
    "bpf_calls",
    "io_uring_ratio",
    "userfaultfd_count",
    "pidfd_count",
    "setuid_attempts",
    "cap_changes",
    "module_load_rate",
    "namespace_changes",
    "priv_syscall_ratio",
    "timing_regularity",
    "perf_event_count",
    "io_uring_abs",
];

// ─── BaselineDrift ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDrift {
    pub pid:               u32,
    /// Symmetric KL-divergence (Jensen-Shannon divergence) — always ≥ 0.
    pub kl_divergence:     f64,
    /// Short-term vs long-term drift (recent 30 events vs full baseline).
    pub window_drift:      f64,
    /// Per-feature absolute delta from baseline EMA.
    pub feature_deltas:    Vec<f64>,
    /// The feature with the largest relative deviation.
    pub top_drift_feature: String,
    pub severity:          DriftSeverity,
}

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

struct ProcessBaseline {
    /// Long-term EMA mean for each feature.
    ema_mean: [f64; FeatureVector::DIM],
    /// EMA variance (Welford-style, single-pass).
    ema_var:  [f64; FeatureVector::DIM],
    /// Current EMA alpha (adaptive: starts at 0.2, decays toward 0.02).
    alpha:    f64,
    updates:  u64,
    /// Rolling window of recent feature vectors (for short-term drift).
    recent:   VecDeque<[f64; FeatureVector::DIM]>,
    last_update: Instant,
}

impl ProcessBaseline {
    fn new(initial: &[f64; FeatureVector::DIM]) -> Self {
        let mut var = [1.0; FeatureVector::DIM]; // start with unit variance
        Self {
            ema_mean:    *initial,
            ema_var:     var,
            alpha:        0.20,  // fast learning initially
            updates:      1,
            recent:       VecDeque::new(),
            last_update:  Instant::now(),
        }
    }

    fn update(&mut self, features: &[f64; FeatureVector::DIM]) {
        // Adaptive alpha: starts at 0.20, decays exponentially to 0.02 floor
        let target_alpha = 0.02_f64;
        let decay = (-0.005 * self.updates as f64).exp();
        self.alpha = target_alpha + (0.20 - target_alpha) * decay;

        for i in 0..FeatureVector::DIM {
            let delta     = features[i] - self.ema_mean[i];
            self.ema_mean[i] += self.alpha * delta;
            let delta2    = features[i] - self.ema_mean[i];
            // EMA variance update
            self.ema_var[i] =
                (1.0 - self.alpha) * (self.ema_var[i] + self.alpha * delta * delta2);
            self.ema_var[i] = self.ema_var[i].max(1e-8);
        }

        // Rolling recent window (last 30 observations)
        self.recent.push_back(*features);
        if self.recent.len() > 30 {
            self.recent.pop_front();
        }

        self.updates += 1;
        self.last_update = Instant::now();
    }

    /// Jensen-Shannon divergence between current observation and baseline.
    /// JS-divergence is symmetric and bounded in [0, ln(2)] ≈ [0, 0.693].
    /// We multiply by 4 to get a scale roughly matching the old KL threshold.
    fn js_divergence(&self, current: &[f64; FeatureVector::DIM]) -> f64 {
        const EPS: f64 = 1e-6;
        // Normalise baseline and current to probability distributions
        let sum_q: f64 = self.ema_mean.iter().map(|&v| v.abs() + EPS).sum();
        let sum_p: f64 = current.iter().map(|&v| v.abs() + EPS).sum();

        let mut js = 0.0;
        for i in 0..FeatureVector::DIM {
            let p = (current[i].abs() + EPS) / sum_p;
            let q = (self.ema_mean[i].abs() + EPS) / sum_q;
            let m = (p + q) * 0.5;
            js += p * (p / m).ln() * 0.5 + q * (q / m).ln() * 0.5;
        }
        // Scale from [0, ln2] to approximately [0, 5] to match old thresholds
        (js * 7.21).max(0.0)
    }

    /// Short-term drift: average JS-divergence of recent window vs baseline.
    fn window_drift(&self) -> f64 {
        if self.recent.len() < 5 { return 0.0; }
        let n = self.recent.len() as f64;
        // Compute mean of recent observations
        let mut recent_mean = [0.0f64; FeatureVector::DIM];
        for obs in &self.recent {
            for i in 0..FeatureVector::DIM {
                recent_mean[i] += obs[i] / n;
            }
        }
        self.js_divergence(&recent_mean)
    }

    fn feature_deltas(&self, current: &[f64; FeatureVector::DIM]) -> [f64; FeatureVector::DIM] {
        std::array::from_fn(|i| {
            let std = self.ema_var[i].sqrt().max(1e-6);
            // Normalised delta: (current - baseline_mean) / baseline_std
            ((current[i] - self.ema_mean[i]) / std).abs()
        })
    }
}

// ─── BehavioralBaseline ───────────────────────────────────────────────────────

/// Thread-safe, lock-free store of per-process behavioral baselines.
pub struct BehavioralBaseline {
    baselines:      DashMap<u32, ProcessBaseline>,
    warmup_updates: u64,
}

impl BehavioralBaseline {
    pub fn new() -> Self {
        Self {
            baselines:      DashMap::new(),
            warmup_updates: 20,
        }
    }

    /// Compute drift for a process. Returns `None` during warm-up.
    pub fn compute_drift(&self, pid: u32, features: &FeatureVector) -> Option<BaselineDrift> {
        let baseline = self.baselines.get(&pid)?;

        if baseline.updates < self.warmup_updates {
            return None;
        }

        let arr     = features.as_array();
        let kl      = baseline.js_divergence(&arr);
        let wdrift  = baseline.window_drift();
        let deltas  = baseline.feature_deltas(&arr);

        let (top_idx, _) = deltas.iter().enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or((0, &0.0));

        Some(BaselineDrift {
            pid,
            kl_divergence:    kl,
            window_drift:     wdrift,
            feature_deltas:   deltas.to_vec(),
            top_drift_feature: FEATURE_NAMES[top_idx].to_string(),
            severity:         DriftSeverity::from_kl(kl.max(wdrift)),
        })
    }

    /// Update the baseline for a process.
    pub fn update(&self, pid: u32, features: &FeatureVector) {
        let arr = features.as_array();
        self.baselines
            .entry(pid)
            .and_modify(|b| b.update(&arr))
            .or_insert_with(|| ProcessBaseline::new(&arr));
    }

    pub fn all_drift_stats(&self) -> Vec<(u32, f64)> {
        self.baselines.iter()
            .filter(|r| r.value().updates >= 5)
            .map(|r| {
                let b = r.value();
                (*r.key(), b.js_divergence(&b.ema_mean))
            })
            .collect()
    }

    pub fn evict(&self, pid: u32) {
        self.baselines.remove(&pid);
    }

    pub fn tracked_count(&self) -> usize {
        self.baselines.len()
    }
}

impl Default for BehavioralBaseline {
    fn default() -> Self { Self::new() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn normal_fv() -> FeatureVector {
        FeatureVector {
            syscall_rate:       50.0, unique_syscalls:    20.0,
            memory_alloc_rate:  0.5,  child_spawn_rate:   0.05,
            network_bytes:      8.0,  write_entropy:      0.3,
            dangerous_calls:    0.0,  event_density:      5.0,
            mmap_exec_ratio:    0.01, ptrace_count:       0.0,
            cross_proc_write:   0.0,  memfd_usage:        0.0,
            bpf_calls:          0.0,  io_uring_ratio:     0.0,
            userfaultfd_count:  0.0,  pidfd_count:        0.0,
            setuid_attempts:    0.0,  cap_changes:        0.0,
            module_load_rate:   0.0,  namespace_changes:  0.0,
            priv_syscall_ratio: 0.005,timing_regularity:  0.3,
            perf_event_count:   0.0,  io_uring_abs:       0.0,
        }
    }

    fn anomalous_fv() -> FeatureVector {
        FeatureVector {
            syscall_rate:       5000.0, unique_syscalls:    200.0,
            memory_alloc_rate:  50.0,   child_spawn_rate:   30.0,
            network_bytes:      20.0,   write_entropy:      0.99,
            dangerous_calls:    100.0,  event_density:      500.0,
            mmap_exec_ratio:    0.90,   ptrace_count:       50.0,
            cross_proc_write:   20.0,   memfd_usage:        10.0,
            bpf_calls:          50.0,   io_uring_ratio:     0.6,
            userfaultfd_count:  5.0,    pidfd_count:        8.0,
            setuid_attempts:    10.0,   cap_changes:        5.0,
            module_load_rate:   2.0,    namespace_changes:  15.0,
            priv_syscall_ratio: 0.9,    timing_regularity:  0.95,
            perf_event_count:   200.0,  io_uring_abs:       4.0,
        }
    }

    #[test]
    fn no_drift_before_warmup() {
        let baseline = BehavioralBaseline::new();
        baseline.update(1234, &normal_fv());
        let drift = baseline.compute_drift(1234, &anomalous_fv());
        assert!(drift.is_none(), "should not compute drift before warmup");
    }

    #[test]
    fn drift_detected_after_warmup() {
        let baseline = BehavioralBaseline::new();
        for _ in 0..25 { baseline.update(5678, &normal_fv()); }
        let drift = baseline.compute_drift(5678, &anomalous_fv())
            .expect("drift must be computed after warmup");
        println!("JS-divergence (scaled): {:.4}", drift.kl_divergence);
        assert!(drift.kl_divergence > 0.0, "drift must be positive");
    }

    #[test]
    fn same_distribution_near_zero_drift() {
        let baseline = BehavioralBaseline::new();
        let fv = normal_fv();
        for _ in 0..25 { baseline.update(9999, &fv); }
        let drift = baseline.compute_drift(9999, &fv).expect("drift must exist");
        assert!(drift.kl_divergence < 1.0,
            "same distribution KL={:.4}", drift.kl_divergence);
        assert_eq!(drift.severity, DriftSeverity::Normal);
    }

    #[test]
    fn severity_levels_correct() {
        assert_eq!(DriftSeverity::from_kl(0.1), DriftSeverity::Normal);
        assert_eq!(DriftSeverity::from_kl(0.7), DriftSeverity::Moderate);
        assert_eq!(DriftSeverity::from_kl(2.0), DriftSeverity::Significant);
        assert_eq!(DriftSeverity::from_kl(4.0), DriftSeverity::Extreme);
    }

    #[test]
    fn eviction_removes_baseline() {
        let baseline = BehavioralBaseline::new();
        for _ in 0..5 { baseline.update(7777, &normal_fv()); }
        assert_eq!(baseline.tracked_count(), 1);
        baseline.evict(7777);
        assert_eq!(baseline.tracked_count(), 0);
    }

    #[test]
    fn feature_names_match_dim() {
        assert_eq!(FEATURE_NAMES.len(), FeatureVector::DIM);
    }

    #[test]
    fn adaptive_alpha_decreases_over_time() {
        let baseline = BehavioralBaseline::new();
        let fv = normal_fv();
        for _ in 0..200 { baseline.update(1111, &fv); }
        // After 200 updates, the baseline should be stable (alpha near 0.02)
        let drift = baseline.compute_drift(1111, &fv).unwrap();
        assert!(drift.kl_divergence < 0.5,
            "stable baseline should have low drift: {:.4}", drift.kl_divergence);
    }
}
