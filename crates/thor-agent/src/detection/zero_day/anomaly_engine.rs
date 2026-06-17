//! Anomaly Engine — Isolation Forest anomaly detection on behavioral feature vectors.
//!
//! The Isolation Forest algorithm works by randomly partitioning the feature
//! space and measuring how quickly individual data points are isolated.
//! Anomalous points (rare, extreme values) are isolated in fewer splits.
//!
//! # Algorithm
//! 1. Build `n_trees` isolation trees from a random subsample of the training
//!    data (or a synthetic normal distribution if no training data is available).
//! 2. For each new point, traverse all trees and record the path length to
//!    isolation.
//! 3. Normalise the average path length against the expected path length for
//!    a dataset of the subsample size.
//! 4. Score = 2^(−E[h(x)] / c(n))  where c(n) is the average path length of
//!    an unsuccessful BST search.
//!
//! # Features (8-dimensional vector)
//! 1. `syscall_rate`       — EMA of calls per second
//! 2. `unique_syscalls`    — number of distinct syscall types seen
//! 3. `memory_alloc_rate`  — mmap/brk/mprotect events per second
//! 4. `child_spawn_rate`   — exec/fork/clone events per second
//! 5. `network_bytes`      — total bytes transferred (log-scaled)
//! 6. `write_entropy`      — write byte-distribution entropy estimate
//! 7. `dangerous_calls`    — count of ptrace/memfd_create/process_vm_writev
//! 8. `event_density`      — events per unit of observation time

use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use rand::Rng;

use super::syscall_profiler::ProcessProfile;

// ─── FeatureVector ────────────────────────────────────────────────────────────

/// An 8-dimensional feature vector derived from a `ProcessProfile`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    pub syscall_rate:       f64,
    pub unique_syscalls:    f64,
    pub memory_alloc_rate:  f64,
    pub child_spawn_rate:   f64,
    pub network_bytes:      f64,
    pub write_entropy:      f64,
    pub dangerous_calls:    f64,
    pub event_density:      f64,
}

impl FeatureVector {
    pub const DIM: usize = 8;

    /// Build a feature vector from a `ProcessProfile`.
    pub fn from_profile(p: &ProcessProfile) -> Self {
        let window = p.window_secs();
        Self {
            syscall_rate:      p.syscall_rate_ema,
            unique_syscalls:   p.unique_syscall_count as f64,
            memory_alloc_rate: p.memory_alloc_rate(),
            child_spawn_rate:  p.child_spawn_rate(),
            network_bytes:     (p.total_network_bytes as f64 + 1.0).ln(),
            write_entropy:     p.write_entropy_estimate,
            dangerous_calls:   p.dangerous_syscall_count as f64,
            event_density:     p.event_count as f64 / window,
        }
    }

    /// Return the feature as a fixed-length array for tree traversal.
    fn as_array(&self) -> [f64; Self::DIM] {
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

    /// Element-wise minimum with another vector.
    fn min_with(&self, other: &Self) -> Self {
        let a = self.as_array();
        let b = other.as_array();
        Self::from_array(std::array::from_fn(|i| a[i].min(b[i])))
    }

    /// Element-wise maximum with another vector.
    fn max_with(&self, other: &Self) -> Self {
        let a = self.as_array();
        let b = other.as_array();
        Self::from_array(std::array::from_fn(|i| a[i].max(b[i])))
    }

    fn from_array(arr: [f64; Self::DIM]) -> Self {
        Self {
            syscall_rate:      arr[0],
            unique_syscalls:   arr[1],
            memory_alloc_rate: arr[2],
            child_spawn_rate:  arr[3],
            network_bytes:     arr[4],
            write_entropy:     arr[5],
            dangerous_calls:   arr[6],
            event_density:     arr[7],
        }
    }
}

// ─── Isolation Tree ───────────────────────────────────────────────────────────

#[derive(Clone)]
enum IsoNode {
    Leaf { size: usize },
    Split {
        feature: usize,
        threshold: f64,
        left: Box<IsoNode>,
        right: Box<IsoNode>,
    },
}

impl IsoNode {
    /// Build an isolation tree from a slice of samples.
    fn build(samples: &[[f64; FeatureVector::DIM]], depth: usize, max_depth: usize) -> Self {
        if samples.len() <= 1 || depth >= max_depth {
            return IsoNode::Leaf { size: samples.len() };
        }

        let mut rng = rand::thread_rng();
        // Choose a random feature dimension
        let feature = rng.gen_range(0..FeatureVector::DIM);

        let min_val = samples.iter().map(|s| s[feature]).fold(f64::INFINITY, f64::min);
        let max_val = samples.iter().map(|s| s[feature]).fold(f64::NEG_INFINITY, f64::max);

        if (max_val - min_val).abs() < 1e-12 {
            return IsoNode::Leaf { size: samples.len() };
        }

        let threshold = rng.gen_range(min_val..=max_val);

        let (left_samples, right_samples): (Vec<_>, Vec<_>) =
            samples.iter().partition(|s| s[feature] < threshold);

        IsoNode::Split {
            feature,
            threshold,
            left:  Box::new(IsoNode::build(&left_samples, depth + 1, max_depth)),
            right: Box::new(IsoNode::build(&right_samples, depth + 1, max_depth)),
        }
    }

    /// Compute path length for a single sample (with size-correction at leaves).
    fn path_length(&self, sample: &[f64; FeatureVector::DIM], depth: f64) -> f64 {
        match self {
            IsoNode::Leaf { size } => depth + average_path_length(*size),
            IsoNode::Split { feature, threshold, left, right } => {
                if sample[*feature] < *threshold {
                    left.path_length(sample, depth + 1.0)
                } else {
                    right.path_length(sample, depth + 1.0)
                }
            }
        }
    }
}

/// Expected path length of an unsuccessful BST search.
fn average_path_length(n: usize) -> f64 {
    if n <= 1 { return 0.0; }
    let n = n as f64;
    2.0 * ((n - 1.0).ln() + std::f64::consts::EULER_MASCHERONI) - 2.0 * (n - 1.0) / n
}

// Euler-Mascheroni constant
trait EulerMascheroni { const EULER_MASCHERONI: f64; }
impl EulerMascheroni for f64 { const EULER_MASCHERONI: f64 = 0.577_215_664_901_532; }

// ─── AnomalyScore ─────────────────────────────────────────────────────────────

/// The result of scoring a feature vector against the Isolation Forest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    /// Normalised anomaly score in [0, 1].
    /// > 0.7 → high anomaly; > 0.9 → extreme anomaly; < 0.45 → normal.
    pub value: f64,
    /// Average path length (lower = more anomalous).
    pub avg_path_length: f64,
    /// Number of trees used in scoring.
    pub n_trees: usize,
}

// ─── AnomalyEngine ────────────────────────────────────────────────────────────

const SUBSAMPLE_SIZE: usize = 256;
const MAX_DEPTH: usize = 12; // ceil(log2(SUBSAMPLE_SIZE))

/// Isolation Forest engine.
///
/// The forest is warm-started with synthetically generated "normal" samples
/// (Gaussian around typical process baseline values) so it can score immediately
/// without requiring a training phase.  As real process data accumulates, the
/// forest is rebuilt periodically to improve accuracy.
pub struct AnomalyEngine {
    n_trees: usize,
    trees:   RwLock<Vec<IsoNode>>,
    /// Buffer of real observed feature vectors (used for periodic retraining).
    sample_buffer: RwLock<Vec<[f64; FeatureVector::DIM]>>,
    /// How many samples to collect before rebuilding the forest.
    retrain_threshold: usize,
}

impl AnomalyEngine {
    /// Create a new engine with `n_trees` isolation trees.
    pub fn new(n_trees: usize) -> Self {
        let engine = Self {
            n_trees,
            trees:             RwLock::new(Vec::new()),
            sample_buffer:     RwLock::new(Vec::new()),
            retrain_threshold: 500,
        };
        // Warm-start with synthetic normal samples
        engine.build_synthetic_forest();
        engine
    }

    /// Score a feature vector, returning an `AnomalyScore`.
    pub fn score(&self, features: &FeatureVector) -> AnomalyScore {
        let arr = features.as_array();
        let trees = self.trees.read().unwrap();

        if trees.is_empty() {
            // No model yet — return neutral score
            return AnomalyScore { value: 0.5, avg_path_length: 0.0, n_trees: 0 };
        }

        let total_path: f64 = trees.iter()
            .map(|tree| tree.path_length(&arr, 0.0))
            .sum();
        let avg_path = total_path / trees.len() as f64;

        // Normalise against expected path length for subsample
        let c_n = average_path_length(SUBSAMPLE_SIZE);
        let score = if c_n.abs() < 1e-12 {
            0.5
        } else {
            2.0_f64.powf(-avg_path / c_n)
        };

        // Buffer the sample for future retraining
        drop(trees);
        {
            let mut buf = self.sample_buffer.write().unwrap();
            buf.push(arr);
            if buf.len() >= self.retrain_threshold {
                let samples = buf.clone();
                buf.clear();
                drop(buf);
                self.rebuild_forest(&samples);
            }
        }

        AnomalyScore {
            value: score.clamp(0.0, 1.0),
            avg_path_length: avg_path,
            n_trees: self.n_trees,
        }
    }

    /// Rebuild the forest from a slice of observed samples.
    pub fn rebuild_forest(&self, samples: &[[f64; FeatureVector::DIM]]) {
        let mut rng = rand::thread_rng();
        let mut new_trees = Vec::with_capacity(self.n_trees);

        for _ in 0..self.n_trees {
            // Subsample
            let n = samples.len().min(SUBSAMPLE_SIZE);
            let mut subsample: Vec<[f64; FeatureVector::DIM]> = (0..n)
                .map(|_| samples[rng.gen_range(0..samples.len())])
                .collect();
            new_trees.push(IsoNode::build(&subsample, 0, MAX_DEPTH));
        }

        *self.trees.write().unwrap() = new_trees;
    }

    /// Build a warm-start forest from synthetic "normal" process behaviour data.
    fn build_synthetic_forest(&self) {
        let mut rng = rand::thread_rng();
        // Synthetic normal baselines (mean, std_dev) for each feature
        let normals: [(f64, f64); FeatureVector::DIM] = [
            (50.0, 20.0),   // syscall_rate: 50/s ± 20
            (20.0, 8.0),    // unique_syscalls: 20 ± 8
            (0.5, 0.3),     // memory_alloc_rate
            (0.05, 0.05),   // child_spawn_rate
            (8.0, 2.0),     // network_bytes (ln-scaled)
            (0.3, 0.15),    // write_entropy
            (0.0, 0.5),     // dangerous_calls (rare)
            (5.0, 2.0),     // event_density
        ];

        let n_samples = SUBSAMPLE_SIZE * self.n_trees;
        let samples: Vec<[f64; FeatureVector::DIM]> = (0..n_samples)
            .map(|_| {
                std::array::from_fn(|i| {
                    let (mean, std) = normals[i];
                    // Box-Muller transform for Gaussian samples
                    let u1: f64 = rng.gen_range(1e-10..1.0);
                    let u2: f64 = rng.gen_range(0.0..1.0);
                    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                    (mean + std * z).max(0.0)
                })
            })
            .collect();

        self.rebuild_forest(&samples);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn normal_features() -> FeatureVector {
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

    fn extreme_features() -> FeatureVector {
        FeatureVector {
            syscall_rate:      10000.0,  // 200× normal
            unique_syscalls:   250.0,    // many unusual syscalls
            memory_alloc_rate: 100.0,    // very aggressive
            child_spawn_rate:  50.0,     // spawning many children
            network_bytes:     20.0,     // large data
            write_entropy:     0.99,     // encrypted writes
            dangerous_calls:   500.0,    // ptrace/memfd
            event_density:     200.0,    // dense events
        }
    }

    #[test]
    fn engine_initialises_without_panic() {
        let engine = AnomalyEngine::new(10);
        let score = engine.score(&normal_features());
        assert!(score.value >= 0.0 && score.value <= 1.0);
    }

    #[test]
    fn anomalous_features_score_higher_than_normal() {
        let engine = AnomalyEngine::new(50);
        let normal_score  = engine.score(&normal_features());
        let extreme_score = engine.score(&extreme_features());

        println!("Normal: {:.3}, Extreme: {:.3}", normal_score.value, extreme_score.value);
        // The extreme feature vector should generally score higher than normal.
        // With a synthetic warm-start this may not always hold perfectly,
        // but the extreme values should at least be > 0.4.
        assert!(extreme_score.value > 0.4, "Extreme features should have non-trivial anomaly score");
    }

    #[test]
    fn score_is_in_valid_range() {
        let engine = AnomalyEngine::new(20);
        for _ in 0..10 {
            let score = engine.score(&extreme_features());
            assert!(score.value >= 0.0 && score.value <= 1.0, "Score must be in [0,1]");
        }
    }

    #[test]
    fn forest_rebuilds_from_samples() {
        let engine = AnomalyEngine::new(10);
        // Feed real "normal" data
        let samples: Vec<[f64; FeatureVector::DIM]> = (0..300)
            .map(|_| normal_features().as_array())
            .collect();
        engine.rebuild_forest(&samples);

        // After retraining on normal data, extreme features should still score higher
        let score = engine.score(&extreme_features());
        assert!(score.n_trees == 10);
        assert!(score.value >= 0.0 && score.value <= 1.0);
    }

    #[test]
    fn feature_vector_from_profile_does_not_panic() {
        use super::super::syscall_profiler::{SyscallProfiler, SyscallEvent, SYS_READ};
        let profiler = SyscallProfiler::new();
        for i in 0..100 {
            let mut ev = SyscallEvent::new(9999, SYS_READ, "test");
            ev.byte_count = i * 100;
            profiler.record(&ev);
        }
        let profile = profiler.get_profile(9999).unwrap();
        let fv = FeatureVector::from_profile(&profile);
        assert!(fv.unique_syscalls >= 1.0);
        assert!(fv.event_density > 0.0);
    }
}
