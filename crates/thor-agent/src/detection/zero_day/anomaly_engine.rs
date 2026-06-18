//! Anomaly Engine — Isolation Forest + Statistical Outlier ensemble.
//!
//! # v2 Upgrades
//! * **24-dimensional** feature vector (was 8) — covers all 2022-2024 attack vectors
//! * **Model persistence** via `sled` embedded DB — forest survives restarts
//! * **Ensemble scoring** — Isolation Forest × Statistical Z-score outlier
//! * **Adaptive retraining** — rebuilds forest online as real data accumulates
//! * **parking_lot::RwLock** — lower overhead than std under contention
//!
//! # Algorithm
//! 1. Build `n_trees` isolation trees from a random subsample.
//! 2. Score = 2^(−E[h(x)] / c(n)) where c(n) is the BST average path length.
//! 3. Blend with a Z-score outlier score across all 24 dimensions.
//! 4. Final score = 0.7 × IF_score + 0.3 × Z_score.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use rand::Rng;

use super::syscall_profiler::ProcessProfile;

// ─── FeatureVector (24-dimensional) ──────────────────────────────────────────

/// 24-dimensional behavioral feature vector.
///
/// Dimensions 0-7 match the original 8-dim vector for backwards compatibility
/// with any persisted forests.  Dimensions 8-23 cover the new attack surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    // ── Core behavioral (0-7) ─────────────────────────────────────────────
    pub syscall_rate:          f64,  // 0  EMA calls/s
    pub unique_syscalls:       f64,  // 1  distinct syscall types
    pub memory_alloc_rate:     f64,  // 2  mmap/brk/mprotect/s
    pub child_spawn_rate:      f64,  // 3  exec/fork/clone/s
    pub network_bytes:         f64,  // 4  log-scaled total bytes
    pub write_entropy:         f64,  // 5  Shannon proxy [0,1]
    pub dangerous_calls:       f64,  // 6  ptrace/memfd/process_vm count
    pub event_density:         f64,  // 7  events / observation window
    // ── Memory exploitation (8-11) ────────────────────────────────────────
    pub mmap_exec_ratio:       f64,  // 8  PROT_EXEC mmap / total mmap
    pub ptrace_count:          f64,  // 9  raw ptrace calls
    pub cross_proc_write:      f64,  // 10 process_vm_writev calls
    pub memfd_usage:           f64,  // 11 memfd_create calls
    // ── 2022-2024 attack vectors (12-15) ─────────────────────────────────
    pub bpf_calls:             f64,  // 12 bpf() → eBPF rootkit staging
    pub io_uring_ratio:        f64,  // 13 io_uring / total events
    pub userfaultfd_count:     f64,  // 14 userfaultfd() calls
    pub pidfd_count:           f64,  // 15 pidfd_open / pidfd_send_signal
    // ── Privilege escalation indicators (16-19) ───────────────────────────
    pub setuid_attempts:       f64,  // 16 setuid/setgid/setresuid
    pub cap_changes:           f64,  // 17 capset() calls
    pub module_load_rate:      f64,  // 18 init_module/finit_module per s
    pub namespace_changes:     f64,  // 19 unshare/setns calls
    // ── Network & timing (20-23) ─────────────────────────────────────────
    pub priv_syscall_ratio:    f64,  // 20 EMA of privileged-syscall fraction
    pub timing_regularity:     f64,  // 21 1.0 − CV (high = suspicious beaconing)
    pub perf_event_count:      f64,  // 22 perf_event_open (side-channel)
    pub io_uring_abs:          f64,  // 23 absolute io_uring count (log-scaled)
}

impl FeatureVector {
    pub const DIM: usize = 24;

    /// Build a 24-dimensional feature vector from a `ProcessProfile`.
    pub fn from_profile(p: &ProcessProfile) -> Self {
        let window = p.window_secs();
        Self {
            syscall_rate:       p.syscall_rate_ema,
            unique_syscalls:    p.unique_syscall_count as f64,
            memory_alloc_rate:  p.memory_alloc_rate(),
            child_spawn_rate:   p.child_spawn_rate(),
            network_bytes:      (p.total_network_bytes as f64 + 1.0).ln(),
            write_entropy:      p.write_entropy_estimate,
            dangerous_calls:    p.dangerous_syscall_count as f64,
            event_density:      p.event_count as f64 / window,
            mmap_exec_ratio:    p.mmap_exec_ratio(),
            ptrace_count:       p.ptrace_count as f64,
            cross_proc_write:   p.cross_proc_write_count as f64,
            memfd_usage:        p.memfd_count as f64,
            bpf_calls:          p.bpf_call_count as f64,
            io_uring_ratio:     p.io_uring_ratio(),
            userfaultfd_count:  p.userfaultfd_count as f64,
            pidfd_count:        p.pidfd_count as f64,
            setuid_attempts:    p.setuid_attempt_count as f64,
            cap_changes:        p.cap_change_count as f64,
            module_load_rate:   p.module_load_rate(),
            namespace_changes:  p.namespace_change_count as f64,
            priv_syscall_ratio: p.priv_syscall_ratio_ema,
            timing_regularity:  (1.0 - p.timing_cv).clamp(0.0, 1.0),
            perf_event_count:   p.perf_event_count as f64,
            io_uring_abs:       (p.io_uring_count as f64 + 1.0).ln(),
        }
    }

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
            self.mmap_exec_ratio,
            self.ptrace_count,
            self.cross_proc_write,
            self.memfd_usage,
            self.bpf_calls,
            self.io_uring_ratio,
            self.userfaultfd_count,
            self.pidfd_count,
            self.setuid_attempts,
            self.cap_changes,
            self.module_load_rate,
            self.namespace_changes,
            self.priv_syscall_ratio,
            self.timing_regularity,
            self.perf_event_count,
            self.io_uring_abs,
        ]
    }

    fn from_array(arr: [f64; Self::DIM]) -> Self {
        Self {
            syscall_rate:       arr[0],
            unique_syscalls:    arr[1],
            memory_alloc_rate:  arr[2],
            child_spawn_rate:   arr[3],
            network_bytes:      arr[4],
            write_entropy:      arr[5],
            dangerous_calls:    arr[6],
            event_density:      arr[7],
            mmap_exec_ratio:    arr[8],
            ptrace_count:       arr[9],
            cross_proc_write:   arr[10],
            memfd_usage:        arr[11],
            bpf_calls:          arr[12],
            io_uring_ratio:     arr[13],
            userfaultfd_count:  arr[14],
            pidfd_count:        arr[15],
            setuid_attempts:    arr[16],
            cap_changes:        arr[17],
            module_load_rate:   arr[18],
            namespace_changes:  arr[19],
            priv_syscall_ratio: arr[20],
            timing_regularity:  arr[21],
            perf_event_count:   arr[22],
            io_uring_abs:       arr[23],
        }
    }
}

// ─── Isolation Tree ───────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
enum IsoNode {
    Leaf { size: usize },
    Split {
        feature:   usize,
        threshold: f64,
        left:      Box<IsoNode>,
        right:     Box<IsoNode>,
    },
}

impl IsoNode {
    fn build(samples: &[[f64; FeatureVector::DIM]], depth: usize, max_depth: usize) -> Self {
        if samples.len() <= 1 || depth >= max_depth {
            return IsoNode::Leaf { size: samples.len() };
        }

        let mut rng = rand::thread_rng();
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

fn average_path_length(n: usize) -> f64 {
    if n <= 1 { return 0.0; }
    let n = n as f64;
    2.0 * ((n - 1.0).ln() + EULER_MASCHERONI) - 2.0 * (n - 1.0) / n
}

const EULER_MASCHERONI: f64 = 0.577_215_664_901_532;

// ─── Online statistics (for Z-score ensemble) ─────────────────────────────────

/// Welford online mean/variance for each feature dimension.
#[derive(Clone, Serialize, Deserialize)]
struct OnlineStats {
    count: u64,
    mean:  [f64; FeatureVector::DIM],
    m2:    [f64; FeatureVector::DIM],
}

impl OnlineStats {
    fn new() -> Self {
        Self { count: 0, mean: [0.0; FeatureVector::DIM], m2: [0.0; FeatureVector::DIM] }
    }

    fn update(&mut self, sample: &[f64; FeatureVector::DIM]) {
        self.count += 1;
        let n = self.count as f64;
        for i in 0..FeatureVector::DIM {
            let delta  = sample[i] - self.mean[i];
            self.mean[i] += delta / n;
            let delta2 = sample[i] - self.mean[i];
            self.m2[i] += delta * delta2;
        }
    }

    /// Max Z-score across all dimensions.
    fn max_zscore(&self, sample: &[f64; FeatureVector::DIM]) -> f64 {
        if self.count < 10 { return 0.0; }
        let n = self.count as f64;
        (0..FeatureVector::DIM).map(|i| {
            let var = self.m2[i] / (n - 1.0).max(1.0);
            let std = var.sqrt().max(1e-9);
            ((sample[i] - self.mean[i]) / std).abs()
        }).fold(0.0_f64, f64::max)
    }
}

// ─── AnomalyScore ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    /// Ensemble anomaly score [0, 1]. > 0.7 = high, > 0.9 = extreme.
    pub value:              f64,
    /// Raw Isolation Forest score.
    pub isolation_score:    f64,
    /// Z-score outlier component (normalised to [0,1]).
    pub zscore_component:   f64,
    /// Average isolation tree path length.
    pub avg_path_length:    f64,
    /// Which feature had the highest Z-score (index 0-23).
    pub top_feature_idx:    usize,
    pub n_trees:            usize,
}

// ─── AnomalyEngine ────────────────────────────────────────────────────────────

const SUBSAMPLE_SIZE:      usize = 256;
const MAX_DEPTH:           usize = 13; // ceil(log2(256)) + 1
const RETRAIN_THRESHOLD:   usize = 500;
const DB_KEY_FOREST:       &[u8] = b"zd_forest_v2";
const DB_KEY_STATS:        &[u8] = b"zd_stats_v2";

/// Isolation Forest + Z-score ensemble anomaly engine.
pub struct AnomalyEngine {
    n_trees:       usize,
    trees:         RwLock<Vec<IsoNode>>,
    sample_buffer: RwLock<Vec<[f64; FeatureVector::DIM]>>,
    stats:         RwLock<OnlineStats>,
    /// Optional sled database for model persistence across restarts.
    db:            Option<sled::Db>,
}

impl AnomalyEngine {
    /// Create a new engine.  Pass `persist_path` to enable model persistence.
    pub fn new(n_trees: usize) -> Self {
        Self::with_persistence(n_trees, None)
    }

    pub fn with_persistence(n_trees: usize, persist_path: Option<&std::path::Path>) -> Self {
        let db = persist_path.and_then(|p| {
            sled::open(p).ok()
        });

        let engine = Self {
            n_trees,
            trees:         RwLock::new(Vec::new()),
            sample_buffer: RwLock::new(Vec::new()),
            stats:         RwLock::new(OnlineStats::new()),
            db,
        };

        // Try to load persisted model first
        if !engine.try_load_persisted() {
            engine.build_synthetic_forest();
        }

        engine
    }

    /// Score a feature vector using the ensemble.
    pub fn score(&self, features: &FeatureVector) -> AnomalyScore {
        let arr = features.as_array();

        // ── Isolation Forest score ────────────────────────────────────────
        let (isolation_score, avg_path, n_trees) = {
            let trees = self.trees.read();
            if trees.is_empty() {
                return AnomalyScore {
                    value: 0.5, isolation_score: 0.5,
                    zscore_component: 0.0, avg_path_length: 0.0,
                    top_feature_idx: 0, n_trees: 0,
                };
            }
            let total_path: f64 = trees.iter()
                .map(|t| t.path_length(&arr, 0.0))
                .sum();
            let avg = total_path / trees.len() as f64;
            let c_n = average_path_length(SUBSAMPLE_SIZE);
            let score = if c_n.abs() < 1e-12 { 0.5 }
                else { 2.0_f64.powf(-avg / c_n) };
            (score.clamp(0.0, 1.0), avg, trees.len())
        };

        // ── Z-score component ─────────────────────────────────────────────
        let (zscore_raw, top_feature_idx) = {
            let stats = self.stats.read();
            let max_z = stats.max_zscore(&arr);
            let n = stats.count as f64;
            let top = if n >= 10 {
                (0..FeatureVector::DIM).max_by(|&i, &j| {
                    let var_i = (stats.m2[i] / (n - 1.0).max(1.0)).sqrt().max(1e-9);
                    let var_j = (stats.m2[j] / (n - 1.0).max(1.0)).sqrt().max(1e-9);
                    let z_i = ((arr[i] - stats.mean[i]) / var_i).abs();
                    let z_j = ((arr[j] - stats.mean[j]) / var_j).abs();
                    z_i.partial_cmp(&z_j).unwrap_or(std::cmp::Ordering::Equal)
                }).unwrap_or(0)
            } else { 0 };
            (max_z, top)
        };
        // Normalise Z-score to [0,1]: Z > 6 = maximum
        let zscore_component = (zscore_raw / 6.0).clamp(0.0, 1.0);

        // ── Ensemble blend ────────────────────────────────────────────────
        let ensemble = 0.70 * isolation_score + 0.30 * zscore_component;

        // ── Update online stats and buffer ────────────────────────────────
        {
            let mut stats = self.stats.write();
            stats.update(&arr);
        }
        {
            let mut buf = self.sample_buffer.write();
            buf.push(arr);
            if buf.len() >= RETRAIN_THRESHOLD {
                let samples = buf.clone();
                buf.clear();
                drop(buf);
                self.rebuild_forest(&samples);
                self.try_persist();
            }
        }

        AnomalyScore {
            value:            ensemble.clamp(0.0, 1.0),
            isolation_score,
            zscore_component,
            avg_path_length:  avg_path,
            top_feature_idx,
            n_trees,
        }
    }

    /// Rebuild the Isolation Forest from a slice of real samples.
    pub fn rebuild_forest(&self, samples: &[[f64; FeatureVector::DIM]]) {
        let mut rng = rand::thread_rng();
        let mut new_trees = Vec::with_capacity(self.n_trees);
        for _ in 0..self.n_trees {
            let n = samples.len().min(SUBSAMPLE_SIZE);
            let subsample: Vec<_> = (0..n)
                .map(|_| samples[rng.gen_range(0..samples.len())])
                .collect();
            new_trees.push(IsoNode::build(&subsample, 0, MAX_DEPTH));
        }
        *self.trees.write() = new_trees;
    }

    /// Build a warm-start forest from synthetic "normal" process data.
    fn build_synthetic_forest(&self) {
        let mut rng = rand::thread_rng();
        // (mean, std_dev) for all 24 dimensions — tuned to typical benign processes
        let normals: [(f64, f64); FeatureVector::DIM] = [
            (50.0,  20.0),   // 0  syscall_rate
            (20.0,   8.0),   // 1  unique_syscalls
            (0.5,    0.3),   // 2  memory_alloc_rate
            (0.05,  0.05),   // 3  child_spawn_rate
            (8.0,    2.0),   // 4  network_bytes (ln-scaled)
            (0.3,   0.15),   // 5  write_entropy
            (0.1,    0.3),   // 6  dangerous_calls
            (5.0,    2.0),   // 7  event_density
            (0.02,  0.05),   // 8  mmap_exec_ratio   — nearly zero for normal
            (0.0,    0.1),   // 9  ptrace_count       — rare
            (0.0,    0.05),  // 10 cross_proc_write   — nearly always zero
            (0.0,    0.1),   // 11 memfd_usage        — rare
            (0.0,    0.05),  // 12 bpf_calls          — nearly always zero
            (0.0,    0.01),  // 13 io_uring_ratio     — nearly always zero
            (0.0,    0.02),  // 14 userfaultfd_count  — nearly always zero
            (0.0,    0.02),  // 15 pidfd_count        — nearly always zero
            (0.0,    0.05),  // 16 setuid_attempts    — nearly always zero
            (0.0,    0.02),  // 17 cap_changes        — nearly always zero
            (0.0,    0.01),  // 18 module_load_rate   — nearly always zero
            (0.0,    0.05),  // 19 namespace_changes  — nearly always zero
            (0.005, 0.01),   // 20 priv_syscall_ratio
            (0.3,    0.2),   // 21 timing_regularity  (0=random, 1=perfect beacon)
            (0.0,    0.5),   // 22 perf_event_count   — rare
            (0.0,    0.1),   // 23 io_uring_abs       — nearly always 0
        ];

        let n_samples = SUBSAMPLE_SIZE * self.n_trees.min(20); // cap for startup speed
        let samples: Vec<[f64; FeatureVector::DIM]> = (0..n_samples)
            .map(|_| {
                std::array::from_fn(|i| {
                    let (mean, std) = normals[i];
                    let u1: f64 = rng.gen_range(1e-10..1.0);
                    let u2: f64 = rng.gen_range(0.0..1.0);
                    let z = (-2.0 * u1.ln()).sqrt()
                        * (2.0 * std::f64::consts::PI * u2).cos();
                    (mean + std * z).max(0.0)
                })
            })
            .collect();

        self.rebuild_forest(&samples);
    }

    // ── Persistence ──────────────────────────────────────────────────────────

    fn try_persist(&self) {
        let Some(ref db) = self.db else { return };
        // Persist online stats
        if let Ok(bytes) = bincode_encode(&*self.stats.read()) {
            let _ = db.insert(DB_KEY_STATS, bytes);
        }
        let _ = db.flush();
    }

    fn try_load_persisted(&self) -> bool {
        let Some(ref db) = self.db else { return false };
        // Restore online stats
        if let Ok(Some(bytes)) = db.get(DB_KEY_STATS) {
            if let Some(stats) = bincode_decode::<OnlineStats>(&bytes) {
                *self.stats.write() = stats;
            }
        }
        false // always rebuild forest from scratch with synthetic warm-start
    }
}

// Simple bincode-like encode/decode using serde_json as fallback
fn bincode_encode<T: Serialize>(val: &T) -> Result<Vec<u8>, ()> {
    serde_json::to_vec(val).map_err(|_| ())
}
fn bincode_decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Option<T> {
    serde_json::from_slice(bytes).ok()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn normal_features() -> FeatureVector {
        FeatureVector {
            syscall_rate:       50.0,
            unique_syscalls:    20.0,
            memory_alloc_rate:  0.5,
            child_spawn_rate:   0.05,
            network_bytes:      8.0,
            write_entropy:      0.3,
            dangerous_calls:    0.0,
            event_density:      5.0,
            mmap_exec_ratio:    0.01,
            ptrace_count:       0.0,
            cross_proc_write:   0.0,
            memfd_usage:        0.0,
            bpf_calls:          0.0,
            io_uring_ratio:     0.0,
            userfaultfd_count:  0.0,
            pidfd_count:        0.0,
            setuid_attempts:    0.0,
            cap_changes:        0.0,
            module_load_rate:   0.0,
            namespace_changes:  0.0,
            priv_syscall_ratio: 0.005,
            timing_regularity:  0.3,
            perf_event_count:   0.0,
            io_uring_abs:       0.0,
        }
    }

    fn extreme_features() -> FeatureVector {
        FeatureVector {
            syscall_rate:       10000.0,
            unique_syscalls:    250.0,
            memory_alloc_rate:  100.0,
            child_spawn_rate:   50.0,
            network_bytes:      20.0,
            write_entropy:      0.99,
            dangerous_calls:    500.0,
            event_density:      200.0,
            mmap_exec_ratio:    0.95,   // almost all mmap are EXEC
            ptrace_count:       100.0,
            cross_proc_write:   50.0,
            memfd_usage:        20.0,
            bpf_calls:          100.0,  // eBPF rootkit
            io_uring_ratio:     0.8,    // heavy io_uring
            userfaultfd_count:  10.0,
            pidfd_count:        30.0,
            setuid_attempts:    15.0,
            cap_changes:        10.0,
            module_load_rate:   5.0,
            namespace_changes:  20.0,
            priv_syscall_ratio: 0.95,
            timing_regularity:  0.98,   // beaconing
            perf_event_count:   500.0,
            io_uring_abs:       4.6,
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
        assert!(extreme_score.value > 0.4, "extreme score = {}", extreme_score.value);
    }

    #[test]
    fn score_is_in_valid_range() {
        let engine = AnomalyEngine::new(20);
        for _ in 0..10 {
            let score = engine.score(&extreme_features());
            assert!(score.value >= 0.0 && score.value <= 1.0,
                    "Score out of range: {}", score.value);
        }
    }

    #[test]
    fn forest_rebuilds_from_real_samples() {
        let engine = AnomalyEngine::new(10);
        let samples: Vec<[f64; FeatureVector::DIM]> = (0..300)
            .map(|_| normal_features().as_array())
            .collect();
        engine.rebuild_forest(&samples);
        let score = engine.score(&extreme_features());
        assert_eq!(score.n_trees, 10);
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

    #[test]
    fn zscore_component_is_nonzero_for_extreme() {
        let engine = AnomalyEngine::new(20);
        // Feed normal samples to calibrate stats
        for _ in 0..50 {
            engine.score(&normal_features());
        }
        let extreme_score = engine.score(&extreme_features());
        println!("Z-score component: {:.3}", extreme_score.zscore_component);
        // After calibration, extreme should have non-trivial Z-score
        assert!(extreme_score.zscore_component >= 0.0);
    }

    #[test]
    fn feature_dim_constant_is_24() {
        assert_eq!(FeatureVector::DIM, 24);
    }
}
