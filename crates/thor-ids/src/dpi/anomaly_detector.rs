//! Anomaly Detector — detects statistical anomalies in network traffic patterns.
//!
//! Uses an adaptive Welford online mean/variance algorithm to maintain a rolling
//! baseline per (src_ip, dst_port) pair, then flags packets that deviate
//! significantly from the established baseline.
//!
//! # Algorithm
//! For each monitored stream, maintains:
//! - Online mean and M2 (Welford's algorithm — single-pass, numerically stable)
//! - Exponentially weighted moving average (EWMA) for adaptive baseline
//! - Z-score based threshold: flag if |z| > ZSCORE_THRESHOLD

use std::time::{Duration, Instant};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::debug;

// ─── Configuration ────────────────────────────────────────────────────────────

/// Z-score threshold above which a packet is considered anomalous.
/// At 3.0 sigmas, roughly 0.3% of normal traffic would be flagged
/// (adjusted upward from textbook 3σ to reduce FPR).
const ZSCORE_THRESHOLD: f64 = 3.5;

/// Minimum number of samples before the baseline is considered reliable.
const MIN_SAMPLES: u64 = 30;

/// EWMA smoothing factor (α). Higher = adapts faster, lower = more stable.
const EWMA_ALPHA: f64 = 0.05;

/// Evict stream state after this many seconds of inactivity.
const STREAM_TTL_SECS: u64 = 300;

// ─── Welford online statistics ────────────────────────────────────────────────

/// Numerically stable online mean/variance using Welford's algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelfordStats {
    pub n: u64,
    pub mean: f64,
    pub m2: f64,   // sum of squared deviations
    pub ewma: f64, // exponentially weighted moving average
}

impl WelfordStats {
    pub fn new() -> Self {
        Self { n: 0, mean: 0.0, m2: 0.0, ewma: 0.0 }
    }

    /// Update with a new sample value.
    pub fn update(&mut self, value: f64) {
        self.n += 1;
        let delta = value - self.mean;
        self.mean += delta / self.n as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;

        // EWMA update
        if self.n == 1 {
            self.ewma = value;
        } else {
            self.ewma = EWMA_ALPHA * value + (1.0 - EWMA_ALPHA) * self.ewma;
        }
    }

    /// Population variance (biased estimator).
    pub fn variance(&self) -> f64 {
        if self.n < 2 { return 0.0; }
        self.m2 / self.n as f64
    }

    /// Standard deviation.
    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Compute the z-score for a new value against the current baseline.
    /// Returns `None` if the baseline is not yet reliable (< MIN_SAMPLES).
    pub fn zscore(&self, value: f64) -> Option<f64> {
        if self.n < MIN_SAMPLES { return None; }
        let sigma = self.std_dev();
        if sigma < 1e-10 { return None; } // Degenerate case: no variance
        Some((value - self.ewma).abs() / sigma)
    }

    /// Returns true if the baseline has enough samples for reliable detection.
    pub fn is_reliable(&self) -> bool {
        self.n >= MIN_SAMPLES
    }
}

impl Default for WelfordStats {
    fn default() -> Self { Self::new() }
}

// ─── Stream state ─────────────────────────────────────────────────────────────

/// Per-stream statistical state.
#[derive(Debug)]
struct StreamState {
    /// Baseline stats for packet size
    size_stats: WelfordStats,
    /// Baseline stats for inter-arrival time (milliseconds)
    iat_stats: WelfordStats,
    /// Baseline stats for payload entropy
    entropy_stats: WelfordStats,
    /// Last packet arrival time
    last_seen: Instant,
    /// Total packets observed in this stream
    packet_count: u64,
}

impl StreamState {
    fn new() -> Self {
        Self {
            size_stats: WelfordStats::new(),
            iat_stats: WelfordStats::new(),
            entropy_stats: WelfordStats::new(),
            last_seen: Instant::now(),
            packet_count: 0,
        }
    }

    /// Update with a new packet observation.
    fn update(&mut self, pkt_size: usize, entropy: f32) {
        let now = Instant::now();
        let iat_ms = now.duration_since(self.last_seen).as_millis() as f64;

        self.size_stats.update(pkt_size as f64);
        if self.packet_count > 0 {
            self.iat_stats.update(iat_ms);
        }
        self.entropy_stats.update(entropy as f64);

        self.last_seen = now;
        self.packet_count += 1;
    }

    fn is_stale(&self) -> bool {
        self.last_seen.elapsed() > Duration::from_secs(STREAM_TTL_SECS)
    }
}

// ─── Anomaly result ───────────────────────────────────────────────────────────

/// Result of analyzing a single packet for anomalies.
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyResult {
    /// Composite anomaly score in [0.0, 1.0]
    pub score: f32,
    /// Whether this is flagged as anomalous
    pub is_anomalous: bool,
    /// Z-score for packet size (None if baseline not ready)
    pub size_zscore: Option<f64>,
    /// Z-score for inter-arrival time (None if baseline not ready)
    pub iat_zscore: Option<f64>,
    /// Z-score for payload entropy (None if baseline not ready)
    pub entropy_zscore: Option<f64>,
    /// Human-readable explanation
    pub explanation: String,
}

impl AnomalyResult {
    fn normal() -> Self {
        Self {
            score: 0.0,
            is_anomalous: false,
            size_zscore: None,
            iat_zscore: None,
            entropy_zscore: None,
            explanation: "within normal baseline".into(),
        }
    }
}

// ─── Engine ───────────────────────────────────────────────────────────────────

/// The traffic anomaly detection engine.
pub struct AnomalyDetector {
    /// Stream state keyed by `"src_ip:dst_ip:dst_port"` string
    streams: DashMap<String, StreamState>,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self { streams: DashMap::new() }
    }

    /// Observe a packet and return an anomaly result.
    ///
    /// - `stream_key`: e.g. `"10.0.0.1:192.168.1.1:443"`
    /// - `pkt_size`: total packet size in bytes
    /// - `payload_entropy`: Shannon entropy of the payload, normalized [0,1]
    pub fn observe(
        &self,
        stream_key: &str,
        pkt_size: usize,
        payload_entropy: f32,
    ) -> AnomalyResult {
        let mut entry = self.streams
            .entry(stream_key.to_string())
            .or_insert_with(StreamState::new);

        // Compute zscores BEFORE updating (so new point is compared to baseline)
        let size_z  = entry.size_stats.zscore(pkt_size as f64);
        let iat_z   = entry.iat_stats.zscore(
            entry.last_seen.elapsed().as_millis() as f64
        );
        let ent_z   = entry.entropy_stats.zscore(payload_entropy as f64);

        // Now update the baseline
        entry.update(pkt_size, payload_entropy);

        // Compute composite anomaly score
        let mut max_z = 0.0f64;
        let mut reasons = Vec::new();

        if let Some(z) = size_z {
            if z > ZSCORE_THRESHOLD {
                reasons.push(format!("size_z={:.2}", z));
                max_z = max_z.max(z);
            }
        }
        if let Some(z) = iat_z {
            if z > ZSCORE_THRESHOLD {
                reasons.push(format!("iat_z={:.2}", z));
                max_z = max_z.max(z);
            }
        }
        if let Some(z) = ent_z {
            if z > ZSCORE_THRESHOLD {
                reasons.push(format!("entropy_z={:.2}", z));
                max_z = max_z.max(z);
            }
        }

        if reasons.is_empty() {
            return AnomalyResult::normal();
        }

        // Normalize z-score to [0,1] score: sigmoid-like capping at z=10
        let score = ((max_z - ZSCORE_THRESHOLD) / (10.0 - ZSCORE_THRESHOLD))
            .min(1.0)
            .max(0.0) as f32;

        debug!(
            "🔴 Anomaly detected on stream '{}': score={:.3} reasons={}",
            stream_key, score, reasons.join(", ")
        );

        AnomalyResult {
            score,
            is_anomalous: score > 0.0,
            size_zscore: size_z,
            iat_zscore: iat_z,
            entropy_zscore: ent_z,
            explanation: format!("Anomaly detected: {}", reasons.join(", ")),
        }
    }

    /// Evict stale stream states to prevent memory growth.
    pub fn evict_stale(&self) -> usize {
        let mut stale_keys: Vec<String> = Vec::new();
        for entry in self.streams.iter() {
            if entry.value().is_stale() {
                stale_keys.push(entry.key().clone());
            }
        }
        let count = stale_keys.len();
        for key in stale_keys { self.streams.remove(&key); }
        count
    }

    /// Return the number of active tracked streams.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self { Self::new() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_welford_mean_variance() {
        let mut stats = WelfordStats::new();
        for i in 1..=10 {
            stats.update(i as f64);
        }
        // Mean of 1..10 = 5.5
        assert!((stats.mean - 5.5).abs() < 0.001, "Expected mean=5.5, got {}", stats.mean);
        assert!(stats.variance() > 0.0, "Variance should be non-zero");
        assert_eq!(stats.n, 10);
    }

    #[test]
    fn test_baseline_not_reliable_before_min_samples() {
        let mut stats = WelfordStats::new();
        for i in 0..29 { stats.update(i as f64); }
        assert!(!stats.is_reliable(), "Should not be reliable with < {} samples", MIN_SAMPLES);
        stats.update(100.0);
        assert!(stats.is_reliable(), "Should be reliable with {} samples", MIN_SAMPLES);
    }

    #[test]
    fn test_normal_traffic_no_anomaly() {
        let detector = AnomalyDetector::new();
        let key = "10.0.0.1:10.0.0.2:80";

        // Feed 50 packets of similar size to establish baseline
        for _ in 0..50 {
            let result = detector.observe(key, 512, 0.45);
            // Early packets shouldn't trigger (baseline not reliable yet)
            if result.is_anomalous {
                assert!(result.score < 0.5, "Early anomaly scores should be low");
            }
        }

        // After baseline established, feed a "normal" packet
        let result = detector.observe(key, 510, 0.44);
        assert!(!result.is_anomalous, "Normal packet should not be anomalous");
    }

    #[test]
    fn test_anomalous_large_packet_flagged() {
        let detector = AnomalyDetector::new();
        let key = "10.0.0.1:10.0.0.2:443";

        // Establish baseline with small packets (~100 bytes, low variance)
        for _ in 0..50 {
            detector.observe(key, 100, 0.3);
        }

        // Feed a dramatically larger packet — should trigger size anomaly
        let result = detector.observe(key, 10000, 0.3);
        assert!(result.is_anomalous, "Dramatically large packet should be flagged");
        assert!(result.size_zscore.is_some());
        assert!(result.size_zscore.unwrap() > ZSCORE_THRESHOLD);
    }

    #[test]
    fn test_stream_count() {
        let detector = AnomalyDetector::new();
        detector.observe("stream-1", 100, 0.5);
        detector.observe("stream-2", 200, 0.6);
        detector.observe("stream-3", 150, 0.4);
        assert_eq!(detector.stream_count(), 3);
    }

    #[test]
    fn test_zscore_threshold_constant() {
        assert!(ZSCORE_THRESHOLD >= 3.0, "Threshold must be >= 3σ to limit false positives");
    }
}
