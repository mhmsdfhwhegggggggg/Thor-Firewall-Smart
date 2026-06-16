//! ThorIDS — Threshold & Suppress Engine
//!
//! Tracks rule firing rates to implement:
//!   threshold type:limit — fire only N times in T seconds
//!   threshold type:threshold — fire after N occurrences in T seconds
//!   threshold type:both — combination
//!   suppress — completely silence a rule for a time window
//!
//! All state is lock-free via DashMap — suitable for high-throughput paths.

use dashmap::DashMap;
use std::time::{Duration, Instant};
use std::sync::Arc;

// ─── Threshold Types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ThresholdType {
    /// Fire at most `count` times per `seconds`
    Limit { count: u32, seconds: u64 },
    /// Fire only after `count` occurrences in `seconds`
    Threshold { count: u32, seconds: u64 },
    /// Fire at most `count` times per `seconds`, only after `count` occurrences
    Both { count: u32, seconds: u64 },
}

// ─── Per-SID Bucket ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct Bucket {
    /// Count of events in current window
    hits: u32,
    /// How many times the rule actually fired in this window
    fires: u32,
    /// When this window started
    window_start: Instant,
}

impl Bucket {
    fn new() -> Self {
        Self { hits: 0, fires: 0, window_start: Instant::now() }
    }

    fn reset(&mut self) {
        self.hits = 0;
        self.fires = 0;
        self.window_start = Instant::now();
    }

    fn age_secs(&self) -> u64 {
        self.window_start.elapsed().as_secs()
    }
}

// ─── ThresholdTracker ─────────────────────────────────────────────────────────

pub struct ThresholdTracker {
    /// sid → Bucket
    buckets: Arc<DashMap<u32, Bucket>>,
    /// sid → suppression expiry
    suppress: Arc<DashMap<u32, Instant>>,
}

impl ThresholdTracker {
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            suppress: Arc::new(DashMap::new()),
        }
    }

    /// Suppress `sid` for `duration`. Returns immediately.
    pub fn suppress(&self, sid: u32, duration: Duration) {
        self.suppress.insert(sid, Instant::now() + duration);
    }

    /// Returns `true` if `sid` is currently suppressed.
    pub fn is_suppressed(&self, sid: u32) -> bool {
        if let Some(exp) = self.suppress.get(&sid) {
            if Instant::now() < *exp {
                return true;
            }
            drop(exp);
            self.suppress.remove(&sid);
        }
        false
    }

    /// Evaluate a threshold rule hit.
    /// Returns `true` if the rule should actually fire an alert.
    pub fn should_fire(&self, sid: u32, thr: &ThresholdType) -> bool {
        if self.is_suppressed(sid) {
            return false;
        }

        let mut bucket = self.buckets.entry(sid).or_insert_with(Bucket::new);

        // Check if we need to reset the time window
        let (window_secs, count) = match thr {
            ThresholdType::Limit { count, seconds } => (*seconds, *count),
            ThresholdType::Threshold { count, seconds } => (*seconds, *count),
            ThresholdType::Both { count, seconds } => (*seconds, *count),
        };

        if bucket.age_secs() >= window_secs {
            bucket.reset();
        }

        bucket.hits += 1;

        match thr {
            ThresholdType::Limit { count, .. } => {
                // Fire at most `count` times in window
                if bucket.fires < *count {
                    bucket.fires += 1;
                    true
                } else {
                    false
                }
            }
            ThresholdType::Threshold { count, .. } => {
                // Only fire after `count` hits; then fire every subsequent hit
                if bucket.hits >= *count {
                    bucket.fires += 1;
                    true
                } else {
                    false
                }
            }
            ThresholdType::Both { count, .. } => {
                // Fire at most `count` times per window, but only after `count` hits
                if bucket.hits >= *count && bucket.fires < *count {
                    bucket.fires += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Clean up expired suppressions and old buckets (call periodically)
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.suppress.retain(|_, exp| *exp > now);
        // Remove buckets older than 5 minutes
        self.buckets.retain(|_, b| b.window_start.elapsed() < Duration::from_secs(300));
    }
}

impl Default for ThresholdTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Default thresholds (applied to all rules that don't specify one) ─────────

/// Rate-limit: at most 3 fires per 60 seconds per SID by default.
pub fn default_threshold() -> ThresholdType {
    ThresholdType::Limit { count: 3, seconds: 60 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_limit_fires_at_most_n_times() {
        let t = ThresholdTracker::new();
        let thr = ThresholdType::Limit { count: 2, seconds: 60 };

        assert!(t.should_fire(1, &thr));   // 1st — allowed
        assert!(t.should_fire(1, &thr));   // 2nd — allowed
        assert!(!t.should_fire(1, &thr));  // 3rd — blocked
        assert!(!t.should_fire(1, &thr));  // 4th — blocked
    }

    #[test]
    fn test_threshold_fires_after_n_hits() {
        let t = ThresholdTracker::new();
        let thr = ThresholdType::Threshold { count: 3, seconds: 60 };

        assert!(!t.should_fire(2, &thr));  // 1st — not yet
        assert!(!t.should_fire(2, &thr));  // 2nd — not yet
        assert!(t.should_fire(2, &thr));   // 3rd — fires
        assert!(t.should_fire(2, &thr));   // 4th — fires (every subsequent)
    }

    #[test]
    fn test_suppress_blocks_all_fires() {
        let t = ThresholdTracker::new();
        let thr = ThresholdType::Limit { count: 100, seconds: 60 };

        t.suppress(3, Duration::from_secs(60));
        assert!(!t.should_fire(3, &thr));
    }

    #[test]
    fn test_different_sids_independent() {
        let t = ThresholdTracker::new();
        let thr = ThresholdType::Limit { count: 1, seconds: 60 };

        assert!(t.should_fire(10, &thr));  // sid 10 fires
        assert!(!t.should_fire(10, &thr)); // sid 10 blocked
        assert!(t.should_fire(11, &thr));  // sid 11 still fires (independent)
    }
}
