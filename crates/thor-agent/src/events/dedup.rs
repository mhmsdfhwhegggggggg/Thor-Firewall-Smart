//! Event deduplication using a sliding-window hash set
//! Uses dashmap for lock-free concurrent access

use dashmap::DashSet;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{interval, Duration};
use crate::events::RawEvent;

pub struct EventDeduplicator {
    seen: Arc<DashSet<u64>>,
    window_secs: u64,
    last_clean: AtomicU64,
}

impl EventDeduplicator {
    pub fn new(window_secs: u64) -> Self {
        let seen = Arc::new(DashSet::with_capacity(16384));
        let dedup = Self {
            seen,
            window_secs,
            last_clean: AtomicU64::new(now_secs()),
        };
        dedup
    }

    pub fn is_duplicate(&self, event: &RawEvent) -> bool {
        let hash = event_hash(event);
        // Periodic cleanup
        let now = now_secs();
        let last = self.last_clean.load(Ordering::Relaxed);
        if now - last > self.window_secs {
            if self.last_clean.compare_exchange(last, now, Ordering::SeqCst, Ordering::Relaxed).is_ok() {
                self.seen.clear();
            }
        }
        !self.seen.insert(hash)
    }
}

fn event_hash(event: &RawEvent) -> u64 {
    let mut h = DefaultHasher::new();
    // Hash key fields per event type (ignore timestamps for dedup)
    match event {
        RawEvent::Process(e) => {
            e.pid().hash(&mut h);
            e.timestamp_ns().wrapping_div(1_000_000_000).hash(&mut h); // 1s bucket
        }
        RawEvent::Network(e) => {
            e.pid.hash(&mut h);
            e.dst_ip.hash(&mut h);
            e.dst_port.hash(&mut h);
            e.timestamp_ns.wrapping_div(1_000_000_000).hash(&mut h);
        }
        RawEvent::XdpDrop { src_ip, dst_port, reason, .. } => {
            src_ip.hash(&mut h);
            dst_port.hash(&mut h);
            reason.hash(&mut h);
        }
    }
    let mut result = 0u64;
    result.hash(&mut h);
    use std::hash::Hasher;
    h.finish()
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
