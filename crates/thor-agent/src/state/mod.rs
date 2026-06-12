//! Thor Shared State — lock-free concurrent state using DashMap + Bloom Filter

pub mod flow;
pub mod ioc;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use dashmap::DashMap;
use bloomfilter::Bloom;
use parking_lot::RwLock;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::debug;

use crate::config::ThorConfig;
use crate::events::enrichment::EnrichedEvent;
use crate::events::RawEvent;

pub use flow::FlowRecord;
pub use ioc::IocDatabase;

/// Central shared state for all agent subsystems
pub struct ThorState {
    /// Lock-free flow table (keyed by 5-tuple)
    pub flows: DashMap<flow::FlowKey, FlowRecord>,
    /// IOC database (Bloom filter for fast negatives + DashMap for positives)
    pub ioc_db: Arc<IocDatabase>,
    /// Atomic counters (no mutex needed)
    pub total_events: AtomicU64,
    pub total_alerts: AtomicU64,
    pub total_packets_dropped: AtomicU64,
    /// Active WebSocket client count
    pub ws_clients: AtomicU64,
}

impl ThorState {
    pub fn new(config: &ThorConfig) -> Self {
        let shards = config.flow_map_shards;
        Self {
            flows: DashMap::with_shard_amount(shards),
            ioc_db: Arc::new(IocDatabase::new(
                config.ioc_bloom_capacity,
                config.ioc_bloom_fpr,
            )),
            total_events: AtomicU64::new(0),
            total_alerts: AtomicU64::new(0),
            total_packets_dropped: AtomicU64::new(0),
            ws_clients: AtomicU64::new(0),
        }
    }

    pub async fn update(&self, event: &EnrichedEvent) {
        self.total_events.fetch_add(1, Ordering::Relaxed);
        match &event.raw {
            RawEvent::Network(e) => {
                let key = flow::FlowKey {
                    src_ip: u32::from(e.src_ip),
                    dst_ip: u32::from(e.dst_ip),
                    src_port: e.src_port,
                    dst_port: e.dst_port,
                    protocol: e.protocol,
                };
                self.flows.entry(key).and_modify(|f| {
                    f.packet_count += 1;
                    f.last_seen = Utc::now();
                }).or_insert_with(|| FlowRecord {
                    key,
                    packet_count: 1,
                    byte_count: 0,
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    pid: Some(e.pid),
                    comm: Some(e.comm.clone()),
                    threat_score: 0.0,
                });
            }
            RawEvent::XdpDrop { .. } => {
                self.total_packets_dropped.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn stats(&self) -> StateStats {
        StateStats {
            total_events: self.total_events.load(Ordering::Relaxed),
            total_alerts: self.total_alerts.load(Ordering::Relaxed),
            active_flows: self.flows.len() as u64,
            ws_clients: self.ws_clients.load(Ordering::Relaxed),
            packets_dropped: self.total_packets_dropped.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StateStats {
    pub total_events: u64,
    pub total_alerts: u64,
    pub active_flows: u64,
    pub ws_clients: u64,
    pub packets_dropped: u64,
}
