//! Shared runtime state — thread-safe, accessible across all subsystems.

pub mod attack_graph;
pub mod persistence;
pub mod flow;
pub mod ioc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use utoipa::ToSchema;

use crate::config::ThorConfig;
use crate::detection::sigma::SigmaEngine;
use crate::events::enrichment::EnrichedEvent;
use flow::{FlowKey, FlowRecord};
use ioc::IocDatabase;

// ─── Live statistics (exposed via /api/v1/stats) ──────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StateStats {
    pub packets_processed: u64,
    pub packets_dropped: u64,
    pub active_flows: usize,
    pub total_alerts: u64,
    pub ioc_count: usize,
    pub ws_clients: usize,
}

// ─── Core shared state ────────────────────────────────────────────────────────

pub struct ThorState {
    // Counters (atomic for lock-free reads)
    pub packets_processed: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub total_alerts: AtomicU64,
    pub ws_clients: AtomicUsize,

    // Flow table — keyed by 5-tuple
    pub flows: DashMap<FlowKey, FlowRecord>,

    // IOC database — Bloom + DashMap
    pub ioc_db: Arc<IocDatabase>,

    // Sigma engine — behind RwLock so handlers can inject rules
    pub sigma_engine: RwLock<SigmaEngine>,
}

impl ThorState {
    pub fn new(config: &ThorConfig) -> Self {
        let ioc_db = Arc::new(IocDatabase::new(
            config.ioc_bloom_capacity,
            config.ioc_bloom_fpr,
        ));

        let sigma_engine = SigmaEngine::load(&config.sigma_rules_dir)
            .unwrap_or_else(|e| {
                tracing::warn!("Sigma engine fallback (empty): {}", e);
                SigmaEngine::empty()
            });

        Self {
            packets_processed: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            total_alerts: AtomicU64::new(0),
            ws_clients: AtomicUsize::new(0),
            flows: DashMap::with_shard_amount(config.flow_map_shards),
            ioc_db,
            sigma_engine: RwLock::new(sigma_engine),
        }
    }

    /// Snapshot statistics for the API
    pub fn stats(&self) -> StateStats {
        StateStats {
            packets_processed: self.packets_processed.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            active_flows: self.flows.len(),
            total_alerts: self.total_alerts.load(Ordering::Relaxed),
            ioc_count: self.ioc_db.len(),
            ws_clients: self.ws_clients.load(Ordering::Relaxed),
        }
    }

    /// Update state from an enriched event
    pub async fn update(&self, event: &EnrichedEvent) {
        self.packets_processed.fetch_add(1, Ordering::Relaxed);
    }
}
