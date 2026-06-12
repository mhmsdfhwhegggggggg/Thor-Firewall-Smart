//! Event processing pipeline — Dedup → Enrich → Detect → SOAR
//! Handles ~1M events/sec with flume bounded channels

use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{info, debug, warn};
use crate::events::{RawEvent, Alert};
use crate::state::ThorState;
use crate::detection::DetectionEngine;
use crate::soar::SoarEngine;
use super::dedup::EventDeduplicator;
use super::enrichment::EventEnricher;

pub struct EventPipeline {
    state: Arc<ThorState>,
    detection: Arc<DetectionEngine>,
    soar: Arc<SoarEngine>,
}

impl EventPipeline {
    pub fn new(
        state: Arc<ThorState>,
        detection: Arc<DetectionEngine>,
        soar: Arc<SoarEngine>,
    ) -> Self {
        Self { state, detection, soar }
    }

    pub fn spawn(
        self,
        raw_rx: flume::Receiver<RawEvent>,
        alert_tx: flume::Sender<Alert>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let dedup = EventDeduplicator::new(60);
            let enricher = EventEnricher::new(self.state.clone());
            let mut processed = 0u64;
            let mut alerts_generated = 0u64;

            info!("🔄 Event pipeline started");

            loop {
                // Batch process up to 256 events per iteration
                let mut batch = Vec::with_capacity(256);
                match raw_rx.try_recv() {
                    Ok(event) => { batch.push(event); }
                    Err(flume::TryRecvError::Empty) => {
                        // Yield when channel is empty
                        tokio::time::sleep(tokio::time::Duration::from_micros(100)).await;
                        continue;
                    }
                    Err(flume::TryRecvError::Disconnected) => {
                        warn!("Event channel disconnected, shutting down pipeline");
                        break;
                    }
                }
                // Drain up to 255 more
                for _ in 0..255 {
                    match raw_rx.try_recv() {
                        Ok(ev) => batch.push(ev),
                        Err(_) => break,
                    }
                }

                for raw_event in batch {
                    processed += 1;
                    if processed % 100_000 == 0 {
                        info!("📊 Pipeline: {} processed, {} alerts", processed, alerts_generated);
                    }

                    // 1. Deduplication — skip seen events
                    if dedup.is_duplicate(&raw_event) {
                        debug!("Dedup: skipping duplicate event");
                        continue;
                    }

                    // 2. Enrichment — add GeoIP, hostname, flow context
                    let enriched = enricher.enrich(raw_event).await;

                    // 3. State update
                    self.state.update(&enriched).await;

                    // 4. Detection (Sigma + YARA + IOC + ML)
                    let alerts = match self.detection.detect(&enriched).await {
                        Ok(a) => a,
                        Err(e) => { warn!("Detection error: {}", e); continue; }
                    };

                    // 5. SOAR response for each alert
                    for mut alert in alerts {
                        alerts_generated += 1;
                        let soar_actions = self.soar.respond(&alert).await;
                        alert.soar_actions_taken = soar_actions;

                        // Broadcast to WebSocket subscribers
                        if let Err(e) = alert_tx.try_send(alert) {
                            if matches!(e, flume::TrySendError::Full(_)) {
                                warn!("Alert channel full — dropping alert");
                            }
                        }
                    }
                }
            }
        })
    }
}
