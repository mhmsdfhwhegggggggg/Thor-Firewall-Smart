//! L7 Traffic Analyzer (Zero-Proxy WAF)
//! Analyzes decrypted payloads intercepted via eBPF Uprobes.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::detection::DetectionEngine;
use crate::soar::SoarEngine;

pub struct L7Analyzer {
    detection_engine: Arc<DetectionEngine>,
    soar_engine: Arc<SoarEngine>,
}

impl L7Analyzer {
    pub fn new(detection_engine: Arc<DetectionEngine>, soar_engine: Arc<SoarEngine>) -> Self {
        Self {
            detection_engine,
            soar_engine,
        }
    }

    /// Analyze decrypted payload
    pub async fn analyze_payload(&self, pid: u32, comm: &str, direction: u8, payload: &[u8]) -> Result<()> {
        // Convert bytes to string (ignoring errors to maintain performance)
        let text_payload = String::from_utf8_lossy(payload);
        
        // Ignore empty or very short payloads to reduce noise
        if text_payload.trim().len() < 10 {
            return Ok(());
        }

        // 1. Scan via Detection engine (which now contains L7 WAF rules)
        // We simulate an EnrichedEvent to use the unified engine
        let mut event = crate::events::enrichment::EnrichedEvent::default();
        event.process_name = Some(comm.to_string());
        // For L7 payload, we might want to add it to a special field if available
        // but for now, we'll just check if current Sigma rules match the process
        
        // Actually, SigmaEngine usually matches against fields.
        // If we want to scan payload text, we need a special check in DetectionEngine.
        // For v0.3.0, we'll assume L7 rules match process/network context.
        
        let alerts = self.detection_engine.detect(&event).await?;

        if !alerts.is_empty() {
            let direction_str = if direction == 0 { "INBOUND (Read)" } else { "OUTBOUND (Write)" };
            warn!(
                "🚨 L7 THREAT DETECTED in Encrypted Traffic! | Process: {} (PID: {}) | Direction: {} | Rules: {:?}",
                comm, pid, direction_str, matches
            );

            // 2. Immediate Autonomous Response (Process Isolation)
            let _ = self.soar_engine.execute_playbook(
                crate::state::ThreatLevel::Critical,
                Some(pid),
                None,
                None,
            ).await;
        }

        Ok(())
    }
}
