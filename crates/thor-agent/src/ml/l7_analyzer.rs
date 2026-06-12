//! L7 Traffic Analyzer (Zero-Proxy WAF)
//! Analyzes decrypted payloads intercepted via eBPF Uprobes.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::detection::sigma::SigmaEngine;
use crate::soar::SoarEngine;

pub struct L7Analyzer {
    sigma_engine: Arc<RwLock<SigmaEngine>>,
    soar_engine: Arc<SoarEngine>,
}

impl L7Analyzer {
    pub fn new(sigma_engine: Arc<RwLock<SigmaEngine>>, soar_engine: Arc<SoarEngine>) -> Self {
        Self {
            sigma_engine,
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

        // 1. Scan via Sigma engine (which now contains L7 WAF rules)
        let engine = self.sigma_engine.read().await;
        // In reality you may need &text_payload instead of text_payload
        let matches = engine.evaluate(&text_payload);

        if !matches.is_empty() {
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
