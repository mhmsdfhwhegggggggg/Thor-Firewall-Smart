//! Enterprise SIEM Exporter
//! Sends Thor events to Splunk, QRadar, ArcSight, Elastic in standard formats

use anyhow::Result;
use chrono::Utc;
use std::net::UdpSocket;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, error};
use serde::Serialize;

use crate::events::Alert;
use thor_common::ThreatLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiemFormat {
    CEF,   // ArcSight, QRadar, Splunk
    LEEF,  // IBM QRadar native
    JSON,  // Splunk HEC, Elastic, Datadog
}

#[derive(Debug, Clone)]
pub struct SiemConfig {
    pub target_addr: String,
    pub format: SiemFormat,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub use_tls: bool,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            target_addr: "127.0.0.1:514".to_string(),
            format: SiemFormat::CEF,
            vendor: "ThorFirewall".to_string(),
            product: "AI-Agent".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            use_tls: false,
        }
    }
}

pub struct SiemExporter {
    config: SiemConfig,
    socket: UdpSocket,
    events_sent: Arc<std::sync::atomic::AtomicU64>,
}

impl SiemExporter {
    pub fn new(config: SiemConfig) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_nonblocking(true)?;
        
        info!(
            "📡 SIEM Exporter initialized | Target: {} | Format: {:?}",
            config.target_addr, config.format
        );
        
        Ok(Self {
            config,
            socket,
            events_sent: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    pub fn export_event(&self, event: &Alert) -> Result<()> {
        let formatted = match self.config.format {
            SiemFormat::CEF => self.format_cef(event),
            SiemFormat::LEEF => self.format_leef(event),
            SiemFormat::JSON => self.format_json(event)?,
        };
        
        match self.socket.send_to(formatted.as_bytes(), &self.config.target_addr) {
            Ok(_) => {
                self.events_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                warn!("Failed to send SIEM event: {}", e);
                Err(e.into())
            }
        }
    }

    fn format_cef(&self, event: &Alert) -> String {
        let (signature_id, name, severity, extensions) = self.extract_event_fields(event);
        
        format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|{}",
            self.config.vendor,
            self.config.product,
            self.config.version,
            signature_id,
            name,
            severity,
            extensions
        )
    }

    fn format_leef(&self, event: &Alert) -> String {
        let (_signature_id, name, _severity, extensions) = self.extract_event_fields(event);
        
        format!(
            "LEEF:2.0|{}|{}|{}|{}|{}",
            self.config.vendor,
            self.config.product,
            self.config.version,
            name,
            extensions
        )
    }

    fn format_json(&self, event: &Alert) -> Result<String> {
        let payload = SiemJsonPayload {
            timestamp: Utc::now().to_rfc3339(),
            vendor: self.config.vendor.clone(),
            product: self.config.product.clone(),
            event_type: "ThreatDetected".to_string(),
            severity: self.get_severity(event),
            details: serde_json::to_value(event)?,
        };
        
        Ok(serde_json::to_string(&payload)?)
    }

    fn extract_event_fields(&self, event: &Alert) -> (String, String, u8, String) {
        let severity = self.get_severity(event);
        let extensions = format!(
            "src={} dst={} spt={} dpt={} app={} msg={} cat=ThreatDetection actions={}",
            event.src_ip.as_deref().unwrap_or("-"),
            event.dst_ip.as_deref().unwrap_or("-"),
            0,
            event.dst_port.unwrap_or(0),
            event.process_name.as_deref().unwrap_or("-"),
            event.rule_name.replace("|", "\\|"),
            event.soar_actions_taken.join(",")
        );
        
        (
            "THREAT-001".to_string(),
            format!("Thor Threat Detected: {}", event.rule_name),
            severity,
            extensions,
        )
    }

    fn get_severity(&self, event: &Alert) -> u8 {
        match event.threat_level {
            ThreatLevel::Critical => 10,
            ThreatLevel::High => 8,
            ThreatLevel::Medium => 5,
            ThreatLevel::Low => 3,
            ThreatLevel::Neutral => 1,
        }
    }

    pub fn get_stats(&self) -> u64 {
        self.events_sent.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[derive(Serialize)]
struct SiemJsonPayload {
    timestamp: String,
    vendor: String,
    product: String,
    event_type: String,
    severity: u8,
    details: serde_json::Value,
}

pub async fn run_siem_exporter_task(
    exporter: Arc<SiemExporter>,
    mut event_rx: mpsc::Receiver<Alert>,
) {
    info!("📡 SIEM Exporter task started");
    
    let mut failed_count = 0u64;
    
    while let Some(event) = event_rx.recv().await {
        if let Err(_e) = exporter.export_event(&event) {
            failed_count += 1;
            if failed_count % 100 == 0 {
                error!("SIEM exporter: {} events failed to send", failed_count);
            }
        }
    }
}
