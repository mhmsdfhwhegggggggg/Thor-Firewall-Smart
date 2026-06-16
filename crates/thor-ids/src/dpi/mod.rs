//! Neural DPI (Deep Packet Inspection) Engine.
//!
//! This module integrates:
//! - [`packet_encoder`]: Extracts 128-dimensional feature vectors from raw packets.
//! - [`protocol_classifier`]: Identifies actual application protocols regardless of declared port.
//! - [`anomaly_detector`]: Detects statistical anomalies in traffic streams.
//! - [`covert_channel_detector`]: Identifies DNS/HTTP/ICMP tunneling and covert channels.

pub mod packet_encoder;
pub mod protocol_classifier;
pub mod anomaly_detector;
pub mod covert_channel_detector;

use std::sync::Arc;
use tracing::{debug, warn};

use packet_encoder::{encode_packet, FEATURE_DIM};
use protocol_classifier::classify_packet;
use anomaly_detector::{AnomalyDetector, AnomalyResult};
use covert_channel_detector::{CovertChannelDetector, CovertChannelAlert};

// ─── DPI Analysis Result ──────────────────────────────────────────────────────

/// Complete DPI analysis result for a single packet.
#[derive(Debug)]
pub struct DpiResult {
    /// 128-dimensional feature vector (None if packet too short)
    pub features: Option<[f32; FEATURE_DIM]>,
    /// Protocol classification result
    pub protocol: Option<protocol_classifier::ClassificationResult>,
    /// Traffic anomaly result
    pub anomaly: Option<AnomalyResult>,
    /// Covert channel alerts
    pub covert_alerts: Vec<CovertChannelAlert>,
    /// Composite threat score combining all signals in [0.0, 1.0]
    pub threat_score: f32,
}

impl DpiResult {
    /// Returns true if any high-confidence threat was detected.
    pub fn is_threatening(&self) -> bool {
        self.threat_score > 0.6
    }
}

// ─── Engine ───────────────────────────────────────────────────────────────────

/// The main Neural DPI engine integrating all sub-analyzers.
pub struct DpiEngine {
    anomaly: AnomalyDetector,
    covert: CovertChannelDetector,
}

impl DpiEngine {
    /// Create a new DPI engine.
    pub fn new() -> Self {
        Self {
            anomaly: AnomalyDetector::new(),
            covert: CovertChannelDetector::new(),
        }
    }

    /// Analyze a raw packet (starting from IP header).
    ///
    /// `stream_key` identifies the traffic flow (e.g. `"src_ip:dst_ip:dst_port"`).
    /// `l4_proto` is the IP protocol byte (6=TCP, 17=UDP, 1=ICMP).
    pub fn analyze(
        &self,
        raw: &[u8],
        stream_key: &str,
        l4_proto: u8,
        dst_port: u16,
        src_ip: Option<&str>,
    ) -> DpiResult {
        // 1. Feature extraction
        let features = encode_packet(raw);

        // 2. Protocol classification
        let protocol = classify_packet(raw, dst_port);

        // 3. Extract payload for further analysis
        let ihl = if raw.len() >= 1 { ((raw[0] & 0xF) * 4) as usize } else { 20 };
        let transport_offset = ihl + if l4_proto == 6 && raw.len() > ihl + 12 {
            ((raw[ihl + 12] >> 4) * 4) as usize
        } else { 8 };
        let payload = if transport_offset < raw.len() { &raw[transport_offset..] } else { &[] };

        // 4. Anomaly detection
        let entropy = features.map(|f| f[32]).unwrap_or(0.0);
        let anomaly = Some(self.anomaly.observe(stream_key, raw.len(), entropy));

        // 5. Covert channel detection
        let covert_alerts = self.covert.analyze(payload, l4_proto, dst_port, src_ip);

        // 6. Compute composite threat score
        let mut score = 0.0f32;

        if let Some(ref a) = anomaly {
            if a.is_anomalous { score += a.score * 0.3; }
        }
        if let Some(ref p) = protocol {
            if p.is_suspicious() { score += p.confidence * 0.4; }
        }
        for alert in &covert_alerts {
            score += alert.confidence * 0.5;
        }

        let threat_score = score.min(1.0);

        if threat_score > 0.5 {
            debug!(
                "🔍 DPI threat detected on stream '{}': score={:.3} covert_alerts={}",
                stream_key, threat_score, covert_alerts.len()
            );
        }

        DpiResult {
            features,
            protocol,
            anomaly,
            covert_alerts,
            threat_score,
        }
    }

    /// Run periodic cleanup — evict stale stream state.
    pub fn cleanup(&self) -> usize {
        self.anomaly.evict_stale()
    }
}

impl Default for DpiEngine {
    fn default() -> Self { Self::new() }
}
