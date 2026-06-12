//! Feature extractor — converts raw events to 32-dimensional float vectors for ONNX

use ndarray::Array1;
use crate::events::enrichment::EnrichedEvent;
use crate::events::RawEvent;
use super::FEATURE_DIMENSION;

pub struct FeatureExtractor;

impl FeatureExtractor {
    pub fn new() -> Self { Self }

    /// Extract FEATURE_DIMENSION-dimensional feature vector from an enriched event
    /// Returns None if the event type doesn't support ML scoring
    pub fn extract(&self, event: &EnrichedEvent) -> Option<Array1<f32>> {
        let mut features = vec![0.0f32; FEATURE_DIMENSION];

        match &event.raw {
            RawEvent::Network(e) => {
                // [0] Event type indicator (0=network, 1=process, 2=xdp)
                features[0] = 0.0;
                // [1] Destination port normalized (0-65535 → 0-1)
                features[1] = e.dst_port as f32 / 65535.0;
                // [2] Protocol (TCP=6→0.5, UDP=17→0.85, other→0)
                features[2] = match e.protocol { 6 => 0.5, 17 => 0.85, _ => 0.0 };
                // [3] Direction (0=inbound, 1=outbound)
                features[3] = 1.0; // Network events are outbound
                // [4] Is RFC1918 destination
                features[4] = if event.is_internal { 1.0 } else { 0.0 };
                // [5] UID normalized
                features[5] = (e.uid as f32 / 65535.0).min(1.0);
                // [6] PID normalized
                features[6] = (e.pid as f32 / 100000.0).min(1.0);
                // [7] Hour of day (0-23 → 0-1)
                features[7] = chrono::Utc::now().format("%H").to_string().parse::<f32>().unwrap_or(0.0) / 23.0;
                // [8-15] Destination IP octets normalized
                let dst_octets = e.dst_ip.octets();
                for (i, &octet) in dst_octets.iter().enumerate().take(4) {
                    features[8 + i] = octet as f32 / 255.0;
                }
                // [12-15] Comm hash (poor man's encoding)
                let comm_bytes = e.comm.as_bytes();
                for (i, &b) in comm_bytes.iter().enumerate().take(4) {
                    features[12 + i] = b as f32 / 255.0;
                }
                // [16-31] Reserved for flow statistics (packet rate, byte rate, etc.)
                // In production these would be populated from ThorState flows
            }
            RawEvent::Process(e) => {
                features[0] = 1.0; // Process event
                features[1] = (e.pid() as f32 / 100000.0).min(1.0);
                features[7] = chrono::Utc::now().format("%H").to_string().parse::<f32>().unwrap_or(0.0) / 23.0;
            }
            RawEvent::XdpDrop { src_port, dst_port, reason, src_ip, .. } => {
                features[0] = 2.0; // XDP event
                features[1] = *dst_port as f32 / 65535.0;
                features[2] = *src_port as f32 / 65535.0;
                features[3] = *reason as f32 / 3.0;
                let src_octets: [u8; 4] = src_ip.to_be_bytes();
                for (i, &octet) in src_octets.iter().enumerate().take(4) {
                    features[4 + i] = octet as f32 / 255.0;
                }
            }
        }

        Some(Array1::from_vec(features))
    }
}
