use dashmap::DashMap;
use bytes::BytesMut;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

pub struct TcpReassembler {
    // Temporary storage for each network flow
    streams: DashMap<FlowKey, (BytesMut, Instant)>,
    #[allow(dead_code)]
    max_buffer_size: usize,
    timeout: Duration,
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self {
            streams: DashMap::new(),
            max_buffer_size: 65535, // 64KB max per flow
            timeout: Duration::from_secs(30),
        }
    }

    /// Add new payload to the flow and reassemble
    pub fn push_payload(&self, key: FlowKey, payload: &[u8], _seq: u32) -> Option<BytesMut> {
        let now = Instant::now();
        let mut entry = self.streams.entry(key).or_insert_with(|| (BytesMut::new(), now));
        
        // Update last activity to prevent memory leak
        entry.1 = now;

        // Add the data (In real prod, sort by TCP Sequence Number)
        entry.0.extend_from_slice(payload);

        // If sufficient payload was gathered to scan (e.g. 512 bytes), return it and clear buffer
        if entry.0.len() >= 512 {
            let complete_payload = entry.0.clone();
            entry.0.clear(); // Reset for next flow chunk
            return Some(complete_payload);
        }

        None
    }

    /// Clean up stale flows (To be called every 5 secs in background)
    pub fn cleanup_stale_flows(&self) {
        let now = Instant::now();
        self.streams.retain(|_key, (_, last_seen)| {
            now.duration_since(*last_seen) < self.timeout
        });
    }
}
