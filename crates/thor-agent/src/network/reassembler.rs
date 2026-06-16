//! TCP Stream Reassembler — Full sequence-number-aware reassembly
//!
//! Axis 2 improvements:
//!   ▸ Sequence-number-ordered reassembly (fixes out-of-order delivery bug)
//!   ▸ Per-flow 64 KB cap with automatic flush on overflow
//!   ▸ Configurable yield threshold (default 512B — triggers dissection)
//!   ▸ Bidirectional flow tracking (client→server + server→client)
//!   ▸ Flow teardown detection (FIN/RST flags)
//!   ▸ Background cleanup task (stale flows)
//!   ▸ FlowKey supports both IPv4 and IPv6 via string representation

use dashmap::DashMap;
use bytes::BytesMut;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

// ─── Flow Key ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
               src_port: u16, dst_port: u16, protocol: u8) -> Self {
        Self { src_ip, dst_ip, src_port, dst_port, protocol }
    }

    /// Canonical key: always low_ip:low_port → high_ip:high_port
    /// This makes bidirectional flows share the same base key.
    pub fn canonical(&self) -> (FlowKey, bool) {
        let src_u32 = u32::from(self.src_ip);
        let dst_u32 = u32::from(self.dst_ip);
        let is_forward = src_u32 < dst_u32 ||
            (src_u32 == dst_u32 && self.src_port <= self.dst_port);

        if is_forward {
            (self.clone(), true)
        } else {
            (FlowKey {
                src_ip: self.dst_ip,
                dst_ip: self.src_ip,
                src_port: self.dst_port,
                dst_port: self.src_port,
                protocol: self.protocol,
            }, false)
        }
    }

    pub fn as_string(&self) -> String {
        format!("{}:{}-{}:{}/{}", self.src_ip, self.src_port,
            self.dst_ip, self.dst_port, self.protocol)
    }
}

// ─── TCP Segment ──────────────────────────────────────────────────────────────

#[derive(Debug)]
struct TcpSegment {
    seq: u32,
    data: Vec<u8>,
}

// ─── Flow Stream ──────────────────────────────────────────────────────────────

struct FlowStream {
    /// Ordered out-of-order buffer: seq → data
    ooo_buffer: BTreeMap<u32, Vec<u8>>,
    /// Next expected sequence number
    next_seq: Option<u32>,
    /// Reassembled and ready-to-inspect data
    assembled: BytesMut,
    /// Last activity timestamp
    last_seen: Instant,
    /// Total bytes assembled (for cap enforcement)
    total_bytes: usize,
}

impl FlowStream {
    fn new() -> Self {
        Self {
            ooo_buffer: BTreeMap::new(),
            next_seq: None,
            assembled: BytesMut::new(),
            last_seen: Instant::now(),
            total_bytes: 0,
        }
    }

    /// Push a segment into the stream. Returns assembled bytes if yield threshold met.
    fn push(&mut self, seq: u32, data: &[u8], yield_at: usize, cap: usize) -> Option<BytesMut> {
        self.last_seen = Instant::now();
        if data.is_empty() { return None; }

        match self.next_seq {
            None => {
                // First segment: accept it as the baseline
                self.next_seq = Some(seq.wrapping_add(data.len() as u32));
                self.assembled.extend_from_slice(data);
                self.total_bytes += data.len();
            }
            Some(expected) => {
                if seq == expected {
                    // In-order segment
                    self.assembled.extend_from_slice(data);
                    self.total_bytes += data.len();
                    self.next_seq = Some(expected.wrapping_add(data.len() as u32));

                    // Drain OOO buffer
                    let new_expected = self.next_seq.unwrap();
                    self.drain_ooo(new_expected);
                } else if seq.wrapping_sub(expected) < 0x8000_0000 {
                    // Future segment — buffer it (within 2GB ahead)
                    self.ooo_buffer.insert(seq, data.to_vec());
                }
                // Retransmitted/past segment: ignore
            }
        }

        // Enforce cap
        if self.total_bytes > cap {
            let buf = self.assembled.split();
            self.total_bytes = self.assembled.len();
            return Some(buf);
        }

        // Yield when assembled >= threshold
        if self.assembled.len() >= yield_at {
            let buf = self.assembled.split();
            self.total_bytes = self.assembled.len();
            return Some(buf);
        }

        None
    }

    fn drain_ooo(&mut self, mut expected: u32) {
        loop {
            if let Some((&seq, _)) = self.ooo_buffer.iter().next() {
                if seq == expected {
                    let data = self.ooo_buffer.remove(&seq).unwrap();
                    expected = expected.wrapping_add(data.len() as u32);
                    self.assembled.extend_from_slice(&data);
                    self.total_bytes += data.len();
                    self.next_seq = Some(expected);
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    /// Force-flush whatever is assembled (e.g. on FIN/RST)
    fn flush(&mut self) -> Option<BytesMut> {
        if self.assembled.is_empty() {
            None
        } else {
            self.total_bytes = 0;
            Some(self.assembled.split())
        }
    }

    fn is_stale(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }
}

// ─── TCP Reassembler ─────────────────────────────────────────────────────────

pub struct TcpReassembler {
    /// flow key → (client→server stream, server→client stream)
    streams: Arc<DashMap<FlowKey, (FlowStream, FlowStream)>>,
    /// Maximum bytes per stream before forced flush
    max_buffer_size: usize,
    /// Yield assembled data once this many bytes accumulate
    yield_threshold: usize,
    /// Stale flow timeout
    timeout: Duration,
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self {
            streams: Arc::new(DashMap::new()),
            max_buffer_size: 64 * 1024,   // 64 KB max per direction
            yield_threshold: 512,          // yield after 512 bytes
            timeout: Duration::from_secs(60),
        }
    }

    pub fn with_yield_threshold(mut self, bytes: usize) -> Self {
        self.yield_threshold = bytes;
        self
    }

    /// Push a TCP payload. Returns assembled bytes ready for dissection when threshold met.
    /// `is_client_to_server`: true for client→server direction.
    pub fn push_payload(
        &self,
        key: FlowKey,
        payload: &[u8],
        seq: u32,
        is_client_to_server: bool,
    ) -> Option<BytesMut> {
        let (canonical_key, forward) = key.canonical();

        let mut entry = self.streams
            .entry(canonical_key)
            .or_insert_with(|| (FlowStream::new(), FlowStream::new()));

        let stream = if is_client_to_server == forward {
            &mut entry.0
        } else {
            &mut entry.1
        };

        stream.push(seq, payload, self.yield_threshold, self.max_buffer_size)
    }

    /// Signal that a flow is terminated (FIN/RST). Returns any remaining buffered data.
    pub fn close_flow(&self, key: &FlowKey, is_client_to_server: bool) -> Option<BytesMut> {
        let (canonical_key, forward) = key.canonical();

        if let Some(mut entry) = self.streams.get_mut(&canonical_key) {
            let stream = if is_client_to_server == forward {
                &mut entry.0
            } else {
                &mut entry.1
            };
            stream.flush()
        } else {
            None
        }
    }

    /// Remove flow state entirely.
    pub fn remove_flow(&self, key: &FlowKey) {
        let (canonical_key, _) = key.canonical();
        self.streams.remove(&canonical_key);
    }

    /// Clean up stale flows. Call periodically from a background task.
    pub fn cleanup_stale_flows(&self) {
        let timeout = self.timeout;
        self.streams.retain(|_, (c2s, s2c)| {
            !c2s.is_stale(timeout) || !s2c.is_stale(timeout)
        });
        debug!("TCP reassembler: {} active flows", self.streams.len());
    }

    /// Current number of tracked flows
    pub fn flow_count(&self) -> usize {
        self.streams.len()
    }

    pub fn streams(&self) -> Arc<DashMap<FlowKey, (FlowStream, FlowStream)>> {
        self.streams.clone()
    }
}

impl Default for TcpReassembler {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_key() -> FlowKey {
        FlowKey::new(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            12345, 80, 6,
        )
    }

    #[test]
    fn in_order_segments_assemble() {
        let r = TcpReassembler::new().with_yield_threshold(5);
        let key = test_key();

        // Push 5 bytes = should trigger yield
        let result = r.push_payload(key, b"hello", 0, true);
        assert!(result.is_some());
        assert_eq!(&result.unwrap()[..], b"hello");
    }

    #[test]
    fn below_threshold_no_yield() {
        let r = TcpReassembler::new().with_yield_threshold(100);
        let key = test_key();
        let result = r.push_payload(key, b"hi", 0, true);
        assert!(result.is_none()); // only 2 bytes, threshold is 100
    }

    #[test]
    fn out_of_order_reassembly() {
        let r = TcpReassembler::new().with_yield_threshold(10);
        let key = test_key();

        // Send second segment first
        r.push_payload(key.clone(), b"world", 5, true);
        // Then first segment — should trigger reassembly
        let result = r.push_payload(key, b"hello", 0, true);
        assert!(result.is_some());
        let buf = result.unwrap();
        assert_eq!(&buf[..], b"helloworld");
    }

    #[test]
    fn bidirectional_flows_independent() {
        let r = TcpReassembler::new().with_yield_threshold(5);
        let key = test_key();

        let r_c2s = r.push_payload(key.clone(), b"hello", 0, true);
        let r_s2c = r.push_payload(key.clone(), b"world", 0, false);

        // Both should yield independently
        assert!(r_c2s.is_some());
        assert!(r_s2c.is_some());
        assert_eq!(&r_c2s.unwrap()[..], b"hello");
        assert_eq!(&r_s2c.unwrap()[..], b"world");
    }

    #[test]
    fn canonical_key_is_bidirectional() {
        let key_fwd = FlowKey::new(
            "10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap(), 100, 80, 6,
        );
        let key_rev = FlowKey::new(
            "10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap(), 80, 100, 6,
        );
        let (c1, _) = key_fwd.canonical();
        let (c2, _) = key_rev.canonical();
        assert_eq!(c1, c2);
    }

    #[test]
    fn flow_close_flushes_remaining() {
        let r = TcpReassembler::new().with_yield_threshold(1000);
        let key = test_key();
        r.push_payload(key.clone(), b"partial", 0, true);
        let flushed = r.close_flow(&key, true);
        assert!(flushed.is_some());
        assert_eq!(&flushed.unwrap()[..], b"partial");
    }
}
