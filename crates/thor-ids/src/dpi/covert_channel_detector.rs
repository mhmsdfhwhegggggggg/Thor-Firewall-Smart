//! Covert Channel Detector — identifies tunneling and data exfiltration
//! through DNS, HTTP, ICMP, and other protocols.
//!
//! Detection strategies:
//! 1. **DNS Tunneling**: abnormally long subdomain labels, high label entropy,
//!    unusual record types, excessive query rate from a single source.
//! 2. **HTTP Tunneling**: unusual HTTP methods, very large or very small
//!    payloads, base64/hex-encoded paths, abnormal User-Agent strings.
//! 3. **ICMP Tunneling**: ICMP data payloads containing non-echo patterns,
//!    oversized ICMP packets, high entropy payload.
//! 4. **Port-Protocol Mismatch**: protocol data inconsistent with port (from
//!    [`protocol_classifier`]).

use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use tracing::debug;

use super::protocol_classifier::{classify, Protocol, ClassificationResult};
use super::packet_encoder::shannon_entropy;

// ─── Detection result ─────────────────────────────────────────────────────────

/// A detected covert channel indicator.
#[derive(Debug, Clone)]
pub struct CovertChannelAlert {
    /// Which channel type was detected
    pub channel_type: ChannelType,
    /// Confidence score in [0.0, 1.0]
    pub confidence: f32,
    /// Human-readable explanation
    pub description: String,
    /// Source IP (if extractable)
    pub src_ip: Option<String>,
    /// Destination port
    pub dst_port: u16,
    /// The evidence bytes that triggered the detection (first 64 bytes)
    pub evidence: Vec<u8>,
}

/// Type of covert channel detected.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChannelType {
    DnsTunnel,
    HttpTunnel,
    IcmpTunnel,
    PortProtocolMismatch,
    HighEntropyUnexpected,
}

impl ChannelType {
    pub fn label(&self) -> &'static str {
        match self {
            ChannelType::DnsTunnel => "DNS_TUNNEL",
            ChannelType::HttpTunnel => "HTTP_TUNNEL",
            ChannelType::IcmpTunnel => "ICMP_TUNNEL",
            ChannelType::PortProtocolMismatch => "PORT_PROTOCOL_MISMATCH",
            ChannelType::HighEntropyUnexpected => "HIGH_ENTROPY_UNEXPECTED",
        }
    }
}

// ─── Per-source DNS tracking ──────────────────────────────────────────────────

const DNS_WINDOW_SECS: u64 = 60;
const DNS_QUERY_THRESHOLD: usize = 100; // queries per minute to flag

struct DnsSourceState {
    query_times: VecDeque<Instant>,
    long_label_count: usize,
    total_queries: usize,
}

impl DnsSourceState {
    fn new() -> Self {
        Self {
            query_times: VecDeque::with_capacity(256),
            long_label_count: 0,
            total_queries: 0,
        }
    }

    fn record_query(&mut self, has_long_label: bool) -> usize {
        let now = Instant::now();
        let window = Duration::from_secs(DNS_WINDOW_SECS);
        // Evict old entries
        while self.query_times.front().map(|t| now.duration_since(*t) > window).unwrap_or(false) {
            self.query_times.pop_front();
        }
        self.query_times.push_back(now);
        self.total_queries += 1;
        if has_long_label { self.long_label_count += 1; }
        self.query_times.len() // queries in current window
    }
}

// ─── Engine ───────────────────────────────────────────────────────────────────

/// The covert channel detection engine.
pub struct CovertChannelDetector {
    /// Per-source DNS query state for rate-based detection
    dns_state: DashMap<String, DnsSourceState>,
}

impl CovertChannelDetector {
    pub fn new() -> Self {
        Self {
            dns_state: DashMap::new(),
        }
    }

    /// Analyze a payload for covert channel indicators.
    ///
    /// `protocol` is the L4 protocol byte (6=TCP, 17=UDP, 1=ICMP).
    /// `dst_port` is the destination port (0 for ICMP).
    /// `src_ip` is the source IP as a string (for rate tracking).
    pub fn analyze(
        &self,
        payload: &[u8],
        protocol: u8,
        dst_port: u16,
        src_ip: Option<&str>,
    ) -> Vec<CovertChannelAlert> {
        let mut alerts = Vec::new();

        // 1. DNS tunneling detection (UDP/53 or TCP/53)
        if dst_port == 53 || dst_port == 5353 {
            if let Some(alert) = self.check_dns_tunnel(payload, src_ip) {
                alerts.push(alert);
            }
        }

        // 2. HTTP tunneling detection
        if dst_port == 80 || dst_port == 8080 || dst_port == 8000 || dst_port == 3128 {
            if let Some(alert) = self.check_http_tunnel(payload, dst_port) {
                alerts.push(alert);
            }
        }

        // 3. ICMP tunneling (protocol == 1)
        if protocol == 1 {
            if let Some(alert) = self.check_icmp_tunnel(payload, src_ip) {
                alerts.push(alert);
            }
        }

        // 4. Port-protocol mismatch detection
        let classification = classify(payload, dst_port);
        if classification.is_suspicious() {
            alerts.push(CovertChannelAlert {
                channel_type: ChannelType::PortProtocolMismatch,
                confidence: classification.confidence,
                description: format!(
                    "Detected {} protocol on port {} (expected different protocol)",
                    classification.protocol.label(), dst_port
                ),
                src_ip: src_ip.map(str::to_string),
                dst_port,
                evidence: payload[..payload.len().min(64)].to_vec(),
            });
        }

        // 5. High-entropy payload on non-encrypted ports
        if !is_expected_encrypted_port(dst_port) && !payload.is_empty() {
            let entropy = shannon_entropy(payload);
            if entropy > 0.92 && payload.len() > 32 {
                alerts.push(CovertChannelAlert {
                    channel_type: ChannelType::HighEntropyUnexpected,
                    confidence: (entropy - 0.92) * 12.5, // scales 0.92-1.0 → 0.0-1.0
                    description: format!(
                        "High entropy payload ({:.3}) on non-encrypted port {} — possible tunneling",
                        entropy, dst_port
                    ),
                    src_ip: src_ip.map(str::to_string),
                    dst_port,
                    evidence: payload[..payload.len().min(64)].to_vec(),
                });
            }
        }

        alerts
    }

    /// DNS tunneling heuristics:
    /// 1. Subdomain label length > 30 characters
    /// 2. Label entropy > 0.8 (random-looking, as in base32/base64 encoded data)
    /// 3. Query rate exceeding threshold
    fn check_dns_tunnel(&self, payload: &[u8], src_ip: Option<&str>) -> Option<CovertChannelAlert> {
        if payload.len() < 12 { return None; }

        // Parse the DNS question section (after 12-byte header)
        let mut pos = 12usize;
        let mut max_label_len = 0usize;
        let mut labels: Vec<&[u8]> = Vec::new();

        while pos < payload.len() {
            let label_len = payload[pos] as usize;
            if label_len == 0 { break; }
            if label_len & 0xC0 == 0xC0 { break; } // compression pointer
            pos += 1;
            if pos + label_len > payload.len() { break; }
            labels.push(&payload[pos..pos + label_len]);
            max_label_len = max_label_len.max(label_len);
            pos += label_len;
        }

        let has_long_label = max_label_len > 30;

        // Calculate entropy of the longest label
        let label_entropy = labels.iter()
            .max_by_key(|l| l.len())
            .map(|l| shannon_entropy(l))
            .unwrap_or(0.0);

        let is_suspicious = has_long_label || label_entropy > 0.75;

        // Update rate state
        let qps = if let Some(ip) = src_ip {
            let mut state = self.dns_state.entry(ip.to_string()).or_insert_with(DnsSourceState::new);
            state.record_query(has_long_label)
        } else { 0 };

        if is_suspicious || qps > DNS_QUERY_THRESHOLD {
            let confidence = {
                let mut score = 0.0f32;
                if has_long_label { score += 0.4; }
                if label_entropy > 0.75 { score += label_entropy * 0.4; }
                if qps > DNS_QUERY_THRESHOLD { score += 0.3; }
                score.min(1.0)
            };

            Some(CovertChannelAlert {
                channel_type: ChannelType::DnsTunnel,
                confidence,
                description: format!(
                    "DNS tunneling indicators: max_label_len={} label_entropy={:.3} qps={}",
                    max_label_len, label_entropy, qps
                ),
                src_ip: src_ip.map(str::to_string),
                dst_port: 53,
                evidence: payload[..payload.len().min(64)].to_vec(),
            })
        } else {
            None
        }
    }

    /// HTTP tunneling heuristics:
    /// 1. Base64 or hex encoded URL paths
    /// 2. Unusual HTTP methods (CONNECT to non-proxy)
    /// 3. Very large HTTP GET body (unusual)
    /// 4. Suspicious User-Agent strings
    fn check_http_tunnel(&self, payload: &[u8], dst_port: u16) -> Option<CovertChannelAlert> {
        let text = std::str::from_utf8(payload).ok()?;
        let first_line = text.lines().next()?;

        let mut score = 0.0f32;
        let mut reasons = Vec::new();

        // Check for CONNECT method on non-proxy port
        if first_line.starts_with("CONNECT ") && dst_port != 3128 && dst_port != 8080 {
            score += 0.6;
            reasons.push("CONNECT method on non-proxy port");
        }

        // Check for base64-encoded path (long, looks base64)
        if let Some(path) = extract_http_path(first_line) {
            let clean_path = path.trim_start_matches('/');
            if clean_path.len() > 50 && is_base64_like(clean_path.as_bytes()) {
                score += 0.5;
                reasons.push("base64-encoded URL path");
            }
        }

        // Check for suspicious User-Agent
        if let Some(ua_line) = text.lines().find(|l| l.to_lowercase().starts_with("user-agent:")) {
            let ua = ua_line.to_lowercase();
            for suspicious in &["python-requests", "go-http-client", "curl/", "wget/", "-"] {
                if ua.contains(suspicious) {
                    score += 0.2;
                    reasons.push("suspicious User-Agent");
                    break;
                }
            }
        }

        if score > 0.4 {
            Some(CovertChannelAlert {
                channel_type: ChannelType::HttpTunnel,
                confidence: score.min(1.0),
                description: format!("HTTP tunneling indicators: {}", reasons.join(", ")),
                src_ip: None,
                dst_port,
                evidence: payload[..payload.len().min(64)].to_vec(),
            })
        } else {
            None
        }
    }

    /// ICMP tunneling heuristics:
    /// 1. ICMP data payload larger than expected (> 64 bytes for echo)
    /// 2. Non-echo ICMP types with data payload
    /// 3. High entropy in ICMP data section
    fn check_icmp_tunnel(&self, payload: &[u8], src_ip: Option<&str>) -> Option<CovertChannelAlert> {
        if payload.len() < 8 { return None; }
        let icmp_type = payload[0];
        let icmp_data = &payload[8..]; // ICMP header is 8 bytes

        let entropy = shannon_entropy(icmp_data);
        let data_len = icmp_data.len();

        let mut score = 0.0f32;
        let mut reasons = Vec::new();

        // Oversized ICMP echo payload
        if icmp_type == 8 && data_len > 64 {
            score += 0.4;
            reasons.push(format!("oversized ICMP echo payload ({} bytes)", data_len));
        }

        // Non-echo ICMP type with significant payload
        if icmp_type != 8 && icmp_type != 0 && data_len > 16 {
            score += 0.3;
            reasons.push(format!("ICMP type {} with {} byte payload", icmp_type, data_len));
        }

        // High entropy in ICMP data
        if entropy > 0.85 && data_len > 16 {
            score += entropy * 0.4;
            reasons.push(format!("high entropy payload ({:.3})", entropy));
        }

        if score > 0.4 {
            Some(CovertChannelAlert {
                channel_type: ChannelType::IcmpTunnel,
                confidence: score.min(1.0),
                description: format!("ICMP tunneling indicators: {}", reasons.join(", ")),
                src_ip: src_ip.map(str::to_string),
                dst_port: 0,
                evidence: payload[..payload.len().min(64)].to_vec(),
            })
        } else {
            None
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn is_expected_encrypted_port(port: u16) -> bool {
    matches!(port, 443 | 8443 | 465 | 993 | 995 | 636 | 8883 | 4433)
}

fn extract_http_path(request_line: &str) -> Option<&str> {
    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() >= 2 { Some(parts[1]) } else { None }
}

fn is_base64_like(data: &[u8]) -> bool {
    if data.len() < 20 { return false; }
    let base64_chars = data.iter().filter(|&&b| {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b == b'-' || b == b'_'
    }).count();
    base64_chars as f32 / data.len() as f32 > 0.90
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_tunnel_long_label() {
        let detector = CovertChannelDetector::new();
        // Construct a DNS query with a 50-char subdomain label
        let label = b"aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkaGVsbG93"; // 48 bytes base32-like
        let mut payload = vec![
            0x12, 0x34, // transaction ID
            0x01, 0x00, // flags: standard query
            0x00, 0x01, // qdcount=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ancount, nscount, arcount
        ];
        payload.push(label.len() as u8);
        payload.extend_from_slice(label);
        payload.extend_from_slice(b"\x07example\x03com\x00"); // .example.com
        payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN

        let alerts = detector.analyze(&payload, 17, 53, Some("10.0.0.1"));
        assert!(!alerts.is_empty(), "Long DNS label should trigger alert");
        assert_eq!(alerts[0].channel_type, ChannelType::DnsTunnel);
    }

    #[test]
    fn test_icmp_tunnel_oversized() {
        let detector = CovertChannelDetector::new();
        // ICMP echo request (type=8) with 100-byte payload
        let mut payload = vec![0x08u8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]; // ICMP header
        payload.extend_from_slice(&[0xAAu8; 100]); // oversized data

        let alerts = detector.analyze(&payload, 1, 0, Some("10.0.0.2"));
        assert!(!alerts.is_empty(), "Oversized ICMP should trigger alert");
        assert_eq!(alerts[0].channel_type, ChannelType::IcmpTunnel);
    }

    #[test]
    fn test_http_on_wrong_port_flagged() {
        let detector = CovertChannelDetector::new();
        let payload = b"GET /aGVsbG93b3JsZGhlbGxvd29ybGQgaGVsbG93b3JsZGhlbGxvd29ybGQ= HTTP/1.1\r\nHost: evil.com\r\n\r\n";
        let alerts = detector.analyze(payload, 6, 443, None); // HTTP on HTTPS port
        // Should trigger port-protocol mismatch
        let mismatch = alerts.iter().any(|a| a.channel_type == ChannelType::PortProtocolMismatch);
        assert!(mismatch, "HTTP on port 443 should trigger mismatch");
    }

    #[test]
    fn test_high_entropy_non_tls_port() {
        let detector = CovertChannelDetector::new();
        // High entropy payload on port 80 (not expected to be encrypted)
        let payload: Vec<u8> = (0u8..=255).cycle().take(256).collect();
        let alerts = detector.analyze(&payload, 6, 80, Some("192.168.1.100"));
        let high_entropy = alerts.iter().any(|a| a.channel_type == ChannelType::HighEntropyUnexpected);
        assert!(high_entropy, "High entropy on port 80 should trigger alert");
    }

    #[test]
    fn test_normal_http_no_alert() {
        let detector = CovertChannelDetector::new();
        let payload = b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        let alerts = detector.analyze(payload, 6, 80, Some("10.0.0.5"));
        // Normal HTTP GET should not trigger any alerts
        assert!(alerts.is_empty() || alerts.iter().all(|a| a.confidence < 0.5),
            "Normal HTTP should not produce high-confidence alerts");
    }
}
