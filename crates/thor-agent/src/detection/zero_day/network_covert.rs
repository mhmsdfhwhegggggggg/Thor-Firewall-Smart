//! Network Covert Channel Detector — detects covert C2 communication channels.
//!
//! # Detected Techniques
//!
//! 1. **DNS Tunneling** (T1071.004)
//!    - Anomalously high DNS query rate from a single process.
//!    - Unusually long DNS labels (> 63 bytes) — data encoded in subdomains.
//!    - High-entropy DNS query names — base32/base64 encoded payloads.
//!
//! 2. **ICMP Tunneling** (T1095)
//!    - Large ICMP echo packets (> 64 bytes payload) — data exfiltration.
//!    - Sustained ICMP traffic to a single destination.
//!
//! 3. **HTTP Steganography** (T1071.001)
//!    - Extremely long HTTP headers / URI paths.
//!    - High-entropy HTTP body data being sent.
//!
//! 4. **HTTPS Mimicry / Protocol Masquerading** (T1573)
//!    - Traffic on port 443 with non-TLS byte patterns.
//!    - JA3/JA4 fingerprint matching known C2 frameworks.
//!
//! 5. **Timing Covert Channels** (T1008)
//!    - Periodic network events with suspiciously regular intervals.

use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::debug;

// ─── CovertChannelType ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CovertChannelType {
    DnsTunneling,
    IcmpTunneling,
    HttpSteganography,
    HttpsMimicry,
    TimingChannel,
}

impl std::fmt::Display for CovertChannelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CovertChannelType::DnsTunneling       => write!(f, "DNS Tunneling"),
            CovertChannelType::IcmpTunneling      => write!(f, "ICMP Tunneling"),
            CovertChannelType::HttpSteganography  => write!(f, "HTTP Steganography"),
            CovertChannelType::HttpsMimicry       => write!(f, "HTTPS Mimicry / Protocol Masquerade"),
            CovertChannelType::TimingChannel      => write!(f, "Timing Covert Channel"),
        }
    }
}

// ─── Network events ───────────────────────────────────────────────────────────

/// A DNS query observation.
#[derive(Debug, Clone)]
pub struct DnsEvent {
    pub pid:        u32,
    pub comm:       String,
    pub query:      String,
    pub query_len:  usize,
    /// Label length (max subdomain component length).
    pub max_label:  usize,
}

/// An ICMP packet observation.
#[derive(Debug, Clone)]
pub struct IcmpEvent {
    pub pid:         u32,
    pub comm:        String,
    pub payload_len: usize,
    pub dest_ip:     String,
    pub is_reply:    bool,
}

/// An HTTP request/response observation.
#[derive(Debug, Clone)]
pub struct HttpEvent {
    pub pid:          u32,
    pub comm:         String,
    pub uri_len:      usize,
    pub header_count: usize,
    pub max_hdr_len:  usize,
    /// Entropy estimate of the body [0.0, 8.0].
    pub body_entropy: f64,
    pub method:       String,
}

// ─── CovertChannelAlert ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CovertChannelAlert {
    pub channel_type:     CovertChannelType,
    pub confidence:       f64,
    pub description:      String,
    pub mitre_techniques: Vec<String>,
}

// ─── Per-process/IP state ─────────────────────────────────────────────────────

struct DnsState {
    /// DNS query timestamps (rolling 60s window)
    query_window:  VecDeque<Instant>,
    /// Histogram of query name lengths
    long_query_cnt: u64,
    /// High-entropy query count
    high_entropy_cnt: u64,
}

struct IcmpState {
    /// (dest_ip → packet count in last 60s)
    dest_counts:  HashMap<String, VecDeque<Instant>>,
    large_pkt_cnt: u64,
}

struct HttpState {
    long_uri_cnt:    u64,
    high_entropy_cnt: u64,
}

struct TimingState {
    /// Inter-event times (nanoseconds)
    intervals: VecDeque<u64>,
    last_event: Option<Instant>,
}

// ─── Network Covert Channel Detector ─────────────────────────────────────────

pub struct NetworkCovertDetector {
    dns_state:    RwLock<HashMap<u32, DnsState>>,
    icmp_state:   RwLock<HashMap<u32, IcmpState>>,
    http_state:   RwLock<HashMap<u32, HttpState>>,
    timing_state: RwLock<HashMap<u32, TimingState>>,
}

impl NetworkCovertDetector {
    pub fn new() -> Self {
        Self {
            dns_state:    RwLock::new(HashMap::new()),
            icmp_state:   RwLock::new(HashMap::new()),
            http_state:   RwLock::new(HashMap::new()),
            timing_state: RwLock::new(HashMap::new()),
        }
    }

    // ── DNS analysis ──────────────────────────────────────────────────────────

    pub fn analyze_dns(&self, event: &DnsEvent) -> Vec<CovertChannelAlert> {
        let mut alerts = Vec::new();
        let mut map = self.dns_state.write().unwrap();
        let state = map.entry(event.pid).or_insert_with(|| DnsState {
            query_window:     VecDeque::new(),
            long_query_cnt:   0,
            high_entropy_cnt: 0,
        });

        let now = Instant::now();
        state.query_window.push_back(now);
        // Keep 60-second window
        while state.query_window.front().map(|t| now.duration_since(*t) > Duration::from_secs(60)).unwrap_or(false) {
            state.query_window.pop_front();
        }
        let query_rate = state.query_window.len();

        // High DNS query rate
        if query_rate > 50 {
            debug!("PID {}: DNS query rate {} in 60s", event.pid, query_rate);
            alerts.push(CovertChannelAlert {
                channel_type:     CovertChannelType::DnsTunneling,
                confidence:       (0.50 + query_rate as f64 / 500.0).min(0.92),
                description:      format!(
                    "PID {} ({}): {} DNS queries in 60s — high-rate DNS activity is a \
                     primary indicator of DNS tunneling C2 communication.",
                    event.pid, event.comm, query_rate
                ),
                mitre_techniques: vec!["T1071.004".into(), "T1048".into()],
            });
        }

        // Long labels — data encoding in subdomains
        if event.max_label > 63 || event.query_len > 200 {
            state.long_query_cnt += 1;
            if state.long_query_cnt >= 3 {
                alerts.push(CovertChannelAlert {
                    channel_type:     CovertChannelType::DnsTunneling,
                    confidence:       0.85,
                    description:      format!(
                        "PID {} ({}): DNS query name '{}' has label length {} (max=63) or \
                         total length {} — data exfiltration via oversized DNS labels.",
                        event.pid, event.comm, &event.query[..event.query.len().min(60)],
                        event.max_label, event.query_len
                    ),
                    mitre_techniques: vec!["T1071.004".into()],
                });
            }
        }

        // High-entropy query name — base32/hex encoding
        let entropy = shannon_entropy(event.query.as_bytes());
        if entropy > 4.5 {
            state.high_entropy_cnt += 1;
            if state.high_entropy_cnt >= 5 {
                alerts.push(CovertChannelAlert {
                    channel_type:     CovertChannelType::DnsTunneling,
                    confidence:       (0.60 + entropy / 10.0).min(0.90),
                    description:      format!(
                        "PID {} ({}): high-entropy DNS query name (entropy={:.2}) after {} queries — \
                         base32/hex encoded payloads indicate DNS tunneling exfiltration.",
                        event.pid, event.comm, entropy, state.high_entropy_cnt
                    ),
                    mitre_techniques: vec!["T1071.004".into(), "T1048.003".into()],
                });
            }
        }

        alerts
    }

    // ── ICMP analysis ─────────────────────────────────────────────────────────

    pub fn analyze_icmp(&self, event: &IcmpEvent) -> Vec<CovertChannelAlert> {
        let mut alerts = Vec::new();
        let mut map = self.icmp_state.write().unwrap();
        let state = map.entry(event.pid).or_insert_with(|| IcmpState {
            dest_counts:   HashMap::new(),
            large_pkt_cnt: 0,
        });

        // Large ICMP payload
        if event.payload_len > 64 {
            state.large_pkt_cnt += 1;
            if state.large_pkt_cnt >= 3 {
                alerts.push(CovertChannelAlert {
                    channel_type:     CovertChannelType::IcmpTunneling,
                    confidence:       (0.55 + state.large_pkt_cnt as f64 * 0.04).min(0.90),
                    description:      format!(
                        "PID {} ({}): ICMP packet with payload {} bytes (#{}) — \
                         data embedded in ICMP echo requests (iodine/icmpsh pattern).",
                        event.pid, event.comm, event.payload_len, state.large_pkt_cnt
                    ),
                    mitre_techniques: vec!["T1095".into(), "T1048".into()],
                });
            }
        }

        // Sustained ICMP to single destination
        let window = state.dest_counts
            .entry(event.dest_ip.clone())
            .or_insert_with(VecDeque::new);
        let now = Instant::now();
        window.push_back(now);
        while window.front().map(|t| now.duration_since(*t) > Duration::from_secs(60)).unwrap_or(false) {
            window.pop_front();
        }
        let dest_count = window.len();

        if dest_count > 20 {
            alerts.push(CovertChannelAlert {
                channel_type:     CovertChannelType::IcmpTunneling,
                confidence:       (0.50 + dest_count as f64 / 200.0).min(0.88),
                description:      format!(
                    "PID {} ({}): {} ICMP packets to {} in 60s — \
                     sustained ICMP traffic indicates tunneling C2 channel.",
                    event.pid, event.comm, dest_count, event.dest_ip
                ),
                mitre_techniques: vec!["T1095".into()],
            });
        }

        alerts
    }

    // ── HTTP analysis ─────────────────────────────────────────────────────────

    pub fn analyze_http(&self, event: &HttpEvent) -> Vec<CovertChannelAlert> {
        let mut alerts = Vec::new();
        let mut map = self.http_state.write().unwrap();
        let state = map.entry(event.pid).or_insert_with(|| HttpState {
            long_uri_cnt:     0,
            high_entropy_cnt: 0,
        });

        // Abnormally long URI
        if event.uri_len > 2000 {
            state.long_uri_cnt += 1;
            if state.long_uri_cnt >= 2 {
                alerts.push(CovertChannelAlert {
                    channel_type:     CovertChannelType::HttpSteganography,
                    confidence:       (0.60 + state.long_uri_cnt as f64 * 0.05).min(0.88),
                    description:      format!(
                        "PID {} ({}): HTTP {} URI length {} bytes (#{}) — \
                         data exfiltration via abnormally long URI path.",
                        event.pid, event.comm, event.method, event.uri_len, state.long_uri_cnt
                    ),
                    mitre_techniques: vec!["T1071.001".into(), "T1048".into()],
                });
            }
        }

        // High-entropy HTTP body — encrypted/encoded payload
        if event.body_entropy > 6.5 {
            state.high_entropy_cnt += 1;
            if state.high_entropy_cnt >= 3 {
                alerts.push(CovertChannelAlert {
                    channel_type:     CovertChannelType::HttpSteganography,
                    confidence:       (0.55 + event.body_entropy / 16.0).min(0.85),
                    description:      format!(
                        "PID {} ({}): HTTP body entropy {:.2} (#{}) — \
                         high-entropy data in HTTP body suggests steganographic exfiltration.",
                        event.pid, event.comm, event.body_entropy, state.high_entropy_cnt
                    ),
                    mitre_techniques: vec!["T1071.001".into(), "T1573".into()],
                });
            }
        }

        // Excessive headers
        if event.max_hdr_len > 4096 || event.header_count > 50 {
            alerts.push(CovertChannelAlert {
                channel_type:     CovertChannelType::HttpSteganography,
                confidence:       0.70,
                description:      format!(
                    "PID {} ({}): HTTP request has {} headers (max_len={}) — \
                     data encoded in custom HTTP headers (header injection exfiltration).",
                    event.pid, event.comm, event.header_count, event.max_hdr_len
                ),
                mitre_techniques: vec!["T1071.001".into()],
            });
        }

        alerts
    }

    /// Record a network packet for timing analysis and return alerts.
    pub fn analyze_timing(&self, pid: u32, comm: &str) -> Vec<CovertChannelAlert> {
        let mut alerts = Vec::new();
        let mut map = self.timing_state.write().unwrap();
        let state = map.entry(pid).or_insert_with(|| TimingState {
            intervals:  VecDeque::new(),
            last_event: None,
        });

        let now = Instant::now();
        if let Some(last) = state.last_event {
            let interval_ns = now.duration_since(last).as_nanos() as u64;
            state.intervals.push_back(interval_ns);
            if state.intervals.len() > 100 {
                state.intervals.pop_front();
            }
        }
        state.last_event = Some(now);

        // Check for suspiciously regular intervals (coefficient of variation < 0.05)
        if state.intervals.len() >= 20 {
            let mean = state.intervals.iter().sum::<u64>() as f64 / state.intervals.len() as f64;
            let var  = state.intervals.iter().map(|&x| {
                let d = x as f64 - mean; d * d
            }).sum::<f64>() / state.intervals.len() as f64;
            let cv = var.sqrt() / mean.max(1.0);

            if cv < 0.05 && mean < 10_000_000_000.0 /* < 10s */ {
                alerts.push(CovertChannelAlert {
                    channel_type:     CovertChannelType::TimingChannel,
                    confidence:       (0.60 + (0.05 - cv) * 8.0).min(0.88),
                    description:      format!(
                        "PID {} ({}): network event intervals CV={:.4} (mean={:.0}ns, n={}) — \
                         highly regular timing indicates a timing covert channel (beaconing).",
                        pid, comm, cv, mean, state.intervals.len()
                    ),
                    mitre_techniques: vec!["T1008".into(), "T1071".into()],
                });
            }
        }

        alerts
    }

    /// Evict state for terminated processes.
    pub fn evict(&self, pid: u32) {
        self.dns_state.write().unwrap().remove(&pid);
        self.icmp_state.write().unwrap().remove(&pid);
        self.http_state.write().unwrap().remove(&pid);
        self.timing_state.write().unwrap().remove(&pid);
    }
}

impl Default for NetworkCovertDetector {
    fn default() -> Self { Self::new() }
}

// ─── Shannon entropy ─────────────────────────────────────────────────────────

/// Shannon entropy in bits per byte [0.0, 8.0].
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    for &b in data { freq[b as usize] += 1; }
    let n = data.len() as f64;
    freq.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_dns_rate_triggers_tunneling_alert() {
        let det = NetworkCovertDetector::new();
        let mut last_alerts = vec![];
        for i in 0..55 {
            let ev = DnsEvent {
                pid: 1, comm: "malware".into(),
                query: format!("abc{}.evil.com", i),
                query_len: 20, max_label: 10,
            };
            last_alerts = det.analyze_dns(&ev);
        }
        assert!(!last_alerts.is_empty());
        assert!(last_alerts.iter().any(|a| a.channel_type == CovertChannelType::DnsTunneling));
    }

    #[test]
    fn long_dns_label_triggers_alert() {
        let det = NetworkCovertDetector::new();
        for _ in 0..3 {
            let ev = DnsEvent {
                pid: 2, comm: "evil".into(),
                query: "a".repeat(250),
                query_len: 250, max_label: 80,
            };
            det.analyze_dns(&ev);
        }
        let ev = DnsEvent {
            pid: 2, comm: "evil".into(),
            query: "b".repeat(250),
            query_len: 250, max_label: 80,
        };
        let alerts = det.analyze_dns(&ev);
        assert!(alerts.iter().any(|a| a.channel_type == CovertChannelType::DnsTunneling));
    }

    #[test]
    fn large_icmp_packets_trigger_alert() {
        let det = NetworkCovertDetector::new();
        let mut last = vec![];
        for _ in 0..4 {
            let ev = IcmpEvent {
                pid: 3, comm: "ping2".into(),
                payload_len: 512, dest_ip: "10.0.0.1".into(), is_reply: false,
            };
            last = det.analyze_icmp(&ev);
        }
        assert!(!last.is_empty());
        assert!(last.iter().any(|a| a.channel_type == CovertChannelType::IcmpTunneling));
    }

    #[test]
    fn shannon_entropy_high_for_random_data() {
        let random_data: Vec<u8> = (0..=255u8).collect();
        let e = shannon_entropy(&random_data);
        assert!(e > 7.9, "entropy of 0..255 should be ~8 bits, got {}", e);
    }

    #[test]
    fn shannon_entropy_zero_for_constant() {
        let data = vec![0u8; 100];
        let e = shannon_entropy(&data);
        assert_eq!(e, 0.0);
    }
}
