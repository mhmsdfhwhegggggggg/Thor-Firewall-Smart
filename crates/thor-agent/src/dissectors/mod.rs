//! ThorDissectors — Deep Packet Inspection Engine (Zeek-inspired)
//!
//! Protocol dissectors for L7 traffic analysis:
//!   ▸ HTTP/1.x — request/response parsing + attack detection
//!   ▸ DNS     — wire format parsing + DGA/tunneling detection
//!   ▸ SMB/2   — header parsing + EternalBlue/DoublePulsar detection
//!   ▸ TLS     — ClientHello/ServerHello + cipher/cert analysis
//!
//! All dissectors produce Zeek-compatible log entries and anomaly enumerations
//! that feed directly into the SOAR engine.
//!
//! Architecture:
//!   TcpReassembler → DissectorEngine → L7 protocol dissector → DissectorResult
//!   DissectorResult → DetectionEngine → alert/SOAR

pub mod dns;
pub mod http;
pub mod smb;
pub mod tls_dissector;

use std::sync::Arc;
use tracing::{debug, warn};
use dashmap::DashMap;
use chrono::Utc;

pub use http::{HttpLog, HttpAnomaly, parse_request, parse_response, detect_anomalies, make_http_log};
pub use dns::{DnsLog, DnsAnomaly, parse_dns_packet, detect_dns_anomalies};
pub use smb::{SmbLog, SmbAnomaly, parse_smb_header, detect_smb_anomalies, make_smb_log};
pub use tls_dissector::{TlsLog, TlsAnomaly, analyse_tls_bytes};

// ─── Protocol Identification ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    Http,
    Https,
    Dns,
    Smb,
    Ssh,
    Tls,
    Unknown,
}

impl Protocol {
    /// Guess protocol from destination port (heuristic; payload overrides)
    pub fn from_port(port: u16) -> Self {
        match port {
            80 | 8080 | 3000 | 8000 => Self::Http,
            443 | 8443 => Self::Https,
            53 => Self::Dns,
            445 | 139 => Self::Smb,
            22 => Self::Ssh,
            _ => Self::Unknown,
        }
    }

    /// Refine protocol guess by peeking at payload bytes
    pub fn from_payload(data: &[u8]) -> Self {
        if data.is_empty() { return Self::Unknown; }
        match data {
            d if d.starts_with(b"GET ") || d.starts_with(b"POST ") ||
                 d.starts_with(b"PUT ") || d.starts_with(b"DELETE ") ||
                 d.starts_with(b"HEAD ") || d.starts_with(b"OPTIONS ") => Self::Http,
            d if d.starts_with(b"HTTP/") => Self::Http,
            d if d[0] == 0x16 && d.len() > 3 => Self::Tls, // TLS handshake
            d if d.starts_with(b"\xffSMB") || d.starts_with(b"\xfeSMB") => Self::Smb,
            // DNS: heuristic — short packet, valid opcode
            d if d.len() >= 12 && (d[2] & 0x80 == 0) => Self::Dns, // query flag
            _ => Self::Unknown,
        }
    }
}

// ─── Dissector Result ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DissectorResult {
    Http(Box<HttpLog>),
    Dns(Box<DnsLog>),
    Smb(Box<SmbLog>),
    Tls(Box<TlsLog>),
    Unknown,
}

impl DissectorResult {
    /// Returns true if any anomaly was detected
    pub fn has_anomaly(&self) -> bool {
        match self {
            Self::Http(log) => !log.anomalies.is_empty(),
            Self::Dns(log) => !log.anomalies.is_empty(),
            Self::Smb(log) => !log.anomalies.is_empty(),
            Self::Tls(log) => !log.anomalies.is_empty(),
            Self::Unknown => false,
        }
    }

    /// Severity score (0.0 – 1.0) based on anomaly types
    pub fn severity(&self) -> f32 {
        match self {
            Self::Http(log) => http_severity(&log.anomalies),
            Self::Dns(log) => dns_severity(&log.anomalies),
            Self::Smb(log) => smb_severity(&log.anomalies),
            Self::Tls(log) => tls_severity(&log.anomalies),
            Self::Unknown => 0.0,
        }
    }

    pub fn protocol_name(&self) -> &'static str {
        match self {
            Self::Http(_) => "HTTP",
            Self::Dns(_) => "DNS",
            Self::Smb(_) => "SMB",
            Self::Tls(_) => "TLS",
            Self::Unknown => "UNKNOWN",
        }
    }
}

fn http_severity(anomalies: &[HttpAnomaly]) -> f32 {
    anomalies.iter().fold(0.0f32, |acc, a| acc + match a {
        HttpAnomaly::Log4ShellRce | HttpAnomaly::Spring4ShellRce |
        HttpAnomaly::Shellshock | HttpAnomaly::WebShell => 0.95,
        HttpAnomaly::SqlInjection | HttpAnomaly::CommandInjection => 0.85,
        HttpAnomaly::PathTraversal | HttpAnomaly::SsrfAttempt => 0.75,
        HttpAnomaly::Xss => 0.6,
        HttpAnomaly::LargeUpload => 0.5,
        HttpAnomaly::SuspiciousUserAgent => 0.3,
        HttpAnomaly::SensitiveFileLeak => 0.7,
    }).min(1.0)
}

fn dns_severity(anomalies: &[DnsAnomaly]) -> f32 {
    anomalies.iter().fold(0.0f32, |acc, a| acc + match a {
        DnsAnomaly::Tunneling => 0.9,
        DnsAnomaly::DgaDomain => 0.8,
        DnsAnomaly::TorHiddenService => 0.75,
        DnsAnomaly::SuspiciousTxtRecord => 0.6,
        DnsAnomaly::FastFlux => 0.65,
        DnsAnomaly::NxdomainFlood => 0.5,
        DnsAnomaly::DnsRebinding => 0.85,
        DnsAnomaly::DohBypass => 0.4,
        DnsAnomaly::OversizedPacket => 0.5,
        DnsAnomaly::HighEntropyLabel => 0.7,
    }).min(1.0)
}

fn smb_severity(anomalies: &[SmbAnomaly]) -> f32 {
    anomalies.iter().fold(0.0f32, |acc, a| acc + match a {
        SmbAnomaly::EternalBlue => 1.0,
        SmbAnomaly::DoublePulsar => 1.0,
        SmbAnomaly::NtlmRelay => 0.9,
        SmbAnomaly::SuspiciousPipeName => 0.85,
        SmbAnomaly::AdminShareAccess => 0.6,
        SmbAnomaly::NullSession => 0.5,
        SmbAnomaly::BruteForce => 0.7,
        SmbAnomaly::SmbRecon => 0.4,
        SmbAnomaly::LargeTransaction => 0.5,
        SmbAnomaly::UnusualDialect => 0.3,
    }).min(1.0)
}

fn tls_severity(anomalies: &[TlsAnomaly]) -> f32 {
    anomalies.iter().fold(0.0f32, |acc, a| acc + match a {
        TlsAnomaly::KnownMaliciousJa4 => 0.95,
        TlsAnomaly::NullCipher | TlsAnomaly::AnonymousCipher => 0.9,
        TlsAnomaly::ExportCipher | TlsAnomaly::WeakCipherSuite => 0.8,
        TlsAnomaly::Ssl30Used => 0.75,
        TlsAnomaly::SelfSignedCert | TlsAnomaly::SuspiciousSni => 0.65,
        TlsAnomaly::SnIpAddress => 0.7,
        TlsAnomaly::Tls10Used => 0.4,
        TlsAnomaly::ExpiredCert => 0.5,
        TlsAnomaly::FutureDatedCert | TlsAnomaly::CertSubjectWildcard => 0.4,
        TlsAnomaly::MissingFallbackScsv => 0.5,
    }).min(1.0)
}

// ─── DissectorEngine ──────────────────────────────────────────────────────────

pub struct DissectorEngine {
    /// Known-malicious JA4 fingerprints (shared with FingerprintEngine)
    malicious_ja4: Arc<std::collections::HashSet<String>>,
    /// Flow → accumulated result count for rate detection
    flow_counts: Arc<DashMap<String, u32>>,
}

impl DissectorEngine {
    pub fn new() -> Self {
        Self {
            malicious_ja4: Arc::new(crate::fingerprint::known_malicious_ja4()),
            flow_counts: Arc::new(DashMap::new()),
        }
    }

    /// Dissect a raw payload and return a structured result.
    pub fn dissect(
        &self,
        payload: &[u8],
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
    ) -> DissectorResult {
        let uid = format!("{}:{}->{}:{}", src_ip, src_port, dst_ip, dst_port);
        let proto = Protocol::from_payload(payload)
            .merge_with(Protocol::from_port(dst_port));

        match proto {
            Protocol::Http => {
                if let Some(req) = parse_request(payload) {
                    let log = make_http_log(&req, None, &uid, src_ip, src_port, dst_ip, dst_port);
                    if log.anomalies.is_empty() {
                        debug!(uid=%uid, "HTTP dissected (clean)");
                    } else {
                        warn!(uid=%uid, anomalies=?log.anomalies, "HTTP anomalies detected");
                    }
                    return DissectorResult::Http(Box::new(log));
                }
                DissectorResult::Unknown
            }
            Protocol::Dns => {
                if let Some(packet) = parse_dns_packet(payload) {
                    let anomalies = detect_dns_anomalies(&packet);
                    let log = DnsLog {
                        ts: Utc::now(),
                        uid,
                        src_ip: src_ip.to_string(),
                        dst_ip: dst_ip.to_string(),
                        proto: "UDP".to_string(),
                        transaction_id: packet.transaction_id,
                        query: packet.questions.first()
                            .map(|q| q.name.clone())
                            .unwrap_or_default(),
                        qtype: packet.questions.first()
                            .map(|q| q.qtype)
                            .unwrap_or(0),
                        qtype_name: packet.questions.first()
                            .map(|q| dns::qtype_name(q.qtype).to_string())
                            .unwrap_or_default(),
                        rcode: packet.rcode,
                        answers: packet.answers.iter()
                            .map(|a| a.rdata.to_string_repr())
                            .collect(),
                        ttls: packet.answers.iter().map(|a| a.ttl).collect(),
                        anomalies,
                    };
                    return DissectorResult::Dns(Box::new(log));
                }
                DissectorResult::Unknown
            }
            Protocol::Smb => {
                if let Some(log) = make_smb_log(payload, &uid, src_ip, dst_ip) {
                    return DissectorResult::Smb(Box::new(log));
                }
                DissectorResult::Unknown
            }
            Protocol::Tls | Protocol::Https => {
                if let Some(log) = analyse_tls_bytes(
                    payload, &uid, src_ip, dst_ip, dst_port, &self.malicious_ja4
                ) {
                    return DissectorResult::Tls(Box::new(log));
                }
                DissectorResult::Unknown
            }
            _ => DissectorResult::Unknown,
        }
    }
}

impl Protocol {
    fn merge_with(self, port_hint: Protocol) -> Protocol {
        // Payload identification takes priority over port heuristics
        if self != Protocol::Unknown { self } else { port_hint }
    }
}

impl Default for DissectorEngine {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_from_port() {
        assert_eq!(Protocol::from_port(80), Protocol::Http);
        assert_eq!(Protocol::from_port(443), Protocol::Https);
        assert_eq!(Protocol::from_port(53), Protocol::Dns);
        assert_eq!(Protocol::from_port(445), Protocol::Smb);
        assert_eq!(Protocol::from_port(9999), Protocol::Unknown);
    }

    #[test]
    fn protocol_from_payload() {
        assert_eq!(Protocol::from_payload(b"GET / HTTP/1.1\r\n"), Protocol::Http);
        assert_eq!(Protocol::from_payload(b"POST /api HTTP/1.1\r\n"), Protocol::Http);
        assert_eq!(Protocol::from_payload(&[0x16, 0x03, 0x01, 0x00, 0x01]), Protocol::Tls);
        assert_eq!(Protocol::from_payload(&[0xff, 0x53, 0x4d, 0x42]), Protocol::Smb);
    }

    #[test]
    fn http_anomaly_severity() {
        let log = HttpLog {
            ts: Utc::now(), uid: "x".into(), src_ip: "1.1.1.1".into(), src_port: 12345,
            dst_ip: "2.2.2.2".into(), dst_port: 80, method: "GET".into(),
            host: "".into(), uri: "/".into(), referrer: "".into(),
            version: "HTTP/1.1".into(), user_agent: "".into(),
            request_body_len: 0, response_status_code: None, response_body_len: 0,
            content_type: "".into(),
            tags: vec!["Log4ShellRce".into()],
            anomalies: vec![HttpAnomaly::Log4ShellRce],
        };
        let r = DissectorResult::Http(Box::new(log));
        assert!(r.severity() > 0.9);
        assert!(r.has_anomaly());
    }
}
