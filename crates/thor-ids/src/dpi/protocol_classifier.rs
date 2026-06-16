//! Protocol Classifier — identifies the actual application protocol from packet
//! features, independent of the declared port number.
//!
//! Uses a deterministic decision-tree approach based on payload signatures and
//! feature thresholds. This enables detection of protocol misrepresentation
//! (e.g., C2 traffic disguised as HTTPS on port 443 but without valid TLS).

use super::packet_encoder::{encode_packet, shannon_entropy, FEATURE_DIM};

/// Classified application protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Http,
    Https,
    Tls,
    Dns,
    Ssh,
    Smtp,
    Smb,
    Rdp,
    /// High-entropy, possibly encrypted or compressed traffic
    EncryptedUnknown,
    /// Low-entropy, likely padding or scan probe
    Empty,
    /// Could not classify with confidence
    Unknown,
}

impl Protocol {
    /// Returns a human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Protocol::Http => "HTTP",
            Protocol::Https => "HTTPS/TLS",
            Protocol::Tls => "TLS",
            Protocol::Dns => "DNS",
            Protocol::Ssh => "SSH",
            Protocol::Smtp => "SMTP",
            Protocol::Smb => "SMB",
            Protocol::Rdp => "RDP",
            Protocol::EncryptedUnknown => "ENCRYPTED_UNKNOWN",
            Protocol::Empty => "EMPTY",
            Protocol::Unknown => "UNKNOWN",
        }
    }
}

/// Classification result with confidence score.
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    /// Classified protocol
    pub protocol: Protocol,
    /// Confidence in [0.0, 1.0] — higher is more certain
    pub confidence: f32,
    /// Declared port (from packet header)
    pub declared_port: u16,
    /// Whether declared port matches classified protocol
    pub port_mismatch: bool,
}

impl ClassificationResult {
    /// Returns true if there is a significant port/protocol mismatch.
    /// This is a strong indicator of covert channel or evasion.
    pub fn is_suspicious(&self) -> bool {
        self.port_mismatch && self.confidence > 0.7
    }
}

/// Classify the application protocol from a raw packet's payload bytes.
///
/// `declared_port` is the destination port from the IP/TCP/UDP header.
pub fn classify(payload: &[u8], declared_port: u16) -> ClassificationResult {
    let protocol = classify_payload(payload);
    let port_mismatch = is_port_mismatch(protocol, declared_port);
    let confidence = compute_confidence(protocol, payload);

    ClassificationResult { protocol, confidence, declared_port, port_mismatch }
}

/// Classify from a raw packet (including IP headers).
pub fn classify_packet(raw: &[u8], declared_port: u16) -> Option<ClassificationResult> {
    if raw.len() < 20 { return None; }
    let ihl = ((raw[0] & 0xF) * 4) as usize;
    let transport_offset = ihl + if raw[9] == 6 {
        let tcp_off = ((raw[ihl + 12] >> 4) * 4) as usize;
        tcp_off
    } else { 8 };
    let payload = if transport_offset < raw.len() { &raw[transport_offset..] } else { &[] };
    Some(classify(payload, declared_port))
}

// ─── Internal classification logic ───────────────────────────────────────────

fn classify_payload(payload: &[u8]) -> Protocol {
    if payload.is_empty() || payload.iter().all(|&b| b == 0) {
        return Protocol::Empty;
    }

    // TLS/HTTPS: record type 0x16 (Handshake) or 0x17 (Application Data)
    if payload.len() >= 5 && (payload[0] == 0x16 || payload[0] == 0x17) {
        let version = u16::from_be_bytes([payload[1], payload[2]]);
        if version >= 0x0301 && version <= 0x0304 {
            return Protocol::Tls;
        }
    }

    // HTTP methods
    if payload.starts_with(b"GET ")
        || payload.starts_with(b"POST ")
        || payload.starts_with(b"PUT ")
        || payload.starts_with(b"DELETE ")
        || payload.starts_with(b"HEAD ")
        || payload.starts_with(b"OPTIONS ")
        || payload.starts_with(b"HTTP/1.")
        || payload.starts_with(b"HTTP/2")
    {
        return Protocol::Http;
    }

    // SSH banner
    if payload.starts_with(b"SSH-") {
        return Protocol::Ssh;
    }

    // SMTP
    if payload.starts_with(b"220 ")
        || payload.starts_with(b"EHLO ")
        || payload.starts_with(b"HELO ")
        || payload.starts_with(b"MAIL FROM:")
    {
        return Protocol::Smtp;
    }

    // SMB
    if payload.len() >= 4 && (&payload[..4] == b"\xFFSMB" || &payload[..4] == b"\xFESMB") {
        return Protocol::Smb;
    }

    // DNS: check for valid DNS query structure
    if payload.len() >= 12 {
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let opcode = (flags >> 11) & 0xF;
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        // QR=0 (query), opcode in {0,1,2}, qdcount reasonable
        if (flags & 0x8000) == 0 && opcode <= 2 && qdcount > 0 && qdcount < 10 {
            return Protocol::Dns;
        }
    }

    // RDP: look for RDP cookie or TPKT header
    if payload.starts_with(b"Cookie: mstshash=")
        || (payload.len() >= 2 && payload[0] == 0x03 && payload[1] == 0x00)
    {
        return Protocol::Rdp;
    }

    // High entropy → likely encrypted unknown protocol
    let entropy = shannon_entropy(payload);
    if entropy > 0.85 {
        return Protocol::EncryptedUnknown;
    }

    Protocol::Unknown
}

/// Returns true if the detected protocol doesn't match the expected protocol
/// for the declared destination port.
fn is_port_mismatch(proto: Protocol, port: u16) -> bool {
    match (proto, port) {
        (Protocol::Http, 80) | (Protocol::Http, 8080) | (Protocol::Http, 8000) => false,
        (Protocol::Tls, 443) | (Protocol::Tls, 8443) => false,
        (Protocol::Dns, 53) => false,
        (Protocol::Ssh, 22) => false,
        (Protocol::Smtp, 25) | (Protocol::Smtp, 587) | (Protocol::Smtp, 465) => false,
        (Protocol::Smb, 445) | (Protocol::Smb, 139) => false,
        (Protocol::Rdp, 3389) => false,
        (Protocol::Empty, _) | (Protocol::Unknown, _) => false,
        _ => true, // Protocol doesn't match declared port — suspicious
    }
}

/// Estimate confidence based on how unambiguous the classification was.
fn compute_confidence(proto: Protocol, payload: &[u8]) -> f32 {
    match proto {
        Protocol::Http => {
            // Stronger if we see both method and HTTP version
            if (payload.starts_with(b"GET ") || payload.starts_with(b"POST "))
                && payload.windows(8).any(|w| w == b"HTTP/1.1")
            { 0.95 } else { 0.80 }
        }
        Protocol::Tls => {
            if payload.len() >= 5 {
                let version = u16::from_be_bytes([payload[1], payload[2]]);
                if version == 0x0303 || version == 0x0304 { 0.95 } else { 0.75 }
            } else { 0.65 }
        }
        Protocol::Dns => 0.85,
        Protocol::Ssh => 0.95,
        Protocol::Smtp => 0.90,
        Protocol::Smb => 0.95,
        Protocol::Rdp => 0.80,
        Protocol::EncryptedUnknown => {
            let e = shannon_entropy(payload);
            // More confident the closer entropy is to 1.0
            0.5 + (e - 0.85).max(0.0) * 3.0
        }
        Protocol::Empty => 0.99,
        Protocol::Unknown => 0.10,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_http_get() {
        let payload = b"GET /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n";
        let result = classify(payload, 80);
        assert_eq!(result.protocol, Protocol::Http);
        assert!(!result.port_mismatch);
        assert!(result.confidence > 0.7);
    }

    #[test]
    fn test_classify_http_on_wrong_port() {
        let payload = b"GET /tunnel HTTP/1.1\r\nHost: attacker.com\r\n\r\n";
        let result = classify(payload, 443); // HTTP on HTTPS port
        assert_eq!(result.protocol, Protocol::Http);
        assert!(result.port_mismatch, "HTTP on port 443 should be a mismatch");
        assert!(result.is_suspicious());
    }

    #[test]
    fn test_classify_tls() {
        // TLS 1.3 ClientHello starts with 0x16, 0x03, 0x01
        let payload = vec![0x16u8, 0x03, 0x01, 0x00, 0x80, 0x01, 0x00, 0x00, 0x7c];
        let result = classify(&payload, 443);
        assert_eq!(result.protocol, Protocol::Tls);
        assert!(!result.port_mismatch);
    }

    #[test]
    fn test_classify_ssh_banner() {
        let payload = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
        let result = classify(payload, 22);
        assert_eq!(result.protocol, Protocol::Ssh);
        assert!(!result.port_mismatch);
    }

    #[test]
    fn test_classify_high_entropy_unknown() {
        // Simulate encrypted/compressed data (high entropy)
        let payload: Vec<u8> = (0u8..=255).cycle().take(256).collect();
        let result = classify(&payload, 4444);
        assert_eq!(result.protocol, Protocol::EncryptedUnknown);
    }

    #[test]
    fn test_smb_on_wrong_port_suspicious() {
        let payload = b"\xFFSMB\x72\x00\x00\x00\x00\x18\x01\x48";
        let result = classify(payload, 80); // SMB over HTTP port
        assert_eq!(result.protocol, Protocol::Smb);
        assert!(result.port_mismatch);
        assert!(result.is_suspicious());
    }
}
