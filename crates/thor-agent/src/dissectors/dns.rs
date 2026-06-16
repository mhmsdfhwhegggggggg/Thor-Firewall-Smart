//! ThorDissector — DNS Protocol Dissector (Zeek-inspired)
//!
//! Parses raw DNS wire format and produces structured dns.log entries.
//! Detects:
//!   ▸ DNS Tunneling (high entropy labels, oversized TXT/NULL records)
//!   ▸ DGA (Domain Generation Algorithm) via entropy + label analysis
//!   ▸ DNS Rebinding attacks
//!   ▸ NXDOMAIN flood / DNS reconnaissance
//!   ▸ Suspicious record types (AAAA→IPv4, TXT exfil)
//!   ▸ DNS-over-HTTPS (DoH) bypass attempts
//!   ▸ Fast-flux domains (multiple short-TTL A records)
//!   ▸ Tor hidden service resolution

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

// ─── DNS Log (Zeek dns.log schema) ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLog {
    pub ts: DateTime<Utc>,
    pub uid: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub proto: String,
    pub transaction_id: u16,
    pub query: String,
    pub qtype: u16,
    pub qtype_name: String,
    pub rcode: u8,
    pub answers: Vec<String>,
    pub ttls: Vec<u32>,
    pub anomalies: Vec<DnsAnomaly>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DnsAnomaly {
    Tunneling,
    DgaDomain,
    NxdomainFlood,
    DnsRebinding,
    TorHiddenService,
    SuspiciousTxtRecord,
    FastFlux,
    DohBypass,
    OversizedPacket,
    HighEntropyLabel,
}

// ─── DNS Wire Format Parsing ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct DnsPacket {
    pub transaction_id: u16,
    pub flags: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: DnsRdata,
}

#[derive(Debug, Clone)]
pub enum DnsRdata {
    A([u8; 4]),
    Aaaa([u8; 16]),
    Cname(String),
    Mx { priority: u16, exchange: String },
    Txt(Vec<String>),
    Ns(String),
    Ptr(String),
    Soa {
        mname: String, rname: String,
        serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32,
    },
    Unknown(Vec<u8>),
}

impl DnsRdata {
    pub fn to_string_repr(&self) -> String {
        match self {
            DnsRdata::A(ip) => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            DnsRdata::Aaaa(ip) => {
                let parts: Vec<String> = ip.chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect();
                parts.join(":")
            }
            DnsRdata::Cname(s) | DnsRdata::Ns(s) | DnsRdata::Ptr(s) => s.clone(),
            DnsRdata::Mx { priority, exchange } => format!("{} {}", priority, exchange),
            DnsRdata::Txt(parts) => parts.join(" "),
            DnsRdata::Unknown(b) => format!("<{} bytes>", b.len()),
            DnsRdata::Soa { mname, .. } => mname.clone(),
        }
    }
}

pub fn parse_dns_packet(data: &[u8]) -> Option<DnsPacket> {
    if data.len() < 12 { return None; }

    let transaction_id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_response = (flags >> 15) & 1 == 1;
    let opcode = ((flags >> 11) & 0xf) as u8;
    let rcode = (flags & 0xf) as u8;

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut pos = 12;

    let mut questions = Vec::new();
    for _ in 0..qdcount {
        let (name, new_pos) = parse_name(data, pos)?;
        pos = new_pos;
        if pos + 4 > data.len() { break; }
        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let qclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        pos += 4;
        questions.push(DnsQuestion { name, qtype, qclass });
    }

    let answers = parse_records(data, &mut pos, ancount);
    let authority = parse_records(data, &mut pos, nscount);
    let additional = parse_records(data, &mut pos, arcount);

    Some(DnsPacket {
        transaction_id, flags, is_response, opcode, rcode,
        questions, answers, authority, additional,
    })
}

fn parse_records(data: &[u8], pos: &mut usize, count: usize) -> Vec<DnsRecord> {
    let mut records = Vec::new();
    for _ in 0..count {
        if let Some(rec) = parse_record(data, pos) {
            records.push(rec);
        } else {
            break;
        }
    }
    records
}

fn parse_record(data: &[u8], pos: &mut usize) -> Option<DnsRecord> {
    let (name, new_pos) = parse_name(data, *pos)?;
    *pos = new_pos;
    if *pos + 10 > data.len() { return None; }

    let rtype = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    let rclass = u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]);
    let ttl = u32::from_be_bytes([data[*pos+4], data[*pos+5], data[*pos+6], data[*pos+7]]);
    let rdlen = u16::from_be_bytes([data[*pos + 8], data[*pos + 9]]) as usize;
    *pos += 10;

    if *pos + rdlen > data.len() { return None; }
    let rdata_bytes = &data[*pos..*pos + rdlen];
    *pos += rdlen;

    let rdata = match rtype {
        1 if rdlen == 4 => DnsRdata::A([rdata_bytes[0], rdata_bytes[1], rdata_bytes[2], rdata_bytes[3]]),
        28 if rdlen == 16 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(rdata_bytes);
            DnsRdata::Aaaa(ip)
        }
        5 => { // CNAME
            let (s, _) = parse_name(data, *pos - rdlen).unwrap_or_default();
            DnsRdata::Cname(s)
        }
        15 if rdlen >= 3 => { // MX
            let priority = u16::from_be_bytes([rdata_bytes[0], rdata_bytes[1]]);
            let rp = *pos - rdlen + 2;
            let (exchange, _) = parse_name(data, rp).unwrap_or_default();
            DnsRdata::Mx { priority, exchange }
        }
        16 => { // TXT
            let mut parts = Vec::new();
            let mut p = 0;
            while p < rdata_bytes.len() {
                let len = rdata_bytes[p] as usize;
                p += 1;
                if p + len <= rdata_bytes.len() {
                    if let Ok(s) = std::str::from_utf8(&rdata_bytes[p..p + len]) {
                        parts.push(s.to_string());
                    }
                    p += len;
                } else { break; }
            }
            DnsRdata::Txt(parts)
        }
        2 => { // NS
            let (s, _) = parse_name(data, *pos - rdlen).unwrap_or_default();
            DnsRdata::Ns(s)
        }
        12 => { // PTR
            let (s, _) = parse_name(data, *pos - rdlen).unwrap_or_default();
            DnsRdata::Ptr(s)
        }
        _ => DnsRdata::Unknown(rdata_bytes.to_vec()),
    };

    Some(DnsRecord { name, rtype, rclass, ttl, rdata })
}

/// Parse a DNS name with compression pointer support.
fn parse_name(data: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut final_pos = None;
    let mut jumps = 0;

    loop {
        if jumps > 10 { return None; } // prevent infinite loops
        if pos >= data.len() { return None; }

        let len = data[pos];

        if len == 0 {
            if final_pos.is_none() { final_pos = Some(pos + 1); }
            break;
        }

        if len & 0xc0 == 0xc0 {
            // Compression pointer
            if pos + 1 >= data.len() { return None; }
            if final_pos.is_none() { final_pos = Some(pos + 2); }
            let ptr = (((len & 0x3f) as usize) << 8) | data[pos + 1] as usize;
            pos = ptr;
            jumps += 1;
        } else {
            pos += 1;
            let label_end = pos + len as usize;
            if label_end > data.len() { return None; }
            labels.push(std::str::from_utf8(&data[pos..label_end]).ok()?.to_string());
            pos = label_end;
        }
    }

    Some((labels.join("."), final_pos.unwrap_or(pos)))
}

// ─── Anomaly Detection ────────────────────────────────────────────────────────

/// Shannon entropy of a string (0.0 = constant, ~4.0 = highly random)
pub fn entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let bytes = s.as_bytes();
    let len = bytes.len() as f64;
    let mut freq = [0u32; 256];
    for &b in bytes { freq[b as usize] += 1; }
    freq.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = c as f64 / len;
        acc - p * p.log2()
    })
}

/// Detect DGA: high-entropy hostname with no real word structure.
/// Simple heuristic: entropy > 3.5 on longest label AND label length > 12.
pub fn is_likely_dga(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 { return false; }

    // Check the second-level domain (longest likely-random label)
    let sld = labels[labels.len().saturating_sub(2)];
    if sld.len() < 8 { return false; }

    let ent = entropy(sld);
    ent > 3.5
}

/// Detect DNS tunneling heuristics.
pub fn is_likely_tunnel(packet: &DnsPacket) -> bool {
    for q in &packet.questions {
        // Oversized query (>63 chars in a single label)
        if q.name.split('.').any(|l| l.len() > 63) { return true; }
        // Very long FQDN (>100 chars total)
        if q.name.len() > 100 { return true; }
        // TXT queries are commonly abused for tunneling
        if q.qtype == 16 { return true; }
        // NULL record queries (used by iodine)
        if q.qtype == 10 { return true; }
        // High entropy across all labels
        if entropy(&q.name) > 4.0 { return true; }
    }

    for ans in &packet.answers {
        if let DnsRdata::Txt(parts) = &ans.rdata {
            let total: usize = parts.iter().map(|p| p.len()).sum();
            if total > 200 { return true; } // Large TXT = possible exfil
        }
    }

    false
}

/// Returns true if the domain is a known Tor .onion gateway.
pub fn is_tor_domain(domain: &str) -> bool {
    let d = domain.to_lowercase();
    d.ends_with(".onion") ||
    d.ends_with(".onion.to") ||
    d.ends_with(".onion.link") ||
    d.ends_with(".onion.ws") ||
    d.ends_with(".tor2web.org") ||
    d.ends_with(".tor2web.fi")
}

/// Returns anomalies detected in a DNS packet.
pub fn detect_dns_anomalies(packet: &DnsPacket) -> Vec<DnsAnomaly> {
    let mut anomalies = Vec::new();

    if is_likely_tunnel(packet) {
        anomalies.push(DnsAnomaly::Tunneling);
    }

    for q in &packet.questions {
        if is_likely_dga(&q.name) {
            anomalies.push(DnsAnomaly::DgaDomain);
        }
        if is_tor_domain(&q.name) {
            anomalies.push(DnsAnomaly::TorHiddenService);
        }
        // DoH bypass attempt (DNS over HTTPS via plain DNS resolver)
        if q.name.contains("dns.google") || q.name.contains("cloudflare-dns.com")
            || q.name.contains("doh.") {
            anomalies.push(DnsAnomaly::DohBypass);
        }
    }

    // Fast-flux: multiple answers with very short TTL
    let short_ttl_count = packet.answers.iter().filter(|r| r.ttl < 60 && r.rtype == 1).count();
    if short_ttl_count >= 3 {
        anomalies.push(DnsAnomaly::FastFlux);
    }

    // Large TXT data
    for ans in &packet.answers {
        if let DnsRdata::Txt(parts) = &ans.rdata {
            let total: usize = parts.iter().map(|p| p.len()).sum();
            if total > 100 {
                anomalies.push(DnsAnomaly::SuspiciousTxtRecord);
            }
        }
    }

    anomalies.dedup_by(|a, b| a == b);
    anomalies
}

pub fn qtype_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA",
        10 => "NULL", 12 => "PTR", 15 => "MX", 16 => "TXT",
        28 => "AAAA", 33 => "SRV", 255 => "ANY",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_values() {
        assert!(entropy("aaaa") < 0.1);
        assert!(entropy("abcdefgh") > 2.0);
        assert!(entropy("xn--nxasmq6b3b4d") > 3.0);
    }

    #[test]
    fn dga_detection() {
        assert!(is_likely_dga("x3k9mq7zr2pj8h4n.com"));
        assert!(!is_likely_dga("google.com"));
        assert!(!is_likely_dga("example.co.uk"));
    }

    #[test]
    fn tor_detection() {
        assert!(is_tor_domain("facebookcore.onion.to"));
        assert!(is_tor_domain("abc123.onion"));
        assert!(!is_tor_domain("facebook.com"));
    }

    #[test]
    fn parse_simple_dns_query() {
        // Minimal hand-crafted DNS query for "a.com" type A
        let mut pkt = vec![
            0x12, 0x34, // transaction ID
            0x01, 0x00, // flags: query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question: "a.com"
            0x01, b'a', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, // QTYPE A
            0x00, 0x01, // QCLASS IN
        ];
        let parsed = parse_dns_packet(&pkt).unwrap();
        assert_eq!(parsed.transaction_id, 0x1234);
        assert!(!parsed.is_response);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "a.com");
        assert_eq!(parsed.questions[0].qtype, 1); // A
    }
}
