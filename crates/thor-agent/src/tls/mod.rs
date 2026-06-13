//! TLS SNI Extraction — inspect Server Name Indication without decryption.
//! Runs on raw packet bytes captured by eBPF, extracts the SNI field from
//! TLS ClientHello messages. No private key required — purely passive.
//!
//! Enables blocking of malicious HTTPS destinations (C2 over TLS) that
//! would otherwise appear as opaque encrypted traffic.
//!
//! Protocol reference: RFC 6066 §3 (Server Name Indication)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

// ─── TLS record types ─────────────────────────────────────────────────────────

const TLS_CONTENT_HANDSHAKE:    u8 = 22;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 1;
const TLS_EXTENSION_SNI:        u16 = 0x0000;
const TLS_SNI_TYPE_HOST:        u8  = 0;

// ─── SNI extraction result ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SniResult {
    pub sni:       Option<String>,
    pub src_ip:    String,
    pub dst_ip:    String,
    pub dst_port:  u16,
    pub tls_version: Option<String>,
}

// ─── Parser ───────────────────────────────────────────────────────────────────

/// Extract SNI from a raw TLS record byte slice.
/// Returns None if the packet is not a TLS ClientHello or SNI is absent.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    // Need at least TLS record header (5 bytes)
    if data.len() < 5 { return None; }

    // TLS record layer header
    let content_type  = data[0];
    let _version_major = data[1];
    let _version_minor = data[2];
    let record_len    = u16::from_be_bytes([data[3], data[4]]) as usize;

    if content_type != TLS_CONTENT_HANDSHAKE { return None; }
    if data.len() < 5 + record_len { return None; }

    let handshake = &data[5..];
    if handshake.is_empty() { return None; }

    // Handshake type
    if handshake[0] != TLS_HANDSHAKE_CLIENT_HELLO { return None; }

    // Skip: handshake type(1) + length(3) + client_version(2) + random(32) = 38
    if handshake.len() < 39 { return None; }
    let mut pos = 38;

    // Session ID
    let session_id_len = handshake[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > handshake.len() { return None; }

    // Cipher suites
    let cipher_len = u16::from_be_bytes([handshake[pos], handshake[pos+1]]) as usize;
    pos += 2 + cipher_len;
    if pos + 1 > handshake.len() { return None; }

    // Compression methods
    let comp_len = handshake[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > handshake.len() { return None; }

    // Extensions
    let ext_total = u16::from_be_bytes([handshake[pos], handshake[pos+1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > handshake.len() { return None; }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos+1]]);
        let ext_len  = u16::from_be_bytes([handshake[pos+2], handshake[pos+3]]) as usize;
        pos += 4;

        if pos + ext_len > ext_end { break; }

        if ext_type == TLS_EXTENSION_SNI {
            // SNI extension structure: list_len(2) + type(1) + name_len(2) + name
            if ext_len < 5 { return None; }
            let sni_type = handshake[pos + 2];
            if sni_type != TLS_SNI_TYPE_HOST { return None; }
            let name_len = u16::from_be_bytes([handshake[pos+3], handshake[pos+4]]) as usize;
            if pos + 5 + name_len > handshake.len() { return None; }
            let name_bytes = &handshake[pos+5..pos+5+name_len];
            return String::from_utf8(name_bytes.to_vec()).ok()
                .filter(|s| s.is_ascii() && !s.is_empty());
        }

        pos += ext_len;
    }

    None
}

// ─── SNI Domain Block List ────────────────────────────────────────────────────

pub struct SniBlocklist {
    exact:    tokio::sync::RwLock<std::collections::HashSet<String>>,
    suffixes: tokio::sync::RwLock<Vec<String>>,    // e.g. ".onion.to" → blocks all *.onion.to
}

impl SniBlocklist {
    pub fn new() -> Arc<Self> {
        let bl = Arc::new(Self {
            exact:    tokio::sync::RwLock::new(std::collections::HashSet::new()),
            suffixes: tokio::sync::RwLock::new(Vec::new()),
        });
        bl
    }

    pub async fn load_defaults(&self) {
        let mut exact = self.exact.write().await;
        let mut sfx   = self.suffixes.write().await;

        // Known C2 frameworks
        let known_bad = [
            "cobalt-strike.cloud", "cobaltstrike.com", "c2.redteam.red",
            "beacon.msf.local", "empire.c2.local",
        ];
        for d in known_bad { exact.insert(d.to_string()); }

        // Bad TLD/suffix patterns
        let bad_suffixes = [
            ".bit", ".onion.to", ".tor2web.org", ".exit.tor.org",
        ];
        for s in bad_suffixes { sfx.push(s.to_string()); }
    }

    pub async fn add_domain(&self, domain: String) {
        self.exact.write().await.insert(domain);
    }

    pub async fn add_suffix(&self, suffix: String) {
        self.suffixes.write().await.push(suffix);
    }

    pub async fn is_blocked(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        if self.exact.read().await.contains(&d) { return true; }
        for sfx in self.suffixes.read().await.iter() {
            if d.ends_with(sfx.as_str()) { return true; }
        }
        false
    }

    pub async fn count(&self) -> usize {
        self.exact.read().await.len() + self.suffixes.read().await.len()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Craft a minimal TLS ClientHello with a known SNI for testing.
    fn craft_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let sni_name_len = sni_bytes.len() as u16;
        let sni_entry_len = sni_name_len + 3;  // type(1) + len(2)
        let sni_list_len  = sni_entry_len + 2; // includes sni_entry_len field itself? RFC says list_len is total
        // SNI extension value: list_len(2) + type(1) + name_len(2) + name
        let mut sni_ext_val = vec![
            ((sni_name_len + 3) >> 8) as u8, ((sni_name_len + 3) & 0xff) as u8,
            0x00, // host_name
            (sni_name_len >> 8) as u8, (sni_name_len & 0xff) as u8,
        ];
        sni_ext_val.extend_from_slice(sni_bytes);
        let ext_len = sni_ext_val.len() as u16;

        let mut extensions = vec![];
        extensions.extend_from_slice(&[0x00, 0x00]); // ext type SNI
        extensions.extend_from_slice(&[(ext_len >> 8) as u8, (ext_len & 0xff) as u8]);
        extensions.extend_from_slice(&sni_ext_val);
        let exts_len = extensions.len() as u16;

        // Minimal ClientHello body: type(1) + len(3) + ver(2) + random(32) +
        // session_id_len(1) + cipher_suites_len(2) + suite(2) + comp_len(1) + 0x00 + exts_len(2) + exts
        let mut hello = vec![
            0x01,                               // ClientHello
            0x00, 0x00, 0x00,                  // length placeholder
            0x03, 0x03,                        // TLS 1.2
        ];
        hello.extend_from_slice(&[0u8; 32]);   // random
        hello.push(0x00);                      // session ID len
        hello.extend_from_slice(&[0x00, 0x02, 0xc0, 0x2b]); // 1 cipher suite
        hello.extend_from_slice(&[0x01, 0x00]); // comp methods
        hello.extend_from_slice(&[(exts_len >> 8) as u8, (exts_len & 0xff) as u8]);
        hello.extend_from_slice(&extensions);

        // Fix handshake length
        let body_len = hello.len() - 4;
        hello[1] = (body_len >> 16) as u8;
        hello[2] = (body_len >> 8) as u8;
        hello[3] = (body_len & 0xff) as u8;

        // TLS record header
        let record_len = hello.len() as u16;
        let mut record = vec![
            0x16,                               // content_type = handshake
            0x03, 0x01,                        // TLS 1.0 (legacy compat)
            (record_len >> 8) as u8, (record_len & 0xff) as u8,
        ];
        record.extend_from_slice(&hello);
        record
    }

    #[test]
    fn test_extract_sni_from_crafted_packet() {
        let pkt = craft_client_hello("evil.example.com");
        let sni = extract_sni(&pkt);
        assert_eq!(sni.as_deref(), Some("evil.example.com"));
    }

    #[test]
    fn test_non_tls_returns_none() {
        let garbage = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(extract_sni(garbage).is_none());
    }

    #[test]
    fn test_empty_slice_returns_none() {
        assert!(extract_sni(&[]).is_none());
    }

    #[test]
    fn test_truncated_returns_none() {
        let pkt = craft_client_hello("test.com");
        let truncated = &pkt[..10];
        assert!(extract_sni(truncated).is_none());
    }

    #[tokio::test]
    async fn test_blocklist_exact_match() {
        let bl = SniBlocklist::new();
        bl.add_domain("malware.example.com".to_string()).await;
        assert!(bl.is_blocked("malware.example.com").await);
        assert!(!bl.is_blocked("safe.example.com").await);
    }

    #[tokio::test]
    async fn test_blocklist_suffix_match() {
        let bl = SniBlocklist::new();
        bl.add_suffix(".onion.to".to_string()).await;
        assert!(bl.is_blocked("c2server.onion.to").await);
        assert!(!bl.is_blocked("normal.example.com").await);
    }
}
