//! JA4S — TLS Server Fingerprinting
//!
//! JA4S format: t{tls_ver}{num_ciphers}_{selected_cipher}_{ext_hex}
//!
//! Fingerprints the TLS ServerHello. Useful for identifying:
//!   - C2 servers with default certificate/cipher configurations
//!   - Misconfigured TLS servers (weak ciphers, TLS 1.0, etc.)
//!   - Self-signed certificate servers (in combination with cert parsing)
//!
//! Reference: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4S.md

use sha2::{Sha256, Digest};

/// Parsed TLS ServerHello
#[derive(Debug, Clone, Default)]
pub struct ServerHello {
    pub tls_version: u16,
    pub supported_version: Option<u16>, // from extension 0x002b
    pub selected_cipher: u16,
    pub extensions: Vec<u16>,
    pub alpn_selected: Option<String>,
}

/// JA4S fingerprint
#[derive(Debug, Clone)]
pub struct Ja4sFingerprint {
    pub fingerprint: String,
    pub tls_version: String,
    pub cipher_hex: String,
    pub ext_hash: String,
}

impl Ja4sFingerprint {
    pub fn from_server_hello_bytes(data: &[u8]) -> Option<Self> {
        let hello = parse_server_hello(data)?;
        Some(Self::from_parsed(&hello))
    }

    pub fn from_parsed(hello: &ServerHello) -> Self {
        let effective_version = hello
            .supported_version
            .unwrap_or(hello.tls_version);

        let ver_str = version_str(effective_version);
        let ext_count = hello.extensions.len().min(99);
        let cipher_hex = format!("{:04x}", hello.selected_cipher);

        // Extensions sorted → SHA256 → first 12 hex chars
        let mut sorted_exts = hello.extensions.clone();
        sorted_exts.sort_unstable();
        let ext_csv = sorted_exts
            .iter()
            .map(|e| format!("{:04x}", e))
            .collect::<Vec<_>>()
            .join(",");
        let ext_hash = hex_sha256(&ext_csv)[..12].to_string();

        let fingerprint = format!("s{}{:02}_{}_{}",
            ver_str, ext_count, cipher_hex, ext_hash);

        Self { fingerprint, tls_version: ver_str.to_string(), cipher_hex, ext_hash }
    }
}

pub fn parse_server_hello(data: &[u8]) -> Option<ServerHello> {
    if data.len() < 5 { return None; }
    if data[0] != 0x16 { return None; } // Handshake

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len { return None; }

    let hs = &data[5..5 + record_len];
    if hs.is_empty() || hs[0] != 0x02 { return None; } // ServerHello

    let body = &hs[4..]; // skip type(1) + len(3)
    if body.len() < 34 { return None; }

    let tls_version = u16::from_be_bytes([body[0], body[1]]);
    let mut pos = 34; // skip version(2) + random(32)

    // Session ID
    if pos >= body.len() { return None; }
    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;

    // Selected cipher suite
    if pos + 2 > body.len() { return None; }
    let selected_cipher = u16::from_be_bytes([body[pos], body[pos + 1]]);
    pos += 2;

    // Compression method
    pos += 1;

    // Extensions
    if pos + 2 > body.len() {
        return Some(ServerHello {
            tls_version, supported_version: None,
            selected_cipher, extensions: vec![],
            alpn_selected: None,
        });
    }

    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(body.len());

    let mut extensions = Vec::new();
    let mut supported_version = None;
    let mut alpn_selected = None;
    let mut ep = pos;

    while ep + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[ep], body[ep + 1]]);
        let ext_len = u16::from_be_bytes([body[ep + 2], body[ep + 3]]) as usize;
        ep += 4;
        if ep + ext_len > ext_end { break; }

        let eb = &body[ep..ep + ext_len];
        extensions.push(ext_type);

        match ext_type {
            0x002b => { // Supported Versions
                if eb.len() >= 2 {
                    supported_version = Some(u16::from_be_bytes([eb[0], eb[1]]));
                }
            }
            0x0010 => { // ALPN
                if eb.len() >= 3 {
                    let proto_len = eb[2] as usize;
                    if eb.len() >= 3 + proto_len {
                        alpn_selected = std::str::from_utf8(&eb[3..3 + proto_len]).ok()
                            .map(|s| s.to_string());
                    }
                }
            }
            _ => {}
        }
        ep += ext_len;
    }

    Some(ServerHello {
        tls_version, supported_version, selected_cipher, extensions, alpn_selected,
    })
}

/// Check if a selected cipher is weak/deprecated
pub fn is_weak_cipher(cipher: u16) -> bool {
    matches!(cipher,
        // NULL ciphers
        0x0001 | 0x0002 | 0x0003 | 0x0004 | 0x0005 |
        // RC4 ciphers
        0x0004 | 0x0005 | 0xc007 | 0xc011 |
        // DES/3DES
        0x0009 | 0x000A | 0x000D | 0x000E | 0x000F | 0x000B | 0x000C |
        // EXPORT ciphers
        0x0008 | 0x000E | 0x0011 | 0x0014 |
        // Anonymous (no auth)
        0x0018 | 0x001B | 0xC018 | 0xC019
    )
}

fn version_str(v: u16) -> &'static str {
    match v {
        0x0304 | 0x7f00..=0x7fff => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

fn hex_sha256(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_ciphers_detected() {
        assert!(is_weak_cipher(0x0004)); // RC4
        assert!(is_weak_cipher(0x0009)); // DES
        assert!(!is_weak_cipher(0xc02b)); // ECDHE-ECDSA-AES128-GCM-SHA256
    }

    #[test]
    fn server_hello_fingerprint() {
        let hello = ServerHello {
            tls_version: 0x0303,
            supported_version: Some(0x0304),
            selected_cipher: 0xc02b,
            extensions: vec![0x002b, 0x0010, 0x0017],
            alpn_selected: Some("h2".to_string()),
        };
        let fp = Ja4sFingerprint::from_parsed(&hello);
        assert!(!fp.fingerprint.is_empty());
        assert!(fp.fingerprint.starts_with('s'));
        assert_eq!(fp.cipher_hex, "c02b");
    }
}
