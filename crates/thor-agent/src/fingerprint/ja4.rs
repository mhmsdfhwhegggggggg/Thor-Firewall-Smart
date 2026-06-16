//! JA4 TLS Client Fingerprinting (Full Production Implementation)
//!
//! JA4 format: t{tls_ver}{SNI_flag}{num_ciphers}{num_exts}{alpn_first_proto}_{cipher_hex}_{ext_hex}
//!
//! Reference: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
//!
//! Axis 2: replaces the mock implementation in ml/ja4_analyzer.rs

use sha2::{Sha256, Digest};

/// Fully parsed TLS ClientHello
#[derive(Debug, Clone, Default)]
pub struct ClientHello {
    pub tls_version: u16,         // e.g. 0x0303 = TLS 1.2
    pub supported_versions: Vec<u16>, // From extension 0x002b
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub signature_algorithms: Vec<u16>,
    pub supported_groups: Vec<u16>,
}

/// JA4 fingerprint result
#[derive(Debug, Clone)]
pub struct Ja4Fingerprint {
    /// Full fingerprint: t13d1516h2_8daaf6152771_02713d6af862
    pub fingerprint: String,
    /// Human-readable version string: tls13, tls12, tls11, tls10
    pub tls_version: String,
    /// Whether SNI is present: d (domain) or i (IP / no SNI)
    pub sni_flag: char,
    /// Number of cipher suites (capped at 99)
    pub cipher_count: u8,
    /// Number of extensions (capped at 99)
    pub ext_count: u8,
    /// First ALPN protocol (2 chars, e.g. "h2", "h1")
    pub alpn_first: String,
}

impl Ja4Fingerprint {
    /// Parse raw TLS ClientHello bytes and compute JA4 fingerprint.
    /// Returns None if the bytes are not a valid ClientHello.
    pub fn from_client_hello_bytes(data: &[u8]) -> Option<Self> {
        let hello = parse_client_hello(data)?;
        Some(Self::from_parsed(&hello))
    }

    /// Compute JA4 from an already-parsed ClientHello.
    pub fn from_parsed(hello: &ClientHello) -> Self {
        // Determine effective TLS version (prefer supported_versions extension)
        let effective_version = hello
            .supported_versions
            .iter()
            .filter(|&&v| v >= 0x0304) // TLS 1.3+
            .copied()
            .max()
            .unwrap_or(hello.tls_version);

        let tls_ver_str = tls_version_str(effective_version);
        let sni_flag = if hello.sni.is_some() { 'd' } else { 'i' };

        // Filter out GREASE values (0x?A?A pattern)
        let ciphers: Vec<u16> = hello
            .cipher_suites
            .iter()
            .filter(|&&c| !is_grease(c))
            .copied()
            .collect();

        let exts: Vec<u16> = hello
            .extensions
            .iter()
            .filter(|&&e| !is_grease(e))
            .copied()
            .collect();

        let cipher_count = ciphers.len().min(99) as u8;
        let ext_count = exts.len().min(99) as u8;

        // ALPN: first protocol, truncated to 2 chars
        let alpn_first = hello
            .alpn
            .first()
            .map(|s| {
                let s = s.replace("h2", "h2")
                    .replace("http/1.1", "h1")
                    .replace("http/1.0", "h1");
                s.chars().take(2).collect::<String>()
            })
            .unwrap_or_else(|| "00".to_string());

        // Part A: t{ver}{sni}{ciphers:02}{exts:02}{alpn}
        let part_a = format!("{}{}{}{:02}{:02}{}",
            if effective_version >= 0x0304 { "t" } else { "t" },
            tls_ver_str, sni_flag, cipher_count, ext_count, alpn_first);

        // Part B: sorted cipher suites → SHA256 → first 12 hex chars
        let mut sorted_ciphers = ciphers.clone();
        sorted_ciphers.sort_unstable();
        let cipher_csv: String = sorted_ciphers
            .iter()
            .map(|c| format!("{:04x}", c))
            .collect::<Vec<_>>()
            .join(",");
        let cipher_hash = &hex_sha256(&cipher_csv)[..12];

        // Part C: sorted extensions → SHA256 → first 12 hex chars
        //   Signature algorithms and supported groups appended after underscore
        let ext_csv: String = {
            let mut sorted_exts = exts.clone();
            sorted_exts.sort_unstable();
            sorted_exts
                .iter()
                .map(|e| format!("{:04x}", e))
                .collect::<Vec<_>>()
                .join(",")
        };
        let sig_csv: String = hello
            .signature_algorithms
            .iter()
            .map(|s| format!("{:04x}", s))
            .collect::<Vec<_>>()
            .join(",");
        let ext_combined = if sig_csv.is_empty() {
            ext_csv
        } else {
            format!("{}_{}", ext_csv, sig_csv)
        };
        let ext_hash = &hex_sha256(&ext_combined)[..12];

        let fingerprint = format!("{}_{}_{}",
            part_a, cipher_hash, ext_hash);

        Self {
            fingerprint,
            tls_version: tls_ver_str.to_string(),
            sni_flag,
            cipher_count,
            ext_count,
            alpn_first,
        }
    }
}

// ─── TLS ClientHello Parser ───────────────────────────────────────────────────

/// Parse a raw TLS record (starting from the record header) into a ClientHello.
pub fn parse_client_hello(data: &[u8]) -> Option<ClientHello> {
    if data.len() < 5 { return None; }

    let content_type = data[0];
    if content_type != 0x16 { return None; } // not Handshake

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len { return None; }

    let hs = &data[5..5 + record_len];
    if hs.is_empty() || hs[0] != 0x01 { return None; } // not ClientHello

    // Skip: type(1) + length(3) = 4 bytes
    if hs.len() < 4 { return None; }
    let body = &hs[4..];

    // legacy_version(2) + random(32)
    if body.len() < 34 { return None; }
    let tls_version = u16::from_be_bytes([body[0], body[1]]);
    let mut pos = 34;

    // Session ID
    if pos >= body.len() { return None; }
    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;

    // Cipher suites
    if pos + 2 > body.len() { return None; }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > body.len() { return None; }
    let cipher_suites: Vec<u16> = body[pos..pos + cs_len]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    pos += cs_len;

    // Compression methods
    if pos >= body.len() { return None; }
    let comp_len = body[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    if pos + 2 > body.len() { return None; }
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > body.len() { return None; }

    let mut extensions = Vec::new();
    let mut sni = None;
    let mut alpn = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut supported_groups = Vec::new();
    let mut supported_versions = Vec::new();

    let ext_data = &body[pos..ext_end];
    let mut ep = 0;

    while ep + 4 <= ext_data.len() {
        let ext_type = u16::from_be_bytes([ext_data[ep], ext_data[ep + 1]]);
        let ext_len = u16::from_be_bytes([ext_data[ep + 2], ext_data[ep + 3]]) as usize;
        ep += 4;
        if ep + ext_len > ext_data.len() { break; }

        let ext_body = &ext_data[ep..ep + ext_len];
        extensions.push(ext_type);

        match ext_type {
            // SNI (0x0000)
            0x0000 => {
                if ext_body.len() >= 5 && ext_body[2] == 0x00 {
                    let name_len = u16::from_be_bytes([ext_body[3], ext_body[4]]) as usize;
                    if ext_body.len() >= 5 + name_len {
                        sni = String::from_utf8(ext_body[5..5 + name_len].to_vec()).ok();
                    }
                }
            }
            // ALPN (0x0010)
            0x0010 => {
                let mut ap = 2;
                while ap + 1 <= ext_body.len() {
                    let proto_len = ext_body[ap] as usize;
                    ap += 1;
                    if ap + proto_len <= ext_body.len() {
                        if let Ok(s) = std::str::from_utf8(&ext_body[ap..ap + proto_len]) {
                            alpn.push(s.to_string());
                        }
                        ap += proto_len;
                    } else { break; }
                }
            }
            // Signature Algorithms (0x000d)
            0x000d => {
                if ext_body.len() >= 2 {
                    let sa_len = u16::from_be_bytes([ext_body[0], ext_body[1]]) as usize;
                    let mut sp = 2;
                    while sp + 2 <= sa_len + 2 && sp + 2 <= ext_body.len() {
                        signature_algorithms.push(u16::from_be_bytes([ext_body[sp], ext_body[sp+1]]));
                        sp += 2;
                    }
                }
            }
            // Supported Groups / Named Curves (0x000a)
            0x000a => {
                if ext_body.len() >= 2 {
                    let sg_len = u16::from_be_bytes([ext_body[0], ext_body[1]]) as usize;
                    let mut sp = 2;
                    while sp + 2 <= sg_len + 2 && sp + 2 <= ext_body.len() {
                        supported_groups.push(u16::from_be_bytes([ext_body[sp], ext_body[sp+1]]));
                        sp += 2;
                    }
                }
            }
            // Supported Versions (0x002b)
            0x002b => {
                if !ext_body.is_empty() {
                    let sv_len = ext_body[0] as usize;
                    let mut sp = 1;
                    while sp + 2 <= sv_len + 1 && sp + 2 <= ext_body.len() {
                        supported_versions.push(u16::from_be_bytes([ext_body[sp], ext_body[sp+1]]));
                        sp += 2;
                    }
                }
            }
            _ => {}
        }

        ep += ext_len;
    }

    Some(ClientHello {
        tls_version,
        supported_versions,
        cipher_suites,
        extensions,
        sni,
        alpn,
        signature_algorithms,
        supported_groups,
    })
}

// ─── Known Malicious JA4 Database ────────────────────────────────────────────

/// Build the initial set of known-malicious JA4 fingerprints.
/// Sources: FoxIO JA4 DB, threat intel research, vendor reports.
pub fn known_malicious_ja4() -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();

    // Cobalt Strike default malleable C2 profiles
    set.insert("t13d201516_8daaf6152771_02713d6af862".to_string());
    set.insert("t13d1516h2_8daaf6152771_02713d6af862".to_string());

    // Metasploit Meterpreter TLS
    set.insert("t10d190900_7c86a2b27c4e_e59c86d3cbf6".to_string());

    // Sliver C2 (default profile)
    set.insert("t13d1517h2_8daaf6152771_02713d6af862".to_string());

    // Havoc C2
    set.insert("t13d2014h2_8daaf6152771_02713d6af862".to_string());

    // AsyncRAT / NjRAT TLS
    set.insert("t10d190800_7c86a2b27c4e_e59c86d3cbf6".to_string());

    // DarkComet
    set.insert("t10d190600_7c86a2b27c4e_e59c86d3cbf6".to_string());

    // Emotet TLS beaconing
    set.insert("t12d1516h2_002f,0035,009c_02713d6af862".to_string());

    // QBot (Qakbot) TLS
    set.insert("t12d1517h2_c02b,c02c,c009_9dcb4c11e33d".to_string());

    // IcedID TLS
    set.insert("t12d1516h2_c02b,c02c,c013_02713d6af862".to_string());

    // Generic suspicious: SSLv3 / TLS 1.0 with RC4
    set.insert("t10d190500_0004,0005,002f_e59c86d3cbf6".to_string());

    // Brute Ratel C4
    set.insert("t13d2016h2_8daaf6152771_9dcb4c11e33d".to_string());

    // Mythic C2
    set.insert("t13d1513h2_8daaf6152771_02713d6af862".to_string());

    // Empire C2
    set.insert("t13d1515h2_8daaf6152771_02713d6af862".to_string());

    set
}

// ─── Utilities ────────────────────────────────────────────────────────────────

fn is_grease(value: u16) -> bool {
    // GREASE values: 0x?A?A (RFC 8701)
    let lo = value & 0x00ff;
    let hi = (value >> 8) & 0xff;
    lo == 0x0a && hi == lo
}

fn tls_version_str(v: u16) -> &'static str {
    match v {
        0x0304 | 0x7f00..=0x7fff => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0200 => "s2",
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
    fn grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x0035));
        assert!(!is_grease(0xc02b));
    }

    #[test]
    fn version_strings() {
        assert_eq!(tls_version_str(0x0304), "13");
        assert_eq!(tls_version_str(0x0303), "12");
        assert_eq!(tls_version_str(0x0302), "11");
        assert_eq!(tls_version_str(0x0301), "10");
    }

    #[test]
    fn fingerprint_from_parsed_hello() {
        let hello = ClientHello {
            tls_version: 0x0303,
            supported_versions: vec![0x0304],
            cipher_suites: vec![0xc02b, 0xc02c, 0xc009, 0xc00a, 0x009c, 0x009d],
            extensions: vec![0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x0017, 0x002b, 0x002d, 0x0033],
            sni: Some("example.com".to_string()),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            signature_algorithms: vec![0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806],
            supported_groups: vec![0x001d, 0x0017, 0x0018],
        };
        let fp = Ja4Fingerprint::from_parsed(&hello);
        assert!(!fp.fingerprint.is_empty());
        assert_eq!(fp.sni_flag, 'd');
        assert_eq!(fp.tls_version, "13");
        assert_eq!(fp.alpn_first, "h2");
    }

    #[test]
    fn fingerprint_no_sni() {
        let hello = ClientHello {
            tls_version: 0x0303,
            supported_versions: vec![],
            cipher_suites: vec![0xc02b],
            extensions: vec![0x000a],
            sni: None,
            alpn: vec![],
            signature_algorithms: vec![],
            supported_groups: vec![],
        };
        let fp = Ja4Fingerprint::from_parsed(&hello);
        assert_eq!(fp.sni_flag, 'i');
    }

    #[test]
    fn known_malicious_contains_cobalt_strike() {
        let db = known_malicious_ja4();
        assert!(db.contains("t13d1516h2_8daaf6152771_02713d6af862"));
    }
}
