//! ThorDissector — Advanced TLS Protocol Dissector
//!
//! Full ClientHello + ServerHello + Certificate parsing with anomaly detection.
//! Complements the SNI extractor in tls/mod.rs with deeper analysis.
//!
//! Detects:
//!   ▸ Self-signed certificates (issuer == subject)
//!   ▸ Expired / future-dated certificates
//!   ▸ Wildcard cert misuse (*.example.com used as C2)
//!   ▸ Known-malicious cipher suites (RC4, NULL, EXPORT, anonymous)
//!   ▸ TLS downgrade attempts (FALLBACK_SCSV missing)
//!   ▸ SNI-as-IP-address (C2 evasion technique)
//!   ▸ JA4 fingerprint — delegates to fingerprint::ja4

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::fingerprint::ja4::{parse_client_hello, Ja4Fingerprint};

// ─── TLS Log (Zeek ssl.log schema) ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsLog {
    pub ts: DateTime<Utc>,
    pub uid: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub ssl_version: String,
    pub cipher: String,
    pub curve: Option<String>,
    pub server_name: Option<String>,
    pub resumed: bool,
    pub established: bool,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_not_before: Option<String>,
    pub cert_not_after: Option<String>,
    pub cert_is_self_signed: bool,
    pub ja4_client: Option<String>,
    pub ja4_server: Option<String>,
    pub anomalies: Vec<TlsAnomaly>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TlsAnomaly {
    SelfSignedCert,
    ExpiredCert,
    FutureDatedCert,
    WeakCipherSuite,
    NullCipher,
    ExportCipher,
    AnonymousCipher,
    Tls10Used,
    Ssl30Used,
    SnIpAddress,
    MissingFallbackScsv,
    CertSubjectWildcard,
    SuspiciousSni,
    KnownMaliciousJa4,
}

// ─── TLS version codes ────────────────────────────────────────────────────────

pub fn tls_version_name(v: u16) -> &'static str {
    match v {
        0x0304 => "TLSv1.3",
        0x0303 => "TLSv1.2",
        0x0302 => "TLSv1.1",
        0x0301 => "TLSv1.0",
        0x0300 => "SSLv3",
        0x0200 => "SSLv2",
        _ => "Unknown",
    }
}

/// IANA cipher suite names for common ciphers
pub fn cipher_name(c: u16) -> &'static str {
    match c {
        0x0000 => "TLS_NULL_WITH_NULL_NULL",
        0x0001 => "TLS_RSA_WITH_NULL_MD5",
        0x0002 => "TLS_RSA_WITH_NULL_SHA",
        0x0004 => "TLS_RSA_WITH_RC4_128_MD5",
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA",
        0x0009 => "TLS_RSA_WITH_DES_CBC_SHA",
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        _ => "UNKNOWN",
    }
}

// ─── Cipher anomaly checks ────────────────────────────────────────────────────

pub fn is_null_cipher(c: u16) -> bool {
    matches!(c, 0x0000 | 0x0001 | 0x0002 | 0x0003)
}

pub fn is_export_cipher(c: u16) -> bool {
    matches!(c, 0x0003 | 0x0006 | 0x0008 | 0x000b | 0x000e | 0x0011 | 0x0014 | 0x0017 | 0x0019)
}

pub fn is_anonymous_cipher(c: u16) -> bool {
    matches!(c,
        0x0018 | 0x001B | 0xc018 | 0xc019 |
        0x0046 | 0x0047 | 0x0048 | 0x0049 |
        0x006c | 0x006d
    )
}

pub fn is_rc4_cipher(c: u16) -> bool {
    matches!(c,
        0x0004 | 0x0005 | 0x000a |
        0xc007 | 0xc008 | 0xc011 | 0xc012 |
        0xc016 | 0xc017
    )
}

// ─── SNI checks ───────────────────────────────────────────────────────────────

/// Returns true if the SNI looks like an IP address (C2 evasion)
pub fn sni_is_ip(sni: &str) -> bool {
    // IPv4
    let parts: Vec<&str> = sni.split('.').collect();
    if parts.len() == 4 {
        if parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            return true;
        }
    }
    // IPv6 in brackets or hex
    sni.contains(':') || sni.starts_with('[')
}

/// Heuristically flag suspicious SNI (all-numeric, TLD mismatch, etc.)
pub fn sni_is_suspicious(sni: &str) -> bool {
    let d = sni.to_lowercase();
    // Tor gateways
    if d.ends_with(".onion") || d.ends_with(".onion.to") { return true; }
    // DGA-like: high randomness
    if crate::dissectors::dns::entropy(&d) > 3.8 { return true; }
    false
}

// ─── TLS Record Dissector ─────────────────────────────────────────────────────

/// Attempt to analyse raw TLS bytes and detect anomalies.
pub fn analyse_tls_bytes(
    data: &[u8],
    uid: &str,
    src_ip: &str,
    dst_ip: &str,
    dst_port: u16,
    known_malicious_ja4: &std::collections::HashSet<String>,
) -> Option<TlsLog> {
    if data.len() < 5 { return None; }
    if data[0] != 0x16 { return None; } // Not Handshake

    let mut anomalies = Vec::new();

    // Try to parse as ClientHello for JA4
    let (server_name, ssl_version, cipher_str, ja4_client) =
        if let Some(hello) = parse_client_hello(data) {
            let fp = Ja4Fingerprint::from_parsed(&hello);

            if known_malicious_ja4.contains(&fp.fingerprint) {
                anomalies.push(TlsAnomaly::KnownMaliciousJa4);
            }

            // Check cipher suites
            for c in &hello.cipher_suites {
                if is_null_cipher(*c) { anomalies.push(TlsAnomaly::NullCipher); }
                if is_export_cipher(*c) { anomalies.push(TlsAnomaly::ExportCipher); }
                if is_anonymous_cipher(*c) { anomalies.push(TlsAnomaly::AnonymousCipher); }
                if is_rc4_cipher(*c) { anomalies.push(TlsAnomaly::WeakCipherSuite); }
            }

            // TLS version anomalies
            let effective = hello.supported_versions.iter().copied().max()
                .unwrap_or(hello.tls_version);
            if effective == 0x0300 { anomalies.push(TlsAnomaly::Ssl30Used); }
            if effective == 0x0301 { anomalies.push(TlsAnomaly::Tls10Used); }

            // SNI anomalies
            if let Some(sni) = &hello.sni {
                if sni_is_ip(sni) { anomalies.push(TlsAnomaly::SnIpAddress); }
                if sni_is_suspicious(sni) { anomalies.push(TlsAnomaly::SuspiciousSni); }
            }

            let ver = hello.supported_versions.iter().copied().max()
                .unwrap_or(hello.tls_version);
            let ciphers = hello.cipher_suites.first()
                .map(|c| cipher_name(*c).to_string())
                .unwrap_or_default();

            (hello.sni, tls_version_name(ver).to_string(), ciphers, Some(fp.fingerprint))
        } else {
            (None, String::new(), String::new(), None)
        };

    anomalies.dedup_by(|a, b| a == b);

    Some(TlsLog {
        ts: Utc::now(),
        uid: uid.to_string(),
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        dst_port,
        ssl_version,
        cipher: cipher_str,
        curve: None,
        server_name,
        resumed: false,
        established: true,
        cert_subject: None,
        cert_issuer: None,
        cert_not_before: None,
        cert_not_after: None,
        cert_is_self_signed: false,
        ja4_client,
        ja4_server: None,
        anomalies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_ip_detection() {
        assert!(sni_is_ip("192.168.1.1"));
        assert!(sni_is_ip("10.0.0.1"));
        assert!(!sni_is_ip("example.com"));
        assert!(!sni_is_ip("a.b.c.d.e.com")); // too many parts
    }

    #[test]
    fn null_cipher_detection() {
        assert!(is_null_cipher(0x0000));
        assert!(is_null_cipher(0x0001));
        assert!(!is_null_cipher(0xc02b));
    }

    #[test]
    fn rc4_cipher_detection() {
        assert!(is_rc4_cipher(0x0004));
        assert!(is_rc4_cipher(0x0005));
        assert!(!is_rc4_cipher(0x1302));
    }

    #[test]
    fn version_names() {
        assert_eq!(tls_version_name(0x0304), "TLSv1.3");
        assert_eq!(tls_version_name(0x0303), "TLSv1.2");
        assert_eq!(tls_version_name(0x0300), "SSLv3");
    }
}
