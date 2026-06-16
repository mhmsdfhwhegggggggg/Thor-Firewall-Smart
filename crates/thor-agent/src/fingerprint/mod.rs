//! ThorFingerprint — Network Traffic Fingerprinting Engine
//!
//! Implements the JA4+ fingerprinting suite:
//!   ▸ JA4  — TLS client fingerprint (replaces JA3)
//!   ▸ JA4S — TLS server fingerprint
//!   ▸ JA4SSH — SSH client/server fingerprint (replaces HASSH)
//!
//! All fingerprints are computed from the wire format without decryption.
//! Uses SHA256 (FIPS-compliant) instead of MD5/SHA1.
//!
//! Axis 2: Full implementation replacing the mock in ml/ja4_analyzer.rs

pub mod ja4;
pub mod ja4s;
pub mod ja4ssh;

use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, warn};
use dashmap::DashMap;
use chrono::{DateTime, Utc};

pub use ja4::{Ja4Fingerprint, ClientHello, known_malicious_ja4};
pub use ja4s::{Ja4sFingerprint, ServerHello};
pub use ja4ssh::{Ja4SshFingerprint, SshKexInit};

// ─── Fingerprint Hit ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FingerprintHit {
    pub fingerprint: String,
    pub kind: FingerprintKind,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub is_malicious: bool,
    pub tool_hint: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FingerprintKind {
    Ja4Client,
    Ja4Server,
    Ja4Ssh,
}

// ─── Fingerprint Engine ───────────────────────────────────────────────────────

pub struct FingerprintEngine {
    /// Known-malicious JA4 hashes
    malicious_ja4: HashSet<String>,
    /// Recent fingerprint hits (fingerprint → count for rate analysis)
    hit_counts: Arc<DashMap<String, u64>>,
}

impl FingerprintEngine {
    pub fn new() -> Self {
        Self {
            malicious_ja4: known_malicious_ja4(),
            hit_counts: Arc::new(DashMap::new()),
        }
    }

    /// Analyse raw TLS bytes and return a fingerprint hit if malicious.
    pub fn analyse_tls_client(
        &self,
        data: &[u8],
        src_ip: &str,
        dst_ip: &str,
        dst_port: u16,
    ) -> Option<FingerprintHit> {
        let fp = Ja4Fingerprint::from_client_hello_bytes(data)?;

        // Increment hit count for analytics
        *self.hit_counts.entry(fp.fingerprint.clone()).or_insert(0) += 1;

        let is_malicious = self.malicious_ja4.contains(&fp.fingerprint);
        if is_malicious {
            warn!(
                fp = %fp.fingerprint,
                src = %src_ip,
                dst = %dst_ip,
                port = dst_port,
                "🚨 Malicious JA4 fingerprint detected"
            );
        } else {
            debug!(fp = %fp.fingerprint, "JA4 client fingerprint");
        }

        Some(FingerprintHit {
            fingerprint: fp.fingerprint,
            kind: FingerprintKind::Ja4Client,
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            dst_port,
            is_malicious,
            tool_hint: None,
            timestamp: Utc::now(),
        })
    }

    /// Analyse raw TLS bytes as a ServerHello.
    pub fn analyse_tls_server(
        &self,
        data: &[u8],
        src_ip: &str,
        dst_ip: &str,
        dst_port: u16,
    ) -> Option<FingerprintHit> {
        let fp = Ja4sFingerprint::from_server_hello_bytes(data)?;
        let is_weak = ja4s::is_weak_cipher(
            u16::from_str_radix(&fp.cipher_hex, 16).unwrap_or(0)
        );

        Some(FingerprintHit {
            fingerprint: fp.fingerprint,
            kind: FingerprintKind::Ja4Server,
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            dst_port,
            is_malicious: is_weak,
            tool_hint: if is_weak { Some("Weak cipher suite".to_string()) } else { None },
            timestamp: Utc::now(),
        })
    }

    /// Analyse raw SSH bytes.
    pub fn analyse_ssh(
        &self,
        data: &[u8],
        src_ip: &str,
        dst_ip: &str,
    ) -> Option<FingerprintHit> {
        let kex = ja4ssh::parse_ssh_kexinit(data)?;
        let fp = Ja4SshFingerprint::from_kex_init(&kex);

        if fp.is_malicious {
            warn!(
                hassh = %fp.hassh,
                tool = ?fp.tool_hint,
                src = %src_ip,
                "🚨 Malicious SSH fingerprint (HASSH)"
            );
        }

        Some(FingerprintHit {
            fingerprint: fp.hassh,
            kind: FingerprintKind::Ja4Ssh,
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            dst_port: 22,
            is_malicious: fp.is_malicious,
            tool_hint: fp.tool_hint.map(|s| s.to_string()),
            timestamp: Utc::now(),
        })
    }

    /// Add a custom malicious JA4 fingerprint to the database.
    pub fn add_malicious_ja4(&mut self, fp: String) {
        self.malicious_ja4.insert(fp);
    }

    /// Returns all fingerprints seen with their hit counts.
    pub fn top_fingerprints(&self, limit: usize) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self.hit_counts
            .iter()
            .map(|r| (r.key().clone(), *r.value()))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(limit);
        v
    }

    pub fn malicious_db_size(&self) -> usize {
        self.malicious_ja4.len()
    }
}

impl Default for FingerprintEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_initialises_with_known_bad_fingerprints() {
        let engine = FingerprintEngine::new();
        assert!(engine.malicious_db_size() > 0);
    }

    #[test]
    fn top_fingerprints_returns_sorted() {
        let engine = FingerprintEngine::new();
        engine.hit_counts.insert("fp1".to_string(), 100);
        engine.hit_counts.insert("fp2".to_string(), 50);
        engine.hit_counts.insert("fp3".to_string(), 200);
        let top = engine.top_fingerprints(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "fp3");
        assert_eq!(top[1].0, "fp1");
    }
}
