//! Immutable Audit Log — PCI-DSS / ISO-27001 compliant
//!
//! Every security-relevant API action is logged with:
//!   - Timestamp (UTC, nanosecond precision)
//!   - User identity (from JWT claims)
//!   - Action type (LOGIN, RULE_INJECT, IP_BLOCK, ALERT_ACK, etc.)
//!   - Source IP of the request
//!   - Result (Success / Failure)
//!   - SHA256 hash of the entry (tamper-evident chain)
//!
//! Storage: sled embedded DB (append-only behaviour enforced by API).
//! Entries are NEVER deleted — only exported after retention period.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{info, error};

// ─── Entry types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    Login,
    LoginFailed,
    Logout,
    AlertAcknowledged,
    AlertExported,
    RuleInjected,
    RuleApproved,
    RuleRejected,
    IpBlocked,
    IpUnblocked,
    IocAdded,
    IocRemoved,
    AgentIsolated,
    AgentRestored,
    ConfigChanged,
    ForensicsExported,
    ApiAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: u64,
    pub timestamp_utc: String,
    pub user: String,
    pub role: String,
    pub action: AuditAction,
    pub target: String,
    pub result: AuditResult,
    pub source_ip: String,
    pub detail: String,
    pub chain_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditResult {
    Success,
    Failure,
    Denied,
}

// ─── Logger ──────────────────────────────────────────────────────────────────

pub struct AuditLogger {
    db: sled::Db,
    prev_hash: parking_lot::Mutex<String>,
}

impl AuditLogger {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let db = sled::Config::new()
            .path(path)
            .mode(sled::Mode::HighThroughput)
            .open()?;

        let prev_hash = db
            .last()?
            .and_then(|(_, v)| serde_json::from_slice::<AuditEntry>(&v).ok())
            .map(|e| e.chain_hash)
            .unwrap_or_else(|| "GENESIS".to_string());

        info!("📋 Audit log opened: {} entries, last_hash={}", db.len(), &prev_hash[..8]);

        Ok(Self {
            db,
            prev_hash: parking_lot::Mutex::new(prev_hash),
        })
    }

    pub fn log(
        &self,
        user: &str,
        role: &str,
        action: AuditAction,
        target: &str,
        result: AuditResult,
        source_ip: &str,
        detail: &str,
    ) {
        let id = self.db.generate_id().unwrap_or(0);
        let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);

        let mut prev = self.prev_hash.lock();

        let raw = format!(
            "{}|{}|{}|{:?}|{}|{:?}|{}|{}|{}",
            id, timestamp, user, action, target, result, source_ip, detail, *prev
        );
        let chain_hash = format!("{:x}", Sha256::digest(raw.as_bytes()));

        let entry = AuditEntry {
            id,
            timestamp_utc: timestamp,
            user: user.to_string(),
            role: role.to_string(),
            action,
            target: target.to_string(),
            result,
            source_ip: source_ip.to_string(),
            detail: detail.to_string(),
            chain_hash: chain_hash.clone(),
        };

        match serde_json::to_vec(&entry) {
            Ok(bytes) => {
                let key = id.to_be_bytes();
                if let Err(e) = self.db.insert(key, bytes) {
                    error!("Audit write failed: {}", e);
                } else {
                    *prev = chain_hash;
                    info!("📋 AUDIT [{:?}] user={} target={}", entry.action, user, target);
                }
            }
            Err(e) => error!("Audit serialize failed: {}", e),
        }
    }

    pub fn recent(&self, limit: usize) -> Vec<AuditEntry> {
        self.db
            .iter()
            .rev()
            .take(limit)
            .filter_map(|r| r.ok())
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    }

    pub fn verify_chain(&self) -> bool {
        let mut prev = "GENESIS".to_string();
        for item in self.db.iter() {
            let Ok((_, v)) = item else { return false };
            let Ok(entry) = serde_json::from_slice::<AuditEntry>(&v) else { return false };

            let raw = format!(
                "{}|{}|{}|{:?}|{}|{:?}|{}|{}|{}",
                entry.id, entry.timestamp_utc, entry.user,
                entry.action, entry.target, entry.result,
                entry.source_ip, entry.detail, prev
            );
            let expected = format!("{:x}", Sha256::digest(raw.as_bytes()));
            if expected != entry.chain_hash {
                error!("🚨 AUDIT CHAIN BROKEN at entry id={}", entry.id);
                return false;
            }
            prev = entry.chain_hash;
        }
        true
    }
}

pub type SharedAuditLogger = Arc<AuditLogger>;
