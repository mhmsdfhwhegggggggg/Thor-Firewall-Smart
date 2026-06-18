//! Audit log persistence — tamper-evident HMAC chain stored in PostgreSQL.

use anyhow::Result;
use serde_json::Value as JsonValue;
use sha2::{Sha256, Digest};
use std::sync::atomic::{AtomicI64, Ordering};
use tracing::error;

use crate::db::ThorDb;

static LAST_CHAIN_HASH: std::sync::OnceLock<std::sync::Mutex<String>> =
    std::sync::OnceLock::new();

fn chain_hash_store() -> &'static std::sync::Mutex<String> {
    LAST_CHAIN_HASH.get_or_init(|| std::sync::Mutex::new("genesis".to_string()))
}

fn compute_hmac(prev_hash: &str, action: &str, actor: &str, time: &str) -> String {
    let secret = std::env::var("THOR_JWT_SECRET").unwrap_or_else(|_| "fallback-audit-key".into());
    let payload = format!("{}:{}:{}:{}", prev_hash, action, actor, time);
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(b":");
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

pub async fn append(
    db: &ThorDb,
    action: &str,
    actor: &str,
    target: Option<&str>,
    details: Option<&JsonValue>,
    source_ip: Option<&str>,
    result: &str,
    agent_hostname: &str,
) -> Result<()> {
    let now = chrono::Utc::now();
    let time_str = now.to_rfc3339();

    let chain_hash = {
        let mut guard = chain_hash_store().lock().unwrap();
        let new_hash = compute_hmac(&guard, action, actor, &time_str);
        *guard = new_hash.clone();
        new_hash
    };

    sqlx::query!(
        r#"
        INSERT INTO audit_log (event_time, action, actor, target, details, source_ip, result, chain_hash, agent_hostname)
        VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9)
        "#,
        now,
        action,
        actor,
        target,
        details,
        source_ip,
        result,
        &chain_hash,
        agent_hostname,
    )
    .execute(db.pool.as_ref())
    .await?;

    Ok(())
}
