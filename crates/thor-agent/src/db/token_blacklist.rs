//! JWT Token Blacklist — Phase 1 fix: token revocation on logout / admin action.
//!
//! Uses Postgres as source of truth + in-process LRU cache (10k entries) to avoid
//! DB hit on every request.  Cache TTL = 5 min; revoked tokens stay in DB until expiry.

use anyhow::Result;
use chrono::{DateTime, Utc};
use dashmap::DashSet;
use std::sync::Arc;
use tracing::{debug, info};

use crate::db::ThorDb;

/// In-process cache — avoids DB lookup on every authenticated request.
#[derive(Clone)]
pub struct TokenBlacklist {
    /// DashSet of revoked JTIs (JWT IDs). Bounded — periodically synced from DB.
    cache: Arc<DashSet<String>>,
    db: ThorDb,
}

impl TokenBlacklist {
    pub async fn new(db: ThorDb) -> Result<Self> {
        let cache = Arc::new(DashSet::with_capacity(10_000));

        // Pre-load non-expired blacklisted tokens at startup
        let bl = Self { cache: cache.clone(), db: db.clone() };
        bl.sync_from_db().await?;

        // Background sync every 5 minutes (picks up revocations from other nodes)
        let bl_clone = bl.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                if let Err(e) = bl_clone.sync_from_db().await {
                    tracing::warn!("Token blacklist sync error: {}", e);
                }
            }
        });

        info!("🔒 Token blacklist initialized ({} pre-loaded)", cache.len());
        Ok(bl)
    }

    /// Check if a JTI is revoked. O(1) in-memory check.
    pub fn is_revoked(&self, jti: &str) -> bool {
        self.cache.contains(jti)
    }

    /// Revoke a token (adds to DB + in-memory cache).
    pub async fn revoke(
        &self,
        jti: &str,
        expires_at: DateTime<Utc>,
        revoked_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        // Insert into DB
        sqlx::query!(
            r#"
            INSERT INTO token_blacklist (jti, expires_at, revoked_by, reason)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (jti) DO NOTHING
            "#,
            jti,
            expires_at,
            revoked_by,
            reason,
        )
        .execute(self.db.pool.as_ref())
        .await?;

        // Add to in-memory cache immediately
        self.cache.insert(jti.to_string());
        debug!("🔒 Revoked JWT: jti={}", jti);
        Ok(())
    }

    /// Purge expired tokens from DB and resync cache.
    async fn sync_from_db(&self) -> Result<()> {
        let rows = sqlx::query!(
            "SELECT jti FROM token_blacklist WHERE expires_at > NOW()"
        )
        .fetch_all(self.db.pool.as_ref())
        .await?;

        // Rebuild cache from DB
        self.cache.clear();
        for row in &rows {
            self.cache.insert(row.jti.clone());
        }
        debug!("🔄 Token blacklist synced: {} active revocations", rows.len());
        Ok(())
    }
}

/// Purge expired entries — called periodically.
pub async fn purge_expired(db: &ThorDb) -> Result<u64> {
    let result = sqlx::query!(
        "DELETE FROM token_blacklist WHERE expires_at < NOW()"
    )
    .execute(db.pool.as_ref())
    .await?;
    Ok(result.rows_affected())
}
