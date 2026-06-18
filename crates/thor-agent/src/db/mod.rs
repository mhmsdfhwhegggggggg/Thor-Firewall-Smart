//! Thor Database Persistence Layer — Phase 1 fix: no more in-memory-only state.
//!
//! Provides async Postgres access using sqlx with connection pooling.
//! All write operations are non-blocking (tokio channels + batch inserts).
//!
//! # Architecture
//! ```
//!   Detection Engine → alert_tx → BatchWriter task → Postgres (batch every 500ms or 100 rows)
//!   SOAR Engine      → campaign_tx → BatchWriter task → Postgres
//!   UEBA Engine      → profile_tx → BatchWriter task → Postgres
//! ```

pub mod alerts;
pub mod campaigns;
pub mod entity_profiles;
pub mod audit;
pub mod token_blacklist;
pub mod ioc_store;
pub mod feedback;
pub mod metrics_store;

use anyhow::{Context, Result};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Shared database pool — clone-able, backed by arc internally.
#[derive(Clone)]
pub struct ThorDb {
    pub pool: Arc<PgPool>,
}

impl ThorDb {
    /// Connect and run migrations. Call once at startup.
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .min_connections(2)
            .acquire_timeout(Duration::from_secs(10))
            .idle_timeout(Duration::from_secs(300))
            .max_lifetime(Duration::from_secs(1800))
            .connect(database_url)
            .await
            .context("Failed to connect to PostgreSQL")?;

        info!("🗄️  PostgreSQL connected: {} max connections", 20);

        // Run migrations from embedded SQL
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("Database migration failed")?;

        info!("✅ Database migrations complete");

        Ok(Self { pool: Arc::new(pool) })
    }

    /// Health check — returns true if DB is reachable.
    pub async fn ping(&self) -> bool {
        sqlx::query("SELECT 1")
            .execute(self.pool.as_ref())
            .await
            .is_ok()
    }
}

/// Start the background batch writer tasks.
/// Returns sender channels for other subsystems to push data.
pub async fn start_batch_writers(
    db: ThorDb,
) -> Result<BatchWriterHandles> {
    let (alert_tx, alert_rx) = tokio::sync::mpsc::channel::<alerts::AlertRow>(4096);
    let (campaign_tx, campaign_rx) = tokio::sync::mpsc::channel::<campaigns::CampaignUpsert>(256);
    let (metrics_tx, metrics_rx) = tokio::sync::mpsc::channel::<metrics_store::MetricsRow>(1024);

    // Alert batch writer
    let db_clone = db.clone();
    tokio::spawn(async move {
        alerts::batch_writer(db_clone, alert_rx).await;
    });

    // Campaign batch writer
    let db_clone = db.clone();
    tokio::spawn(async move {
        campaigns::batch_writer(db_clone, campaign_rx).await;
    });

    // Metrics batch writer (snapshots every 60s)
    let db_clone = db.clone();
    tokio::spawn(async move {
        metrics_store::batch_writer(db_clone, metrics_rx).await;
    });

    // Token blacklist cleanup (purge expired tokens every 10 minutes)
    let db_clone = db.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(600)).await;
            match token_blacklist::purge_expired(&db_clone).await {
                Ok(n) => { if n > 0 { info!("🧹 Purged {} expired JWT tokens from blacklist", n); } }
                Err(e) => warn!("Token blacklist purge error: {}", e),
            }
        }
    });

    info!("🚀 DB batch writers started (alerts, campaigns, metrics)");

    Ok(BatchWriterHandles {
        alert_tx,
        campaign_tx,
        metrics_tx,
    })
}

/// Channels the rest of the system uses to persist data asynchronously.
#[derive(Clone)]
pub struct BatchWriterHandles {
    pub alert_tx:    tokio::sync::mpsc::Sender<alerts::AlertRow>,
    pub campaign_tx: tokio::sync::mpsc::Sender<campaigns::CampaignUpsert>,
    pub metrics_tx:  tokio::sync::mpsc::Sender<metrics_store::MetricsRow>,
}
