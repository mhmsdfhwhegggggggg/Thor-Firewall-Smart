//! Metrics snapshot persistence.

use anyhow::Result;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tracing::{info, error};

use crate::db::ThorDb;

#[derive(Debug, Clone)]
pub struct MetricsRow {
    pub agent_hostname:   String,
    pub packets_processed: i64,
    pub packets_dropped:   i64,
    pub active_flows:      i32,
    pub total_alerts:      i64,
    pub ioc_count:         i32,
    pub ws_clients:        i32,
    pub cpu_usage_pct:     f64,
    pub mem_usage_mb:      f64,
}

pub async fn batch_writer(db: ThorDb, mut rx: Receiver<MetricsRow>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    info!("📊 Metrics snapshot writer started (60s interval)");

    loop {
        interval.tick().await;
        // Drain all pending, keep only the latest per agent
        let mut latest: Option<MetricsRow> = None;
        while let Ok(row) = rx.try_recv() {
            latest = Some(row);
        }
        if let Some(row) = latest {
            if let Err(e) = insert_snapshot(&db, &row).await {
                error!("Metrics snapshot insert failed: {}", e);
            }
        }
    }
}

async fn insert_snapshot(db: &ThorDb, m: &MetricsRow) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO metrics_snapshots (
            agent_hostname, packets_processed, packets_dropped,
            active_flows, total_alerts, ioc_count, ws_clients,
            cpu_usage_pct, mem_usage_mb
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
        m.agent_hostname,
        m.packets_processed,
        m.packets_dropped,
        m.active_flows,
        m.total_alerts,
        m.ioc_count,
        m.ws_clients,
        m.cpu_usage_pct,
        m.mem_usage_mb,
    )
    .execute(db.pool.as_ref())
    .await?;
    Ok(())
}
