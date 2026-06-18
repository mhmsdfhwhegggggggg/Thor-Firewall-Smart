//! Campaign persistence — upsert active attack campaigns to PostgreSQL.

use anyhow::Result;
use chrono::{DateTime, Utc};
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tracing::{info, error};
use uuid::Uuid;

use crate::db::ThorDb;

#[derive(Debug, Clone)]
pub struct CampaignUpsert {
    pub id:               Uuid,
    pub status:           String,
    pub max_threat_level: String,
    pub kill_chain_stage: Option<String>,
    pub alert_count:      i32,
    pub involved_ips:     Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub threat_narrative: Option<String>,
    pub first_seen:       DateTime<Utc>,
    pub last_seen:        DateTime<Utc>,
}

pub async fn batch_writer(db: ThorDb, mut rx: Receiver<CampaignUpsert>) {
    let mut batch: Vec<CampaignUpsert> = Vec::with_capacity(50);
    let mut interval = tokio::time::interval(Duration::from_secs(5));

    info!("📝 Campaign batch writer started");

    loop {
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(row) => {
                        batch.push(row);
                        if batch.len() >= 50 { flush(&db, &mut batch).await; }
                    }
                    None => {
                        if !batch.is_empty() { flush(&db, &mut batch).await; }
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                if !batch.is_empty() { flush(&db, &mut batch).await; }
            }
        }
    }
}

async fn flush(db: &ThorDb, batch: &mut Vec<CampaignUpsert>) {
    let n = batch.len();
    for row in batch.iter() {
        if let Err(e) = upsert_campaign(db, row).await {
            error!("Campaign upsert failed: {}", e);
        }
    }
    info!("💾 Persisted/updated {} campaigns", n);
    batch.clear();
}

async fn upsert_campaign(db: &ThorDb, c: &CampaignUpsert) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO campaigns (
            id, status, max_threat_level, kill_chain_stage, alert_count,
            involved_ips, mitre_techniques, threat_narrative, first_seen, last_seen
        ) VALUES ($1, $2::text, $3::text, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (id) DO UPDATE SET
            status           = EXCLUDED.status,
            max_threat_level = EXCLUDED.max_threat_level,
            kill_chain_stage = EXCLUDED.kill_chain_stage,
            alert_count      = EXCLUDED.alert_count,
            involved_ips     = EXCLUDED.involved_ips,
            mitre_techniques = EXCLUDED.mitre_techniques,
            threat_narrative = EXCLUDED.threat_narrative,
            last_seen        = EXCLUDED.last_seen
        "#,
        c.id,
        c.status,
        c.max_threat_level,
        c.kill_chain_stage,
        c.alert_count,
        &c.involved_ips,
        &c.mitre_techniques,
        c.threat_narrative,
        c.first_seen,
        c.last_seen,
    )
    .execute(db.pool.as_ref())
    .await?;
    Ok(())
}

pub async fn query_active(db: &ThorDb) -> Result<Vec<serde_json::Value>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, status::text, max_threat_level::text, kill_chain_stage,
               alert_count, involved_ips, mitre_techniques, threat_narrative,
               first_seen, last_seen
        FROM campaigns
        WHERE status = 'active'
        ORDER BY last_seen DESC
        LIMIT 100
        "#
    )
    .fetch_all(db.pool.as_ref())
    .await?;

    Ok(rows.iter().map(|r| serde_json::json!({
        "id": r.id,
        "status": r.status,
        "max_threat_level": r.max_threat_level,
        "kill_chain_stage": r.kill_chain_stage,
        "alert_count": r.alert_count,
        "involved_ips": r.involved_ips,
        "mitre_techniques": r.mitre_techniques,
        "threat_narrative": r.threat_narrative,
        "first_seen": r.first_seen,
        "last_seen": r.last_seen,
    })).collect())
}
