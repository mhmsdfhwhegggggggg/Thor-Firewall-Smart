//! Alert persistence — async batch inserts to PostgreSQL.
//!
//! Adapts from the in-memory events::Alert to a flat DB row.

use anyhow::Result;
use chrono::{DateTime, Utc};
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tracing::{info, error};

use crate::events::{Alert, RuleType};
use thor_common::ThreatLevel;
use crate::db::ThorDb;

// ─── Flat row for INSERT ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AlertRow {
    pub id:             String,
    pub rule_name:      String,
    pub rule_type:      String,
    pub threat_level:   String,
    pub src_ip:         Option<String>,
    pub dst_ip:         Option<String>,
    pub dst_port:       Option<i32>,
    pub pid:            Option<i32>,
    pub process_name:   Option<String>,
    pub message:        String,
    pub ml_score:       Option<f64>,
    pub detected_at:    DateTime<Utc>,
    pub agent_hostname: String,
    pub agent_version:  String,
}

impl AlertRow {
    pub fn from_alert(alert: &Alert, agent_hostname: &str, agent_version: &str) -> Self {
        let rule_type = match alert.rule_type {
            RuleType::Sigma      => "sigma",
            RuleType::Yara       => "yara",
            RuleType::Ioc        => "ioc",
            RuleType::Ml         => "ml",
            RuleType::Xdp        => "ids",   // map to ids enum value
            RuleType::Ids        => "ids",
            RuleType::Fim        => "fim",
            RuleType::Ueba       => "ml",    // closest enum value
            RuleType::ThreatIntel => "ioc",  // closest enum value
        };
        let threat_level = match alert.threat_level {
            ThreatLevel::Critical => "critical",
            ThreatLevel::High     => "high",
            ThreatLevel::Medium   => "medium",
            ThreatLevel::Low      => "low",
            ThreatLevel::Unknown  => "low",
        };
        Self {
            id:             alert.id.clone(),
            rule_name:      alert.rule_name.clone(),
            rule_type:      rule_type.to_string(),
            threat_level:   threat_level.to_string(),
            src_ip:         alert.src_ip.clone(),
            dst_ip:         alert.dst_ip.clone(),
            dst_port:       alert.dst_port.map(|p| p as i32),
            pid:            alert.pid.map(|p| p as i32),
            process_name:   alert.process_name.clone(),
            message:        alert.description.clone(),
            ml_score:       alert.ml_score.map(|s| s as f64),
            detected_at:    alert.timestamp,
            agent_hostname: agent_hostname.to_string(),
            agent_version:  agent_version.to_string(),
        }
    }
}

// ─── Batch writer ─────────────────────────────────────────────────────────────

pub async fn batch_writer(db: ThorDb, mut rx: Receiver<AlertRow>) {
    let mut batch: Vec<AlertRow> = Vec::with_capacity(100);
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    info!("📝 Alert batch writer started");

    loop {
        tokio::select! {
            maybe_row = rx.recv() => {
                match maybe_row {
                    Some(row) => {
                        batch.push(row);
                        if batch.len() >= 100 { flush_batch(&db, &mut batch).await; }
                    }
                    None => {
                        if !batch.is_empty() { flush_batch(&db, &mut batch).await; }
                        info!("Alert batch writer shutting down");
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                if !batch.is_empty() { flush_batch(&db, &mut batch).await; }
            }
        }
    }
}

async fn flush_batch(db: &ThorDb, batch: &mut Vec<AlertRow>) {
    let n = batch.len();
    if let Err(e) = insert_batch(db, batch).await {
        error!("❌ Failed to persist {} alerts: {}", n, e);
    } else {
        info!("💾 Persisted {} alerts", n);
    }
    batch.clear();
}

async fn insert_batch(db: &ThorDb, batch: &[AlertRow]) -> Result<()> {
    for row in batch {
        sqlx::query!(
            r#"
            INSERT INTO alerts (
                rule_name, rule_type, threat_level, message,
                src_ip, dst_ip, dst_port, pid, process_name,
                ml_score, detected_at, agent_hostname, agent_version
            ) VALUES (
                $1, $2::text, $3::text, $4,
                $5::inet, $6::inet, $7, $8, $9,
                $10, $11, $12, $13
            )
            ON CONFLICT DO NOTHING
            "#,
            row.rule_name,
            row.rule_type,
            row.threat_level,
            row.message,
            row.src_ip,
            row.dst_ip,
            row.dst_port,
            row.pid,
            row.process_name,
            row.ml_score,
            row.detected_at,
            row.agent_hostname,
            row.agent_version,
        )
        .execute(db.pool.as_ref())
        .await?;
    }
    Ok(())
}

/// Query recent alerts for the API.
pub async fn query_recent(
    db: &ThorDb,
    limit: i64,
    offset: i64,
    min_level: Option<&str>,
) -> Result<Vec<serde_json::Value>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, rule_name, rule_type::text, threat_level::text, message,
               src_ip::text, dst_ip::text, dst_port, pid, process_name,
               mitre_tactic, mitre_technique, ml_score, campaign_id,
               detected_at, status::text
        FROM alerts
        WHERE ($3::text IS NULL OR threat_level::text >= $3)
        ORDER BY detected_at DESC
        LIMIT $1 OFFSET $2
        "#,
        limit,
        offset,
        min_level,
    )
    .fetch_all(db.pool.as_ref())
    .await?;

    Ok(rows.iter().map(|r| serde_json::json!({
        "id": r.id,
        "rule_name": r.rule_name,
        "rule_type": r.rule_type,
        "threat_level": r.threat_level,
        "message": r.message,
        "src_ip": r.src_ip,
        "dst_ip": r.dst_ip,
        "pid": r.pid,
        "process_name": r.process_name,
        "mitre_tactic": r.mitre_tactic,
        "mitre_technique": r.mitre_technique,
        "ml_score": r.ml_score,
        "campaign_id": r.campaign_id,
        "detected_at": r.detected_at,
        "status": r.status,
    })).collect())
}
