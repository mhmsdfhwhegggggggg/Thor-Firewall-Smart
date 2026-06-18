//! ML Feedback loop — Phase 3: analyst marks true/false positive → retraining DB.

use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use crate::db::ThorDb;

pub async fn submit_feedback(
    db: &ThorDb,
    alert_id: Uuid,
    is_true_positive: bool,
    analyst: &str,
    notes: Option<&str>,
    model_version: Option<&str>,
    features_json: Option<&serde_json::Value>,
) -> Result<()> {
    // 1. Insert feedback record
    sqlx::query!(
        r#"
        INSERT INTO ml_feedback (alert_id, is_true_positive, analyst, features_json, model_version, notes)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        alert_id,
        is_true_positive,
        analyst,
        features_json,
        model_version,
        notes,
    )
    .execute(db.pool.as_ref())
    .await?;

    // 2. Update alert status based on feedback
    let new_status = if is_true_positive { "acknowledged" } else { "false_positive" };
    sqlx::query!(
        r#"UPDATE alerts SET status = $1::alert_status, false_positive_feedback = $2,
           analyst_notes = $3, acknowledged_by = $4, acknowledged_at = NOW()
           WHERE id = $5"#,
        new_status,
        !is_true_positive,
        notes,
        analyst,
        alert_id,
    )
    .execute(db.pool.as_ref())
    .await?;

    Ok(())
}

pub async fn get_feedback_stats(db: &ThorDb) -> Result<serde_json::Value> {
    let row = sqlx::query!(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE is_true_positive) as true_positives,
            COUNT(*) FILTER (WHERE NOT is_true_positive) as false_positives,
            COUNT(*) as total,
            ROUND(
                100.0 * COUNT(*) FILTER (WHERE NOT is_true_positive) / NULLIF(COUNT(*), 0), 2
            ) as fpr_pct
        FROM ml_feedback
        WHERE feedback_at > NOW() - INTERVAL '30 days'
        "#
    )
    .fetch_one(db.pool.as_ref())
    .await?;

    Ok(serde_json::json!({
        "period": "30d",
        "true_positives": row.true_positives,
        "false_positives": row.false_positives,
        "total_feedback": row.total,
        "false_positive_rate_pct": row.fpr_pct,
    }))
}

pub async fn get_retraining_dataset(db: &ThorDb, model_version: Option<&str>) -> Result<Vec<serde_json::Value>> {
    let rows = sqlx::query!(
        r#"
        SELECT f.features_json, f.is_true_positive, f.model_version
        FROM ml_feedback f
        WHERE f.features_json IS NOT NULL
          AND ($1::text IS NULL OR f.model_version < $1)
        ORDER BY f.feedback_at DESC
        LIMIT 10000
        "#,
        model_version,
    )
    .fetch_all(db.pool.as_ref())
    .await?;

    Ok(rows.iter().map(|r| serde_json::json!({
        "features": r.features_json,
        "label": r.is_true_positive,
        "model_version": r.model_version,
    })).collect())
}
