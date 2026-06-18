//! UEBA entity profile persistence.

use anyhow::Result;
use chrono::Utc;
use serde_json::Value as JsonValue;
use tracing::error;

use crate::db::ThorDb;

pub async fn upsert_profile(
    db: &ThorDb,
    entity_type: &str,
    entity_id: &str,
    baseline_json: &JsonValue,
    risk_score: f64,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO entity_profiles (entity_type, entity_id, baseline_json, risk_score, last_seen, updated_at)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        ON CONFLICT (entity_type, entity_id) DO UPDATE SET
            baseline_json = EXCLUDED.baseline_json,
            risk_score    = EXCLUDED.risk_score,
            last_seen     = NOW(),
            updated_at    = NOW(),
            anomaly_count = entity_profiles.anomaly_count + CASE WHEN EXCLUDED.risk_score > 0.7 THEN 1 ELSE 0 END
        "#,
        entity_type,
        entity_id,
        baseline_json,
        risk_score,
    )
    .execute(db.pool.as_ref())
    .await?;
    Ok(())
}

pub async fn get_high_risk_entities(db: &ThorDb, min_score: f64) -> Result<Vec<serde_json::Value>> {
    let rows = sqlx::query!(
        r#"
        SELECT entity_type, entity_id, risk_score, anomaly_count, last_seen
        FROM entity_profiles
        WHERE risk_score >= $1
        ORDER BY risk_score DESC
        LIMIT 50
        "#,
        min_score
    )
    .fetch_all(db.pool.as_ref())
    .await?;

    Ok(rows.iter().map(|r| serde_json::json!({
        "entity_type": r.entity_type,
        "entity_id": r.entity_id,
        "risk_score": r.risk_score,
        "anomaly_count": r.anomaly_count,
        "last_seen": r.last_seen,
    })).collect())
}
