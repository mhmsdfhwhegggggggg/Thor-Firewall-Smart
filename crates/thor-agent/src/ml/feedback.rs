//! ML Feedback Loop — Phase 3: Continuous learning from analyst verdicts.
//!
//! Analyst marks alert as true/false positive → stored in ml_feedback table →
//! batch export for retraining pipeline → model version bumped.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::db::ThorDb;
use crate::db::feedback as fb;

#[derive(Debug, Serialize, Deserialize)]
pub struct FeedbackRequest {
    pub alert_id:         String,
    pub is_true_positive: bool,
    pub analyst:          String,
    pub notes:            Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FeedbackResponse {
    pub success:  bool,
    pub message:  String,
    pub fpr_30d:  Option<f64>,
}

/// Process feedback from API and persist to DB.
pub async fn process_feedback(
    db: &ThorDb,
    req: &FeedbackRequest,
    model_version: Option<&str>,
) -> Result<FeedbackResponse> {
    let alert_id = Uuid::parse_str(&req.alert_id)?;

    fb::submit_feedback(
        db,
        alert_id,
        req.is_true_positive,
        &req.analyst,
        req.notes.as_deref(),
        model_version,
        None, // features_json — populated by retraining pipeline
    ).await?;

    let verdict = if req.is_true_positive { "TRUE POSITIVE" } else { "FALSE POSITIVE" };
    info!("📊 ML feedback: alert={} verdict={} analyst={}", req.alert_id, verdict, req.analyst);

    // Return current FPR for the UI to display
    let stats = fb::get_feedback_stats(db).await.unwrap_or_else(|_| serde_json::json!({}));
    let fpr = stats.get("false_positive_rate_pct").and_then(|v| v.as_f64());

    Ok(FeedbackResponse {
        success: true,
        message: format!("Feedback recorded: {}", verdict),
        fpr_30d: fpr,
    })
}

/// Export labelled dataset for model retraining.
/// Called by retraining pipeline (Python ml/ scripts) via API.
pub async fn export_training_data(
    db: &ThorDb,
    since_model_version: Option<&str>,
) -> Result<Vec<serde_json::Value>> {
    let data = fb::get_retraining_dataset(db, since_model_version).await?;
    info!("📤 Exporting {} training samples for retraining", data.len());
    Ok(data)
}

/// Check if model needs retraining based on accumulated feedback.
pub async fn should_retrain(db: &ThorDb, threshold_samples: i64) -> bool {
    let result = sqlx::query!(
        "SELECT COUNT(*) as cnt FROM ml_feedback WHERE feedback_at > NOW() - INTERVAL '7 days'"
    )
    .fetch_one(db.pool.as_ref())
    .await;

    match result {
        Ok(row) => row.cnt.unwrap_or(0) >= threshold_samples,
        Err(e) => { warn!("Retrain check failed: {}", e); false }
    }
}
