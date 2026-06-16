//! Continuous Learning Engine — records analyst feedback for periodic model retraining.
//!
//! Analysts classify alerts as True Positive (TP) or False Positive (FP).
//! Feedback is persisted to a SQLite journal. A background task periodically
//! exports labeled examples and triggers ONNX model re-export.
//!
//! # Flow
//! ```text
//! Analyst UI/API
//!     │ label(alert_id, TP/FP, features)
//!     ▼
//! ContinuousLearner::record_feedback()
//!     │ persist to SQLite journal
//!     ▼
//! background task (every N hours)
//!     │ export_training_data() → labeled_examples.csv
//!     │ trigger retrain script (scripts/train_and_export.py)
//!     ▼
//! New ONNX model replaces models/thor_ueba_model.onnx
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn, error};
use chrono::Utc;

// ─── Feedback label ───────────────────────────────────────────────────────────

/// Analyst classification of a triggered alert.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum FeedbackLabel {
    /// The alert was a genuine threat (model was correct to alert).
    TruePositive,
    /// The alert was a false alarm (model should not have alerted).
    FalsePositive,
    /// Ambiguous — do not use for training but log for review.
    Uncertain,
}

impl FeedbackLabel {
    /// Returns the integer label used in the training CSV (1=TP, 0=FP, -1=uncertain).
    pub fn as_int(self) -> i8 {
        match self {
            FeedbackLabel::TruePositive => 1,
            FeedbackLabel::FalsePositive => 0,
            FeedbackLabel::Uncertain => -1,
        }
    }

    /// Parse from string ("tp", "fp", "uncertain").
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tp" | "true_positive" | "1" => Some(FeedbackLabel::TruePositive),
            "fp" | "false_positive" | "0" => Some(FeedbackLabel::FalsePositive),
            "uncertain" | "u" | "-1" => Some(FeedbackLabel::Uncertain),
            _ => None,
        }
    }
}

// ─── Feedback entry ───────────────────────────────────────────────────────────

/// A single labeled training example from an analyst.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackEntry {
    /// The alert ID this feedback refers to.
    pub alert_id: String,
    /// Analyst username or ID.
    pub analyst_id: String,
    /// Classification label.
    pub label: FeedbackLabel,
    /// The 28-dimensional feature vector used for ONNX scoring.
    pub features: Vec<f32>,
    /// Optional free-text explanation from the analyst.
    pub notes: Option<String>,
    /// When this feedback was recorded (RFC3339).
    pub recorded_at: String,
    /// ML anomaly score that triggered the alert.
    pub original_score: f32,
}

// ─── Engine ───────────────────────────────────────────────────────────────────

/// The continuous learning engine — thread-safe via `Arc<Mutex<Connection>>`.
pub struct ContinuousLearner {
    db: Arc<Mutex<Connection>>,
    model_path: PathBuf,
    export_path: PathBuf,
    retrain_script: PathBuf,
    /// Minimum number of new feedback entries before triggering retraining.
    retrain_threshold: usize,
}

impl ContinuousLearner {
    /// Open (or create) the feedback journal at `db_path`.
    pub fn open(
        db_path: &Path,
        model_path: &Path,
        export_path: &Path,
    ) -> Result<Self> {
        let conn = Connection::open(db_path)
            .with_context(|| format!("Cannot open feedback DB at {:?}", db_path))?;

        // Schema
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS feedback (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id      TEXT    NOT NULL,
                analyst_id    TEXT    NOT NULL,
                label         INTEGER NOT NULL,
                features      BLOB    NOT NULL,
                notes         TEXT,
                original_score REAL   NOT NULL,
                recorded_at   TEXT    NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_feedback_recorded ON feedback(recorded_at);
            CREATE INDEX IF NOT EXISTS idx_feedback_label    ON feedback(label);",
        ).context("Failed to create feedback schema")?;

        info!("📚 ContinuousLearner: journal opened at {:?}", db_path);

        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
            model_path: model_path.to_path_buf(),
            export_path: export_path.to_path_buf(),
            retrain_script: PathBuf::from("scripts/train_and_export.py"),
            retrain_threshold: 100,
        })
    }

    /// Override the minimum feedback count that triggers retraining.
    pub fn with_retrain_threshold(mut self, n: usize) -> Self {
        self.retrain_threshold = n;
        self
    }

    /// Record analyst feedback for a specific alert.
    ///
    /// Returns the row ID of the inserted entry.
    pub async fn record_feedback(&self, entry: &FeedbackEntry) -> Result<i64> {
        let db = self.db.lock().await;

        // Serialize features as raw f32 bytes (compact binary storage)
        let feat_bytes: Vec<u8> = entry.features.iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();

        let row_id = db.execute(
            "INSERT INTO feedback
                (alert_id, analyst_id, label, features, notes, original_score, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry.alert_id,
                entry.analyst_id,
                entry.label.as_int(),
                feat_bytes,
                entry.notes,
                entry.original_score,
                entry.recorded_at,
            ],
        ).context("Failed to insert feedback entry")?;

        let last_id = db.last_insert_rowid();
        info!(
            "💾 Feedback recorded: alert={} label={:?} analyst={} row={}",
            entry.alert_id, entry.label, entry.analyst_id, last_id
        );

        Ok(last_id)
    }

    /// Return the total number of feedback entries in the journal.
    pub async fn feedback_count(&self) -> Result<usize> {
        let db = self.db.lock().await;
        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM feedback",
            [],
            |row| row.get(0),
        ).context("Failed to count feedback")?;
        Ok(count as usize)
    }

    /// Return feedback statistics: (total, true_positives, false_positives, uncertain).
    pub async fn stats(&self) -> Result<FeedbackStats> {
        let db = self.db.lock().await;
        let total: i64 = db.query_row("SELECT COUNT(*) FROM feedback", [], |r| r.get(0))?;
        let tp: i64 = db.query_row("SELECT COUNT(*) FROM feedback WHERE label = 1", [], |r| r.get(0))?;
        let fp: i64 = db.query_row("SELECT COUNT(*) FROM feedback WHERE label = 0", [], |r| r.get(0))?;
        let unc: i64 = db.query_row("SELECT COUNT(*) FROM feedback WHERE label = -1", [], |r| r.get(0))?;
        Ok(FeedbackStats {
            total: total as usize,
            true_positives: tp as usize,
            false_positives: fp as usize,
            uncertain: unc as usize,
        })
    }

    /// Export all usable feedback (TP + FP, excluding Uncertain) to a CSV for retraining.
    ///
    /// CSV format: `label,f0,f1,...,f27`
    pub async fn export_training_data(&self) -> Result<PathBuf> {
        let db = self.db.lock().await;

        let mut stmt = db.prepare(
            "SELECT label, features FROM feedback WHERE label IN (0, 1) ORDER BY id"
        ).context("Failed to prepare export query")?;

        let mut rows = stmt.query([])?;
        let mut lines = vec!["label,f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13,f14,f15,f16,f17,f18,f19,f20,f21,f22,f23,f24,f25,f26,f27".to_string()];

        let mut count = 0usize;
        while let Some(row) = rows.next()? {
            let label: i8 = row.get(0)?;
            let feat_bytes: Vec<u8> = row.get(1)?;

            // Deserialize f32 features from little-endian bytes
            let features: Vec<f32> = feat_bytes.chunks_exact(4)
                .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .collect();

            if features.len() == 28 {
                let feat_str: Vec<String> = features.iter().map(|f| format!("{:.6}", f)).collect();
                lines.push(format!("{},{}", label, feat_str.join(",")));
                count += 1;
            }
        }
        drop(rows);
        drop(stmt);
        drop(db);

        let csv_path = self.export_path.join("labeled_feedback.csv");
        std::fs::write(&csv_path, lines.join("\n"))
            .with_context(|| format!("Cannot write CSV to {:?}", csv_path))?;

        info!("📊 Exported {} training examples to {:?}", count, csv_path);
        Ok(csv_path)
    }

    /// Check if retraining should be triggered and do so if threshold is met.
    ///
    /// Returns true if retraining was triggered.
    pub async fn maybe_retrain(&self) -> Result<bool> {
        let count = self.feedback_count().await?;
        if count < self.retrain_threshold {
            return Ok(false);
        }

        info!("🔄 Retraining threshold reached ({} entries) — exporting and triggering retrain", count);
        let csv_path = self.export_training_data().await?;

        // Invoke the Python training script
        let output = tokio::process::Command::new("python3")
            .arg(&self.retrain_script)
            .arg("--input").arg(&csv_path)
            .arg("--output").arg(&self.model_path)
            .output()
            .await
            .context("Failed to spawn retrain script")?;

        if output.status.success() {
            info!("✅ Model retrained successfully. New ONNX model at {:?}", self.model_path);
            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("⚠️  Retrain script failed: {}", stderr);
            Ok(false)
        }
    }

    /// Spawn a background task that checks for retraining every `interval`.
    pub fn spawn_background_retrainer(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                match self.maybe_retrain().await {
                    Ok(true) => info!("🤖 Background retrain completed"),
                    Ok(false) => {}
                    Err(e) => error!("Background retrain error: {}", e),
                }
            }
        });
    }
}

/// Summary statistics of the feedback journal.
#[derive(Debug, Clone, Serialize)]
pub struct FeedbackStats {
    pub total: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub uncertain: usize,
}

impl FeedbackStats {
    /// Estimated false positive rate based on recorded feedback.
    pub fn fp_rate(&self) -> f64 {
        let labeled = self.true_positives + self.false_positives;
        if labeled == 0 { return 0.0; }
        self.false_positives as f64 / labeled as f64
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn dummy_entry(label: FeedbackLabel) -> FeedbackEntry {
        FeedbackEntry {
            alert_id: uuid::Uuid::new_v4().to_string(),
            analyst_id: "analyst-1".into(),
            label,
            features: vec![0.1f32; 28],
            notes: Some("test note".into()),
            recorded_at: Utc::now().to_rfc3339(),
            original_score: 0.75,
        }
    }

    #[tokio::test]
    async fn test_record_and_count() {
        let dir = tempdir().unwrap();
        let learner = ContinuousLearner::open(
            &dir.path().join("feedback.db"),
            &dir.path().join("model.onnx"),
            dir.path(),
        ).unwrap();

        assert_eq!(learner.feedback_count().await.unwrap(), 0);

        learner.record_feedback(&dummy_entry(FeedbackLabel::TruePositive)).await.unwrap();
        learner.record_feedback(&dummy_entry(FeedbackLabel::FalsePositive)).await.unwrap();
        learner.record_feedback(&dummy_entry(FeedbackLabel::Uncertain)).await.unwrap();

        assert_eq!(learner.feedback_count().await.unwrap(), 3);
    }

    #[tokio::test]
    async fn test_stats() {
        let dir = tempdir().unwrap();
        let learner = ContinuousLearner::open(
            &dir.path().join("feedback.db"),
            &dir.path().join("model.onnx"),
            dir.path(),
        ).unwrap();

        for _ in 0..5 { learner.record_feedback(&dummy_entry(FeedbackLabel::TruePositive)).await.unwrap(); }
        for _ in 0..3 { learner.record_feedback(&dummy_entry(FeedbackLabel::FalsePositive)).await.unwrap(); }

        let stats = learner.stats().await.unwrap();
        assert_eq!(stats.true_positives, 5);
        assert_eq!(stats.false_positives, 3);
        assert!((stats.fp_rate() - 3.0/8.0).abs() < 1e-6);
    }

    #[tokio::test]
    async fn test_export_training_data() {
        let dir = tempdir().unwrap();
        let learner = ContinuousLearner::open(
            &dir.path().join("feedback.db"),
            &dir.path().join("model.onnx"),
            dir.path(),
        ).unwrap();

        for _ in 0..10 { learner.record_feedback(&dummy_entry(FeedbackLabel::TruePositive)).await.unwrap(); }
        for _ in 0..5 { learner.record_feedback(&dummy_entry(FeedbackLabel::FalsePositive)).await.unwrap(); }
        // Uncertain should NOT appear in export
        learner.record_feedback(&dummy_entry(FeedbackLabel::Uncertain)).await.unwrap();

        let csv_path = learner.export_training_data().await.unwrap();
        let content = std::fs::read_to_string(&csv_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        // 1 header + 15 data rows (10 TP + 5 FP, uncertain excluded)
        assert_eq!(lines.len(), 16, "Expected header + 15 data rows");
    }

    #[test]
    fn test_feedback_label_parsing() {
        assert_eq!(FeedbackLabel::from_str("tp"), Some(FeedbackLabel::TruePositive));
        assert_eq!(FeedbackLabel::from_str("FP"), Some(FeedbackLabel::FalsePositive));
        assert_eq!(FeedbackLabel::from_str("uncertain"), Some(FeedbackLabel::Uncertain));
        assert_eq!(FeedbackLabel::from_str("garbage"), None);
    }

    #[test]
    fn test_fp_rate_zero_when_no_data() {
        let stats = FeedbackStats { total: 0, true_positives: 0, false_positives: 0, uncertain: 0 };
        assert_eq!(stats.fp_rate(), 0.0);
    }
}
