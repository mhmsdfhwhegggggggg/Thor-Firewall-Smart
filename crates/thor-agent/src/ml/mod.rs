//! Thor ML Engine — ONNX-based UEBA + Anomaly Detection
//! Wraps ORT (ONNX Runtime) for real-time process/network scoring.
//! Falls back to a dummy always-zero scorer if model isn't loaded.

pub mod features;
pub mod gnn_detector;
pub mod ja4_analyzer;
pub mod l7_analyzer;
pub mod llm_reporter;
pub mod onnx_scorer;

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

use crate::events::enrichment::EnrichedEvent;
use crate::events::RawEvent;

use self::features::extract_features;
use self::onnx_scorer::OnnxScorer;

// ─── MlEngine ─────────────────────────────────────────────────────────────────

pub struct MlEngine {
    scorer: Option<Arc<OnnxScorer>>,
    loaded: bool,
}

impl MlEngine {
    pub fn new(model_path: &Path) -> Result<Self> {
        if !model_path.exists() {
            return Err(anyhow::anyhow!("Model not found: {:?}", model_path));
        }
        let scorer = OnnxScorer::load(model_path)?;
        info!("🤖 ML engine: ONNX model loaded from {:?}", model_path);
        Ok(Self { scorer: Some(Arc::new(scorer)), loaded: true })
    }

    /// Dummy scorer — always returns None (rule-only mode)
    pub fn dummy() -> Self {
        Self { scorer: None, loaded: false }
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Score an event for anomaly. Returns Some(0.0..1.0) or None if unavailable.
    pub async fn score(&self, event: &EnrichedEvent) -> Option<f32> {
        let scorer = self.scorer.as_ref()?;
        let features = extract_features(event);
        scorer.score(&features).ok()
    }
}
