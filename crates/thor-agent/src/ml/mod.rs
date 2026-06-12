//! ML Engine — ONNX Runtime inference for UEBA anomaly detection
//! Uses IsolationForest exported to ONNX format via skl2onnx
//! <1ms CPU inference, no GPU required

pub mod features;

use anyhow::{Context, Result};
use ndarray::{Array1, Array2};
use ort::{Environment, Session, SessionBuilder, Value};
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

use crate::events::enrichment::EnrichedEvent;
use crate::events::RawEvent;
use features::FeatureExtractor;

pub const FEATURE_DIMENSION: usize = 32;

pub struct MlEngine {
    session: Option<Arc<Session>>,
    extractor: FeatureExtractor,
}

impl MlEngine {
    pub fn new(model_path: &Path) -> Result<Self> {
        if !model_path.exists() {
            return Err(anyhow::anyhow!("ONNX model not found: {:?}", model_path));
        }

        let environment = Environment::builder()
            .with_name("thor-ueba")
            .with_log_level(ort::LoggingLevel::Warning)
            .build()
            .context("Failed to create ORT environment")?;

        let session = SessionBuilder::new(&Arc::new(environment))
            .context("SessionBuilder failed")?
            .with_intra_threads(1)
            .context("set_intra_threads failed")?
            .with_model_from_file(model_path)
            .context("Failed to load ONNX model")?;

        info!("🤖 ONNX model loaded: {:?} (FEATURE_DIM={})", model_path, FEATURE_DIMENSION);
        Ok(Self { session: Some(Arc::new(session)), extractor: FeatureExtractor::new() })
    }

    /// Dummy engine for when model file is absent
    pub fn dummy() -> Self {
        warn!("⚠️  ML engine in dummy mode — no ONNX model");
        Self { session: None, extractor: FeatureExtractor::new() }
    }

    /// Score an event — returns anomaly probability [0.0, 1.0]
    /// Returns None if no model loaded
    pub async fn score(&self, event: &EnrichedEvent) -> Option<f32> {
        let session = self.session.as_ref()?;
        let features = self.extractor.extract(event)?;
        let session = session.clone();

        tokio::task::spawn_blocking(move || {
            let input = Array2::from_shape_vec(
                (1, FEATURE_DIMENSION),
                features.to_vec(),
            ).ok()?;

            let ort_input = Value::from_array(session.allocator(), &input).ok()?;
            let outputs = session.run(vec![ort_input]).ok()?;

            // IsolationForest output: [label, score] — score is in outputs[1]
            // Negative scores = anomaly, positive = normal
            // Normalize to [0, 1] anomaly probability
            let scores: &ort::tensor::OrtOwnedTensor<f32, _> = outputs[1].try_extract().ok()?;
            let raw_score = scores.view()[[0, 0]];
            // Convert IF score: more negative = more anomalous
            let normalized = 1.0_f32 - ((raw_score + 0.5_f32).max(0.0).min(1.0));
            Some(normalized)
        }).await.ok().flatten()
    }
}
