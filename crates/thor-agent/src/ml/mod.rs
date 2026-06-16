//! Thor ML Engine — ONNX-based UEBA + Anomaly Detection
//! Wraps ORT (ONNX Runtime) for real-time process/network scoring.
//! Falls back to a dummy always-zero scorer if model isn't loaded.

pub mod features;
pub mod gnn_detector;
pub mod ja4_analyzer;
pub mod l7_analyzer;
pub mod llm_reporter;
pub mod malware_classifier;
pub mod onnx_scorer;
pub mod timeseries_anomaly;

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

use crate::events::enrichment::EnrichedEvent;
use crate::events::RawEvent;

use self::features::extract_features;
use self::onnx_scorer::OnnxScorer;
pub use self::malware_classifier::{
    MalwareClassifier, MalwareFeatures, MalwarePrediction,
    CLASS_COUNT, CLASS_LABELS, FEATURE_DIM,
};
pub use self::timeseries_anomaly::{
    AnomalyResult, TimeseriesAnomalyDetector, TimeStep, WindowBuffer,
    DEFAULT_THRESHOLD, STEP_FEATURES, WINDOW_SIZE,
};

// ─── MlEngine ─────────────────────────────────────────────────────────────────

pub struct MlEngine {
    scorer:              Option<Arc<OnnxScorer>>,
    malware_classifier:  Option<Arc<MalwareClassifier>>,
    timeseries_detector: Option<Arc<TimeseriesAnomalyDetector>>,
    loaded:              bool,
}

impl MlEngine {
    pub fn new(model_path: &Path) -> Result<Self> {
        if !model_path.exists() {
            return Err(anyhow::anyhow!("Model not found: {:?}", model_path));
        }
        let scorer = OnnxScorer::load(model_path)?;
        info!("🤖 ML engine: ONNX model loaded from {:?}", model_path);
        Ok(Self {
            scorer: Some(Arc::new(scorer)),
            malware_classifier: None,
            timeseries_detector: None,
            loaded: true,
        })
    }

    /// Load all three models (UEBA + Malware Classifier + Time-Series Anomaly).
    /// Missing model files degrade gracefully to heuristic mode.
    pub fn new_full(
        ueba_model:     &Path,
        malware_model:  &Path,
        timeseries_model: &Path,
    ) -> Result<Self> {
        // UEBA / Isolation Forest
        let scorer = if ueba_model.exists() {
            match OnnxScorer::load(ueba_model) {
                Ok(s) => {
                    info!("🤖 UEBA model loaded: {:?}", ueba_model);
                    Some(Arc::new(s))
                }
                Err(e) => {
                    warn!("UEBA model load failed: {e}");
                    None
                }
            }
        } else {
            warn!("UEBA model not found: {:?}", ueba_model);
            None
        };

        // Malware Classifier
        let malware_classifier = match MalwareClassifier::load(malware_model) {
            Ok(clf) => {
                info!("🧬 Malware classifier loaded: {:?}", malware_model);
                Some(Arc::new(clf))
            }
            Err(e) => {
                warn!("Malware classifier load failed: {e} — using heuristics");
                // Load in heuristic mode (file missing is graceful)
                MalwareClassifier::load("/nonexistent/model.onnx").ok().map(Arc::new)
            }
        };

        // Time-Series Anomaly Detector
        let timeseries_detector = match TimeseriesAnomalyDetector::load(timeseries_model, None) {
            Ok(det) => {
                info!("📈 Time-series anomaly detector loaded: {:?}", timeseries_model);
                Some(Arc::new(det))
            }
            Err(e) => {
                warn!("Time-series detector load failed: {e} — using statistical baseline");
                None
            }
        };

        let loaded = scorer.is_some();
        Ok(Self { scorer, malware_classifier, timeseries_detector, loaded })
    }

    /// Dummy scorer — always returns None (rule-only mode)
    pub fn dummy() -> Self {
        Self {
            scorer: None,
            malware_classifier: None,
            timeseries_detector: None,
            loaded: false,
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Score an event for UEBA anomaly. Returns Some(0.0..1.0) or None if unavailable.
    pub async fn score(&self, event: &EnrichedEvent) -> Option<f32> {
        let scorer = self.scorer.as_ref()?;
        let features = extract_features(event);
        scorer.score(&features).ok()
    }

    /// Classify a process/file sample as a malware family.
    /// Returns None when the classifier is not loaded.
    pub fn classify_malware(&self, features: &MalwareFeatures) -> Option<MalwarePrediction> {
        let clf = self.malware_classifier.as_ref()?;
        match clf.predict(features) {
            Ok(pred) => Some(pred),
            Err(e) => {
                warn!("Malware classifier inference failed: {e}");
                None
            }
        }
    }

    /// Detect time-series anomalies in a host's behaviour window.
    /// Returns None when the detector is not loaded or the buffer is not full.
    pub fn detect_timeseries_anomaly(&self, buf: &WindowBuffer) -> Option<AnomalyResult> {
        let det = self.timeseries_detector.as_ref()?;
        if !buf.is_ready() {
            return None;
        }
        match det.detect(buf) {
            Ok(result) => Some(result),
            Err(e) => {
                warn!("Time-series detector inference failed: {e}");
                None
            }
        }
    }
}
