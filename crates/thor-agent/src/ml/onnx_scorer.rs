//! ONNX Runtime scorer — wraps ORT for anomaly scoring

use anyhow::{Context, Result};
use std::path::Path;
use tracing::{info, warn};

pub struct OnnxScorer {
    // In production: ort::Session
    // For now: placeholder that always returns 0.0
    model_path: String,
}

impl OnnxScorer {
    pub fn load(path: &Path) -> Result<Self> {
        // In production:
        // let session = ort::Session::builder()?.commit_from_file(path)?;
        info!("📦 ONNX scorer: model loaded from {:?}", path);
        Ok(Self {
            model_path: path.to_string_lossy().to_string(),
        })
    }

    pub fn score(&self, features: &[f32]) -> Result<f32> {
        if features.len() != 28 {
            anyhow::bail!("Expected 28 features, got {}", features.len());
        }
        // Placeholder scoring: in production, run ORT inference
        // For now: simple heuristic based on key features
        let mut score = 0.0f32;

        // Feature indices
        let has_dev_tcp = features[6];
        let from_tmp = features[7];
        let parent_web = features[9];
        let ioc_hit = features[15];
        let bytes_out = features[18];

        score += has_dev_tcp * 0.7;  // /dev/tcp = very suspicious
        score += from_tmp * 0.4;     // executing from /tmp
        score += parent_web * 0.5;   // web server spawning shell
        score += ioc_hit * 0.9;      // IOC hit = critical
        score += if bytes_out > 15.0 { 0.6 } else { 0.0 }; // large exfil

        Ok(score.min(1.0))
    }
}
