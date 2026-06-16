//! Time-Series Anomaly Detection Model
//!
//! Implements an ONNX-backed LSTM Autoencoder that learns normal network/process
//! behaviour over a rolling window and flags sequences with reconstruction error
//! above a learned threshold as anomalous.
//!
//! Architecture: Encoder LSTM (128 units) → bottleneck (32) → Decoder LSTM (128)
//! Training data: per-host aggregated telemetry at 1-minute resolution.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Number of time-steps in one input window.
pub const WINDOW_SIZE: usize = 60;   // 60 minutes of 1-min aggregations

/// Number of features measured per time-step.
pub const STEP_FEATURES: usize = 24;

/// Anomaly threshold: reconstruction error above this → anomaly.
/// Calibrated at training time as `mean + 3 * std` on validation data.
pub const DEFAULT_THRESHOLD: f32 = 0.08;

// ─── Per-step feature vector ──────────────────────────────────────────────────

/// Aggregated per-host metrics collected over one minute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeStep {
    pub timestamp_unix:       u64,   // Unix epoch (second)
    // Network metrics
    pub bytes_out_mb:         f32,
    pub bytes_in_mb:          f32,
    pub conn_count:           u32,
    pub unique_dst_ips:       u32,
    pub unique_dst_ports:     u32,
    pub dns_query_count:      u32,
    pub tls_handshake_count:  u32,
    // Process metrics
    pub process_create_count: u32,
    pub child_proc_count:     u32,
    pub cpu_pct:              f32,
    pub mem_rss_mb:           f32,
    // File system metrics
    pub file_create_count:    u32,
    pub file_delete_count:    u32,
    pub file_write_mb:        f32,
    // Auth / access
    pub login_success_count:  u32,
    pub login_fail_count:     u32,
    pub sudo_count:           u32,
    // Alerts generated in this window
    pub alert_count_low:      u32,
    pub alert_count_med:      u32,
    pub alert_count_high:     u32,
    pub alert_count_crit:     u32,
    // Derived
    pub entropy_score:        f32,   // Normalised connection-destination entropy
    pub dga_score:            f32,   // Fraction of DNS queries flagged as DGA
}

impl TimeStep {
    /// Convert to a flat `[f32; STEP_FEATURES]` vector (normalised 0–1).
    pub fn to_features(&self) -> [f32; STEP_FEATURES] {
        [
            self.bytes_out_mb.ln_1p() / 20.0,
            self.bytes_in_mb.ln_1p() / 20.0,
            (self.conn_count as f32).ln_1p() / 10.0,
            (self.unique_dst_ips as f32).ln_1p() / 8.0,
            (self.unique_dst_ports as f32) / 65535.0,
            (self.dns_query_count as f32).ln_1p() / 7.0,
            (self.tls_handshake_count as f32).ln_1p() / 7.0,
            (self.process_create_count as f32).ln_1p() / 6.0,
            (self.child_proc_count as f32).ln_1p() / 5.0,
            self.cpu_pct / 100.0,
            self.mem_rss_mb.ln_1p() / 14.0,
            (self.file_create_count as f32).ln_1p() / 6.0,
            (self.file_delete_count as f32).ln_1p() / 5.0,
            self.file_write_mb.ln_1p() / 10.0,
            (self.login_success_count as f32).ln_1p() / 4.0,
            (self.login_fail_count as f32).ln_1p() / 4.0,
            (self.sudo_count as f32).ln_1p() / 3.0,
            (self.alert_count_low as f32).ln_1p() / 4.0,
            (self.alert_count_med as f32).ln_1p() / 3.0,
            (self.alert_count_high as f32).ln_1p() / 3.0,
            (self.alert_count_crit as f32).ln_1p() / 2.0,
            self.entropy_score.clamp(0.0, 1.0),
            self.dga_score.clamp(0.0, 1.0),
            0.0, // reserved
        ]
    }
}

// ─── Anomaly detection output ─────────────────────────────────────────────────

/// Result of running anomaly detection on a window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResult {
    /// Mean squared reconstruction error across the window.
    pub reconstruction_error: f32,
    /// Whether the error exceeds the configured threshold.
    pub is_anomalous:         bool,
    /// Normalised anomaly score: `error / threshold` (> 1.0 → anomalous).
    pub anomaly_score:        f32,
    /// Which time-steps contributed most to the error (top-5 indices).
    pub hot_steps:            Vec<usize>,
    /// Which features drove the anomaly (top-5 feature indices).
    pub hot_features:         Vec<usize>,
}

impl AnomalyResult {
    pub fn severity(&self) -> &'static str {
        match self.anomaly_score {
            s if s < 1.0  => "normal",
            s if s < 1.5  => "low",
            s if s < 2.5  => "medium",
            s if s < 4.0  => "high",
            _             => "critical",
        }
    }
}

// ─── Sliding-window buffer ────────────────────────────────────────────────────

/// Maintains a rolling FIFO of `WINDOW_SIZE` time-steps per host.
pub struct WindowBuffer {
    host_id:   String,
    window:    VecDeque<TimeStep>,
    capacity:  usize,
}

impl WindowBuffer {
    pub fn new(host_id: impl Into<String>) -> Self {
        Self {
            host_id: host_id.into(),
            window: VecDeque::with_capacity(WINDOW_SIZE + 1),
            capacity: WINDOW_SIZE,
        }
    }

    /// Append a time-step; returns `true` when the window is full and ready
    /// for inference.
    pub fn push(&mut self, step: TimeStep) -> bool {
        if self.window.len() == self.capacity {
            self.window.pop_front();
        }
        self.window.push_back(step);
        self.window.len() == self.capacity
    }

    pub fn is_ready(&self) -> bool {
        self.window.len() == self.capacity
    }

    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    /// Export the window as a flat `Vec<f32>` of shape `[WINDOW_SIZE, STEP_FEATURES]`.
    pub fn to_flat(&self) -> Vec<f32> {
        let mut flat = Vec::with_capacity(WINDOW_SIZE * STEP_FEATURES);
        for step in &self.window {
            flat.extend_from_slice(&step.to_features());
        }
        flat
    }
}

// ─── LSTM Autoencoder detector ────────────────────────────────────────────────

/// LSTM Autoencoder-based time-series anomaly detector.
pub struct TimeseriesAnomalyDetector {
    model_path: std::path::PathBuf,
    threshold:  f32,
    #[cfg(feature = "onnx")]
    session:    Arc<ort::Session>,
}

impl TimeseriesAnomalyDetector {
    /// Load the ONNX model from disk.
    ///
    /// If the model file does not exist, the detector operates in
    /// **statistical baseline mode** (z-score on feature means).
    pub fn load(path: impl AsRef<Path>, threshold: Option<f32>) -> Result<Self> {
        let model_path = path.as_ref().to_path_buf();
        let threshold  = threshold.unwrap_or(DEFAULT_THRESHOLD);

        if !model_path.exists() {
            warn!(
                path = %model_path.display(),
                "Time-series anomaly ONNX model not found — using statistical baseline"
            );
        } else {
            info!(
                path = %model_path.display(),
                threshold,
                "Loading time-series anomaly detector"
            );
        }

        #[cfg(feature = "onnx")]
        if model_path.exists() {
            let session = ort::Session::builder()
                .context("ONNX session builder failed")?
                .with_intra_threads(1)
                .context("Failed to set intra-op threads")?
                .commit_from_file(&model_path)
                .context("Failed to load time-series ONNX model")?;
            return Ok(Self { model_path, threshold, session: Arc::new(session) });
        }

        Ok(Self {
            model_path,
            threshold,
            #[cfg(feature = "onnx")]
            session: {
                return Err(anyhow::anyhow!("ONNX model missing"));
            },
        })
    }

    /// Run anomaly detection on a ready `WindowBuffer`.
    pub fn detect(&self, buf: &WindowBuffer) -> Result<AnomalyResult> {
        anyhow::ensure!(buf.is_ready(), "Window buffer not full yet");
        let flat = buf.to_flat();

        #[cfg(feature = "onnx")]
        if self.model_path.exists() {
            return self.onnx_detect(&flat);
        }

        self.statistical_detect(&flat)
    }

    /// ONNX LSTM Autoencoder inference.
    #[cfg(feature = "onnx")]
    fn onnx_detect(&self, flat: &[f32]) -> Result<AnomalyResult> {
        use ort::inputs;
        use ndarray::Array3;

        let input = Array3::from_shape_vec((1, WINDOW_SIZE, STEP_FEATURES), flat.to_vec())
            .context("Failed to shape ONNX input tensor")?;

        let outputs = self.session
            .run(inputs!["input" => input.view()]
                .context("Failed to prepare ONNX inputs")?)
            .context("ONNX time-series inference failed")?;

        // Output: reconstructed sequence [1, WINDOW_SIZE, STEP_FEATURES]
        let recon = outputs[0]
            .try_extract_tensor::<f32>()
            .context("Failed to extract ONNX output")?;
        let recon_slice = recon.as_slice().context("Reconstruction tensor not contiguous")?;

        self.compute_anomaly_result(flat, recon_slice)
    }

    /// Statistical fallback: z-score on feature column means vs. rolling baseline.
    fn statistical_detect(&self, flat: &[f32]) -> Result<AnomalyResult> {
        // Compute per-feature mean across the window
        let mut feat_means = [0.0f32; STEP_FEATURES];
        for t in 0..WINDOW_SIZE {
            for f in 0..STEP_FEATURES {
                feat_means[f] += flat[t * STEP_FEATURES + f];
            }
        }
        for m in &mut feat_means { *m /= WINDOW_SIZE as f32; }

        // Compute variance, then z-score for last step vs. mean
        let last_step_offset = (WINDOW_SIZE - 1) * STEP_FEATURES;
        let mut step_errors = [0.0f32; STEP_FEATURES];
        for f in 0..STEP_FEATURES {
            let last = flat[last_step_offset + f];
            step_errors[f] = (last - feat_means[f]).powi(2);
        }
        let mse: f32 = step_errors.iter().sum::<f32>() / STEP_FEATURES as f32;

        // Build per-step scalar error (MSE vs. column mean)
        let mut step_mse = vec![0.0f32; WINDOW_SIZE];
        for t in 0..WINDOW_SIZE {
            let mut s = 0.0f32;
            for f in 0..STEP_FEATURES {
                let v = flat[t * STEP_FEATURES + f];
                s += (v - feat_means[f]).powi(2);
            }
            step_mse[t] = s / STEP_FEATURES as f32;
        }

        // Top-5 hot time-steps
        let mut hot_steps_idx: Vec<usize> = (0..WINDOW_SIZE).collect();
        hot_steps_idx.sort_unstable_by(|&a, &b| step_mse[b].partial_cmp(&step_mse[a]).unwrap());
        let hot_steps = hot_steps_idx[..5.min(WINDOW_SIZE)].to_vec();

        // Top-5 hot features (from last step)
        let mut feat_idx: Vec<usize> = (0..STEP_FEATURES).collect();
        feat_idx.sort_unstable_by(|&a, &b| step_errors[b].partial_cmp(&step_errors[a]).unwrap());
        let hot_features = feat_idx[..5.min(STEP_FEATURES)].to_vec();

        let anomaly_score = mse / self.threshold.max(1e-9);

        debug!(mse, anomaly_score, threshold = self.threshold, "Statistical anomaly check");

        Ok(AnomalyResult {
            reconstruction_error: mse,
            is_anomalous: mse > self.threshold,
            anomaly_score,
            hot_steps,
            hot_features,
        })
    }

    /// Compute anomaly metrics from original and reconstructed tensors.
    fn compute_anomaly_result(&self, original: &[f32], reconstructed: &[f32]) -> Result<AnomalyResult> {
        let len = original.len().min(reconstructed.len());
        let mut step_mse = vec![0.0f32; WINDOW_SIZE];

        for t in 0..WINDOW_SIZE {
            let mut s = 0.0f32;
            for f in 0..STEP_FEATURES {
                let idx = t * STEP_FEATURES + f;
                if idx < len {
                    s += (original[idx] - reconstructed[idx]).powi(2);
                }
            }
            step_mse[t] = s / STEP_FEATURES as f32;
        }

        let mse: f32 = step_mse.iter().sum::<f32>() / WINDOW_SIZE as f32;

        let mut hot_steps_idx: Vec<usize> = (0..WINDOW_SIZE).collect();
        hot_steps_idx.sort_unstable_by(|&a, &b| step_mse[b].partial_cmp(&step_mse[a]).unwrap());
        let hot_steps = hot_steps_idx[..5.min(WINDOW_SIZE)].to_vec();

        let mut feat_err = vec![0.0f32; STEP_FEATURES];
        for f in 0..STEP_FEATURES {
            for t in 0..WINDOW_SIZE {
                let idx = t * STEP_FEATURES + f;
                if idx < len {
                    feat_err[f] += (original[idx] - reconstructed[idx]).powi(2);
                }
            }
            feat_err[f] /= WINDOW_SIZE as f32;
        }
        let mut feat_idx: Vec<usize> = (0..STEP_FEATURES).collect();
        feat_idx.sort_unstable_by(|&a, &b| feat_err[b].partial_cmp(&feat_err[a]).unwrap());
        let hot_features = feat_idx[..5.min(STEP_FEATURES)].to_vec();

        let anomaly_score = mse / self.threshold.max(1e-9);
        Ok(AnomalyResult {
            reconstruction_error: mse,
            is_anomalous: mse > self.threshold,
            anomaly_score,
            hot_steps,
            hot_features,
        })
    }
}
