//! Axis 4 — Zero-Day Detection Engine
//!
//! This module provides the complete zero-day and exploit primitive detection
//! capability for Thor Firewall Smart.  It operates entirely in user-space
//! using eBPF telemetry fed from the kernel-side `syscall_profiler.bpf.c`
//! probe and in-memory statistical analysis.
//!
//! # Architecture
//!
//! ```text
//!  ┌─────────────────────────────────────────────────────────┐
//!  │                   ZeroDayEngine                         │
//!  │  ┌─────────────────┐  ┌─────────────────┐              │
//!  │  │ SyscallProfiler  │  │  AnomalyEngine   │             │
//!  │  │ (per-PID baseline│  │ (Isolation Forest│             │
//!  │  │  from eBPF ring  │  │  over feature    │             │
//!  │  │  buffer events)  │  │  vectors)        │             │
//!  │  └────────┬────────┘  └────────┬─────────┘             │
//!  │           │                    │                         │
//!  │  ┌────────▼────────────────────▼────────────────────┐  │
//!  │  │          ExploitPrimitiveDetector                 │  │
//!  │  │  ROP Chain · UAF Patterns · Heap Spray · ASLR    │  │
//!  │  └───────────────────────────────────────────────────┘  │
//!  └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Modules
//! * `syscall_profiler` — eBPF event consumer, builds per-process behavioral
//!                        baseline using sliding-window histograms.
//! * `anomaly_engine`   — Isolation Forest anomaly scoring on feature vectors.
//! * `exploit_primitives` — Heuristic detection of ROP chains, UAF, and heap spray.
//! * `behavioral_baseline` — Stores and computes KL-divergence drift from baseline.

pub mod syscall_profiler;
pub mod anomaly_engine;
pub mod exploit_primitives;
pub mod behavioral_baseline;
pub mod kernel_exploit;
pub mod process_hollowing;
pub mod network_covert;

use std::sync::Arc;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

pub use syscall_profiler::{SyscallEvent, SyscallProfiler, ProcessProfile};
pub use anomaly_engine::{AnomalyEngine, FeatureVector, AnomalyScore};
pub use exploit_primitives::{ExploitPrimitiveDetector, ExploitAlert, ExploitType};
pub use behavioral_baseline::{BehavioralBaseline, BaselineDrift};
pub use kernel_exploit::{KernelExploitDetector, KernelExploitAlert, KernelExploitType};
pub use process_hollowing::{ProcessHollowingDetector, HollowingAlert, HollowingType};
pub use network_covert::{NetworkCovertDetector, CovertChannelAlert, CovertChannelType};

// ─── Zero-Day Alert ───────────────────────────────────────────────────────────

/// Severity level for zero-day alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ZeroDaySeverity {
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
}

impl ZeroDaySeverity {
    pub fn from_score(score: f64) -> Self {
        if score >= 0.90      { ZeroDaySeverity::Critical }
        else if score >= 0.75 { ZeroDaySeverity::High }
        else if score >= 0.55 { ZeroDaySeverity::Medium }
        else                  { ZeroDaySeverity::Low }
    }
}

impl std::fmt::Display for ZeroDaySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZeroDaySeverity::Low      => write!(f, "LOW"),
            ZeroDaySeverity::Medium   => write!(f, "MEDIUM"),
            ZeroDaySeverity::High     => write!(f, "HIGH"),
            ZeroDaySeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A zero-day detection alert — unified output from all detection engines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroDayAlert {
    /// Unique alert identifier (UUIDv4).
    pub id: String,
    /// UTC timestamp of detection.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Process ID under analysis.
    pub pid: u32,
    /// Process name (from /proc/<pid>/comm).
    pub process_name: String,
    /// Detection method that triggered this alert.
    pub detection_method: DetectionMethod,
    /// Anomaly score — 0.0 (normal) to 1.0 (extremely anomalous).
    pub anomaly_score: f64,
    /// Alert severity derived from anomaly_score.
    pub severity: ZeroDaySeverity,
    /// Human-readable description of the detected behavior.
    pub description: String,
    /// MITRE ATT&CK technique IDs.
    pub mitre_techniques: Vec<String>,
    /// Feature vector snapshot at time of detection.
    pub features: Option<FeatureVector>,
    /// Exploit primitive type (if applicable).
    pub exploit_type: Option<ExploitType>,
}

/// Which detection engine produced the alert.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DetectionMethod {
    /// Isolation Forest ML anomaly on syscall behavioral profile.
    BehavioralAnomaly,
    /// ROP chain / UAF / heap spray heuristic.
    ExploitPrimitive,
    /// Significant KL-divergence drift from established baseline.
    BaselineDrift,
    /// Combined signal from multiple engines.
    Combined,
}

impl std::fmt::Display for DetectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionMethod::BehavioralAnomaly => write!(f, "BehavioralAnomaly"),
            DetectionMethod::ExploitPrimitive  => write!(f, "ExploitPrimitive"),
            DetectionMethod::BaselineDrift     => write!(f, "BaselineDrift"),
            DetectionMethod::Combined          => write!(f, "Combined"),
        }
    }
}

// ─── Zero-Day Engine ──────────────────────────────────────────────────────────

/// The unified zero-day detection engine.
///
/// Coordinates `SyscallProfiler`, `AnomalyEngine`, `ExploitPrimitiveDetector`,
/// and `BehavioralBaseline` into a single evaluation pipeline.
pub struct ZeroDayEngine {
    pub profiler:   Arc<SyscallProfiler>,
    pub anomaly:    Arc<AnomalyEngine>,
    pub primitives: Arc<ExploitPrimitiveDetector>,
    pub baseline:   Arc<BehavioralBaseline>,
    /// Minimum anomaly score to emit an alert (default: 0.55).
    pub threshold:  f64,
}

impl ZeroDayEngine {
    /// Create a new engine with default parameters.
    pub fn new() -> Self {
        Self {
            profiler:   Arc::new(SyscallProfiler::new()),
            anomaly:    Arc::new(AnomalyEngine::new(100)),   // 100 trees
            primitives: Arc::new(ExploitPrimitiveDetector::new()),
            baseline:   Arc::new(BehavioralBaseline::new()),
            threshold:  0.55,
        }
    }

    /// Ingest a new syscall event and run the full detection pipeline.
    ///
    /// Returns a list of zero-day alerts (may be empty for normal behaviour).
    pub fn ingest(&self, event: &SyscallEvent) -> Vec<ZeroDayAlert> {
        let mut alerts = Vec::new();

        // 1. Update the per-process behavioral profile
        self.profiler.record(event);

        // 2. Retrieve the current process profile
        let profile = match self.profiler.get_profile(event.pid) {
            Some(p) => p,
            None    => return alerts,
        };

        // Skip scoring until we have enough events to establish a baseline
        if profile.event_count < 50 {
            return alerts;
        }

        // 3. Build feature vector from profile
        let features = FeatureVector::from_profile(&profile);

        // 4. Isolation Forest anomaly score
        let score: AnomalyScore = self.anomaly.score(&features);

        if score.value >= self.threshold {
            alerts.push(ZeroDayAlert {
                id:               uuid::Uuid::new_v4().to_string(),
                timestamp:        chrono::Utc::now(),
                pid:              event.pid,
                process_name:     profile.process_name.clone(),
                detection_method: DetectionMethod::BehavioralAnomaly,
                anomaly_score:    score.value,
                severity:         ZeroDaySeverity::from_score(score.value),
                description:      format!(
                    "Behavioral anomaly detected for PID {} ({}): isolation score {:.3} — {}",
                    event.pid, profile.process_name, score.value,
                    describe_anomaly(&features, &score)
                ),
                mitre_techniques: vec!["T1055".into(), "T1203".into()],
                features:         Some(features.clone()),
                exploit_type:     None,
            });
        }

        // 5. KL-divergence baseline drift check
        if let Some(drift) = self.baseline.compute_drift(event.pid, &features) {
            if drift.kl_divergence > 1.5 {
                let drift_score = (drift.kl_divergence / 5.0).min(1.0);
                alerts.push(ZeroDayAlert {
                    id:               uuid::Uuid::new_v4().to_string(),
                    timestamp:        chrono::Utc::now(),
                    pid:              event.pid,
                    process_name:     profile.process_name.clone(),
                    detection_method: DetectionMethod::BaselineDrift,
                    anomaly_score:    drift_score,
                    severity:         ZeroDaySeverity::from_score(drift_score),
                    description:      format!(
                        "Behavioral baseline drift for PID {} ({}): KL-div={:.3} (threshold: 1.5)",
                        event.pid, profile.process_name, drift.kl_divergence
                    ),
                    mitre_techniques: vec!["T1055".into()],
                    features:         Some(features.clone()),
                    exploit_type:     None,
                });
            }
        }

        // 6. Update baseline after the drift check
        self.baseline.update(event.pid, &features);

        // 7. Exploit primitive detection
        let exploit_alerts = self.primitives.analyze(event, &profile);
        for ea in exploit_alerts {
            let ex_score = ea.confidence;
            alerts.push(ZeroDayAlert {
                id:               uuid::Uuid::new_v4().to_string(),
                timestamp:        chrono::Utc::now(),
                pid:              event.pid,
                process_name:     profile.process_name.clone(),
                detection_method: DetectionMethod::ExploitPrimitive,
                anomaly_score:    ex_score,
                severity:         ZeroDaySeverity::from_score(ex_score),
                description:      ea.description.clone(),
                mitre_techniques: ea.mitre_techniques.clone(),
                features:         Some(features.clone()),
                exploit_type:     Some(ea.exploit_type.clone()),
            });
        }

        if !alerts.is_empty() {
            info!(
                "🚨 Zero-Day: {} alert(s) for PID {} ({})",
                alerts.len(), event.pid, profile.process_name
            );
        }

        alerts
    }

    /// Retrieve all current per-process profiles (for API exposure).
    pub fn all_profiles(&self) -> Vec<ProcessProfile> {
        self.profiler.all_profiles()
    }

    /// Retrieve current baseline drift stats for all tracked processes.
    pub fn all_drift_stats(&self) -> Vec<(u32, f64)> {
        self.baseline.all_drift_stats()
    }
}

impl Default for ZeroDayEngine {
    fn default() -> Self { Self::new() }
}

fn describe_anomaly(features: &FeatureVector, score: &AnomalyScore) -> String {
    let mut signals = Vec::new();
    if features.syscall_rate > 500.0    { signals.push(format!("high syscall rate ({:.0}/s)", features.syscall_rate)); }
    if features.unique_syscalls > 80.0  { signals.push(format!("diverse syscalls ({:.0} unique)", features.unique_syscalls)); }
    if features.memory_alloc_rate > 5.0 { signals.push(format!("aggressive memory alloc ({:.1}x/s)", features.memory_alloc_rate)); }
    if features.child_spawn_rate > 2.0  { signals.push(format!("child spawning ({:.1}/s)", features.child_spawn_rate)); }
    if features.write_entropy > 0.8     { signals.push(format!("high-entropy writes ({:.2})", features.write_entropy)); }
    if features.network_bytes > 1e6     { signals.push(format!("network traffic ({:.0} bytes)", features.network_bytes)); }
    if signals.is_empty() {
        format!("composite anomaly (score: {:.3})", score.value)
    } else {
        signals.join("; ")
    }
}
