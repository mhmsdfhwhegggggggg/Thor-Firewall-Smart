//! Detection Engine — unified threat detection:
//! Sigma (condition-aware), YARA, IOC, ML/ONNX, IDS (Suricata-compatible), FIM
//! Phase 3 Axis 1: Behavioral Sigma Sequence Detection (multi-stage attack chains)
//! Phase 4: Zero-Day Detection (behavioral anomaly + exploit primitive heuristics)
//!
//! v0.3.0 CRITICAL FIX:
//!   - ml_threshold is now configurable via ThorConfig (default 0.495).
//!   - Previously hardcoded at 0.70 → 0% detection rate with a correctly trained IF model.
//!   - DetectionEngine::new() now takes ml_threshold: f64 from config.

pub mod ioc_check;
pub mod sigma;
pub mod sigma_compiler;
pub mod yara;
pub mod zero_day;
/// Phase 3 Axis 1 — multi-stage behavioral sequence detection engine
pub mod sequence_detector;

pub use sequence_detector::{
    SequenceDetector, SequenceRule, SequenceStage, StagePredicate, EntityField,
};

use std::path::Path;
use std::sync::Arc;
use anyhow::Result;
use tracing::{info, warn};

use crate::events::{Alert, RuleType};
use crate::events::enrichment::EnrichedEvent;
use crate::ids::IdsEngine;
use crate::ml::MlEngine;
use thor_common::ThreatLevel;

use ioc_check::IocChecker;
use sigma::SigmaEngine;
use yara::YaraEngine;

pub struct DetectionEngine {
    sigma:        SigmaEngine,
    yara:         YaraEngine,
    ioc_checker:  IocChecker,
    ids:          Arc<IdsEngine>,
    ml:           Arc<MlEngine>,
    /// Configurable ML anomaly threshold.
    /// CRITICAL FIX (v0.3.0): was hardcoded to 0.70 → 0% detection.
    /// Default: 0.495 (from ThorConfig.ml_threshold / THOR_ML_THRESHOLD env var).
    /// Tune: lower → more sensitive; higher → fewer false positives.
    ml_threshold: f64,
}

impl DetectionEngine {
    /// Create the detection engine.
    ///
    /// # Arguments
    /// * `ml_threshold` — Anomaly score threshold from `ThorConfig.ml_threshold`.
    ///   **Do not hardcode this.** Always pass `config.ml_threshold`.
    pub fn new(
        sigma_rules_dir: &Path,
        yara_rules_dir:  &Path,
        ids_rules_dir:   &Path,
        ml:              Arc<MlEngine>,
        ml_threshold:    f64,
    ) -> Result<Self> {
        let sigma = SigmaEngine::load(sigma_rules_dir)
            .map_err(|e| { warn!("Sigma load error: {}", e); e })?;

        let yara = YaraEngine::load(yara_rules_dir)
            .map_err(|e| { warn!("YARA load error: {}", e); e })?;

        let ioc_checker = IocChecker::new();
        let ids = Arc::new(IdsEngine::load_from_dir(ids_rules_dir));

        info!(
            "🔍 Detection engine initialized — Sigma:{} YARA:{} IDS:{} ml_threshold:{:.3}",
            sigma.rule_count(),
            yara.rule_count(),
            ids.rule_count(),
            ml_threshold,
        );

        Ok(Self { sigma, yara, ioc_checker, ids, ml, ml_threshold })
    }

    pub async fn detect(&self, event: &EnrichedEvent) -> Result<Vec<Alert>> {
        let mut alerts = Vec::new();

        // 1. Sigma rule matching (full condition parser)
        if let Some(alert) = self.sigma.check(event) {
            alerts.push(alert);
        }

        // 2. IOC check (Bloom + DashMap)
        if let Some(alert) = self.ioc_checker.check(event) {
            alerts.push(alert);
        }

        // 3. IDS rules (Suricata-compatible)
        alerts.extend(self.ids.scan(event));

        // 4. YARA scan (CPU-heavy — run in spawn_blocking)
        let yara_alerts = tokio::task::spawn_blocking({
            let yara = self.yara.clone();
            let ev   = event.clone();
            move || yara.scan(&ev)
        }).await.unwrap_or_default();
        alerts.extend(yara_alerts);

        // 5. ML anomaly detection
        // CRITICAL FIX: use self.ml_threshold (configurable) not hardcoded 0.70
        if let Some(score) = self.ml.score(event).await {
            let threshold = self.ml_threshold as f32;
            if score > threshold {
                alerts.push(Alert {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: chrono::Utc::now(),
                    source: event.hostname.clone().unwrap_or_default(),
                    rule_name: "ML:AnomalyScore".to_string(),
                    rule_type: RuleType::Ml,
                    threat_level: ThreatLevel::from_score(score),
                    description: format!(
                        "ML anomaly score: {:.3} (threshold: {:.3}) — {}",
                        score, threshold, classify_anomaly(score, threshold)
                    ),
                    pid: None,
                    process_name: None,
                    src_ip: event.src_ip_str.clone(),
                    dst_ip: event.dst_ip_str.clone(),
                    dst_port: None,
                    ml_score: Some(score),
                    soar_actions_taken: vec![],
                    raw_event_type: event.raw.source().to_string(),
                });
            }
        }

        Ok(alerts)
    }

    pub fn sigma_rule_count(&self) -> usize { self.sigma.rule_count() }
    pub fn yara_rule_count(&self)  -> usize { self.yara.rule_count() }
    pub fn ids_rule_count(&self)   -> usize { self.ids.rule_count() }
    /// Expose the configured ML threshold (for metrics/health endpoint)
    pub fn ml_threshold(&self) -> f64 { self.ml_threshold }
}

/// Classify anomaly severity relative to the configured threshold.
/// Bands are relative to threshold so they work regardless of the configured value.
fn classify_anomaly(score: f32, threshold: f32) -> &'static str {
    let excess = score - threshold;
    if excess >= 0.45      { "Critical — likely active attack" }
    else if excess >= 0.30 { "High — highly suspicious behavior" }
    else if excess >= 0.15 { "Medium — anomalous activity" }
    else                   { "Low — marginal anomaly" }
}

#[cfg(test)]
mod tests {
    use super::classify_anomaly;

    #[test]
    fn classify_is_relative_to_threshold() {
        // With threshold=0.495, score=0.95 → excess=0.455 → Critical
        assert_eq!(classify_anomaly(0.95, 0.495), "Critical — likely active attack");
        // score just above threshold → Low
        assert_eq!(classify_anomaly(0.50, 0.495), "Low — marginal anomaly");
    }
}
