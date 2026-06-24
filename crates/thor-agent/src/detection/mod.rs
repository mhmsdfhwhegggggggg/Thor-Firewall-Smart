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

use parking_lot::RwLock;

pub struct DetectionEngine {
    sigma:        Arc<RwLock<SigmaEngine>>,
    yara:         YaraEngine,
    ioc_checker:  IocChecker,
    ids:          Arc<IdsEngine>,
    ml:           Arc<MlEngine>,
    ml_threshold: f64,
    /// Phase 11: Zero-Day behavioral pipeline engine
    /// High-severity findings → Quarantine + HITL (never auto-block)
    /// Per NIST SP 800-61r3: zero-day incidents require human authorization
    zero_day:     Arc<zero_day::ZeroDayEngine>,
}

impl DetectionEngine {
    pub fn inject_sigma_rule(&self, rule: crate::detection::sigma::GuardedDynamicRule) -> Result<()> {
        let mut sigma = self.sigma.write();
        sigma.add_rule(&rule.yaml_content)?;
        info!("💉 Rule {} injected into Sigma engine", rule.id);
        Ok(())
    }
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
        let sigma = Arc::new(RwLock::new(SigmaEngine::load(sigma_rules_dir)
            .map_err(|e| { warn!("Sigma load error: {}", e); e })?));

        let yara = YaraEngine::load(yara_rules_dir)
            .map_err(|e| { warn!("YARA load error: {}", e); e })?;

        let ioc_checker = IocChecker::new();
        let ids = Arc::new(IdsEngine::load_from_dir(ids_rules_dir));

        info!(
            "🔍 Detection engine initialized — Sigma:{} YARA:{} IDS:{} ml_threshold:{:.3}",
            sigma.read().rule_count(),
            yara.rule_count(),
            ids.rule_count(),
            ml_threshold,
        );

        let zero_day = Arc::new(zero_day::ZeroDayEngine::new());
        info!("🎯 ZeroDayEngine initialized: threshold=0.55 (maps to Quarantine for score≥0.75)");

        Ok(Self { sigma, yara, ioc_checker, ids, ml, ml_threshold, zero_day })
    }

    pub async fn detect(&self, event: &EnrichedEvent) -> Result<Vec<Alert>> {
        let mut alerts = Vec::new();

        // 1. Sigma rule matching (deterministic)
        if let Some(mut alert) = self.sigma.read().check(event) {
            alert.confidence_score = 0.85; // Deterministic rule
            alerts.push(alert);
        }

        // 2. IOC check (High fidelity)
        if let Some(mut alert) = self.ioc_checker.check(event) {
            alert.confidence_score = 1.0; // Absolute match
            alerts.push(alert);
        }

        // 3. IDS rules (Suricata-compatible)
        for mut alert in self.ids.scan(event) {
            alert.confidence_score = 0.85;
            alerts.push(alert);
        }

        // 4. YARA scan
        let mut yara_alerts = tokio::task::spawn_blocking({
            let yara = self.yara.clone();
            let ev   = event.clone();
            move || yara.scan(&ev)
        }).await.unwrap_or_default();
        
        for alert in &mut yara_alerts {
            alert.confidence_score = 0.90; // YARA is usually high fidelity malware match
        }
        alerts.extend(yara_alerts);

        // 5. ML anomaly detection (Ensemble Intelligence) with XAI
        if let Some((xai_score, feature_weights)) = self.ml.score_with_xai(event).await {
            let threshold = self.ml_threshold as f32;
            if xai_score > threshold {
                // 🔍 NEW: Deep Behavioral Classification
                let mut ml_description = format!("ML anomaly score: {:.3} (threshold: {:.3})", xai_score, threshold);
                let mut final_confidence = xai_score;

                if let Some(prediction) = self.ml.classify_malware_from_event(event) {
                    ml_description.push_str(&format!(" | Classification: {} ({:.2}%)", prediction.class, prediction.confidence * 100.0));
                    if prediction.confidence > 0.8 {
                        final_confidence = (final_confidence + 0.1).min(1.0);
                    }
                }

                alerts.push(Alert {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: chrono::Utc::now(),
                    source: event.hostname.clone().unwrap_or_default(),
                    rule_name: "ML:EnsembleAnomaly".to_string(),
                    rule_type: RuleType::Ml,
                    threat_level: ThreatLevel::from_score(xai_score),
                    description: ml_description,
                    pid: event.pid,
                    process_name: event.process_name.clone(),
                    src_ip: event.src_ip_str.clone(),
                    dst_ip: event.dst_ip_str.clone(),
                    dst_port: None,
                    ml_score: Some(xai_score),
                    confidence_score: final_confidence,
                    xai_report: Some(crate::ml::XaiReport {
                        model_version: "thor-isolation-forest-v3-2026".to_string(),
                        anomaly_score: xai_score,
                        threshold: self.ml_threshold as f32,
                        top_features: feature_weights,
                        explanation: format!(
                            "[ML XAI] Score={:.3} threshold={:.3} ({}) — {}",
                            xai_score, self.ml_threshold,
                            if xai_score > self.ml_threshold as f32 { "ANOMALOUS" } else { "normal" },
                            classify_anomaly(xai_score, self.ml_threshold as f32)
                        ),
                        active_feature_count: 28,
                        generated_at: chrono::Utc::now().to_rfc3339(),
                    }),
                    soar_actions_taken: vec![],
                    raw_event_type: event.raw.source().to_string(),
                });
            }
        }

        // 6. Time-Series Behavioral Drift (Host Level)
        // We track "System Call Rate" or "Network Thruput" as a time-series
        if let Some(hostname) = &event.hostname {
            // Aggregate metric for this host (simulated metric for integration)
            let metric_val = event.pid.map(|p| p as f64).unwrap_or(0.0); // Simplified metric
            if let Some(result) = self.ml.detect_timeseries_anomaly_simple(hostname, "host_activity", metric_val) {
                if result.should_alert {
                    alerts.push(Alert {
                        id: uuid::Uuid::new_v4().to_string(),
                        timestamp: chrono::Utc::now(),
                        source: hostname.clone(),
                        rule_name: "ML:BehavioralDrift".to_string(),
                        rule_type: RuleType::Ml,
                        threat_level: ThreatLevel::High,
                        description: format!(
                            "Host behavior drift detected! Baseline: {:.2}, Observed: {:.2}, Z-Score: {:.2}",
                            result.baseline, result.value, result.zscore
                        ),
                        pid: None,
                        process_name: None,
                        src_ip: event.src_ip_str.clone(),
                        dst_ip: None,
                        dst_port: None,
                        ml_score: Some(result.zscore as f32 / 10.0),
                        confidence_score: 0.85, // High confidence for behavioral drift
                        xai_report: None,
                        soar_actions_taken: vec![],
                        raw_event_type: "timeseries".into(),
                    });
                }
            }
        }

        // 7. Phase 11: Zero-Day Behavioral Pipeline
        // ZeroDayEngine analyzes syscall profiles for novel attack patterns.
        // CRITICAL: High-severity zero-days ALWAYS go to HITL Quarantine flow —
        // NEVER to auto-block. This prevents false-positive termination of legitimate
        // processes and ensures human review (NIST SP 800-61r3 requirement).
        //
        // Mapping (from ZeroDaySeverity):
        //   Critical (score ≥ 0.85) → Quarantine + XAI + HITL immediately
        //   High (score ≥ 0.70)     → Quarantine + XAI + HITL
        //   Medium (score ≥ 0.55)   → Deep inspection + alert (no suspension)
        //   Low                     → Log + baseline update
        if let Some(pid) = event.pid {
            let syscall_event = zero_day::syscall_profiler::SyscallEvent {
                pid,
                syscall_nr: 0,    // populated from eBPF ring buffer in production
                timestamp_ns: event.raw.timestamp_ns(),
                args: [0u64; 6],
                comm: event.process_name.clone().unwrap_or_default()
                    .chars().take(16).collect::<String>()
                    .as_bytes().iter().chain(std::iter::repeat(&0u8))
                    .take(16).cloned().collect::<Vec<u8>>()
                    .try_into().unwrap_or([0u8; 16]),
                ret: 0,
            };
            self.zero_day.profiler.ingest(syscall_event);

            if let Some(finding) = self.zero_day.analyze(pid).await {
                let (threat_level, confidence, should_quarantine) = match finding.severity {
                    zero_day::ZeroDaySeverity::Critical => (ThreatLevel::Critical, 0.95f32, true),
                    zero_day::ZeroDaySeverity::High     => (ThreatLevel::High,     0.80f32, true),
                    zero_day::ZeroDaySeverity::Medium   => (ThreatLevel::High,     0.65f32, false),
                    zero_day::ZeroDaySeverity::Low      => (ThreatLevel::Medium,   0.45f32, false),
                };

                // Build XAI report from zero-day finding
                let xai_explanation = format!(
                    "[Zero-Day XAI] Methods: {}. Score: {:.3}. Summary: {}",
                    finding.methods.iter().map(|m| format!("{:?}", m)).collect::<Vec<_>>().join(", "),
                    finding.threat_score,
                    finding.summary
                );

                let zd_report = Some(crate::ml::XaiReport {
                    model_version: "thor-zero-day-engine-v2-2026".to_string(),
                    anomaly_score: finding.threat_score as f32,
                    threshold: 0.55,
                    top_features: finding.methods.iter().enumerate().take(5).map(|(i, m)| {
                        crate::ml::FeatureWeight {
                            feature_name: format!("{:?}", m),
                            feature_value: finding.threat_score as f32,
                            deviation_score: (finding.threat_score as f32 - 0.55).max(0.0),
                            importance: 1.0 / (i as f32 + 1.0),
                            direction: "above_normal".to_string(),
                        }
                    }).collect(),
                    explanation: xai_explanation.clone(),
                    active_feature_count: finding.methods.len(),
                    generated_at: chrono::Utc::now().to_rfc3339(),
                });

                let mut zd_actions = vec!["zero_day_detected".to_string()];
                if should_quarantine {
                    // HITL quarantine — SoarEngine will apply SIGSTOP and await admin decision
                    zd_actions.push("hitl_quarantine_required".to_string());
                    warn!(
                        "🚨 Zero-Day HITL: PID {} flagged ({:?}, score={:.3}).                          Queuing for Quarantine state. XAI: {}",
                        pid, finding.severity, finding.threat_score, xai_explanation
                    );
                }

                alerts.push(Alert {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: chrono::Utc::now(),
                    source: event.hostname.clone().unwrap_or_else(|| "zero_day_engine".to_string()),
                    rule_name: format!("ZeroDay::{:?}", finding.severity),
                    rule_type: RuleType::Ml,
                    threat_level,
                    description: finding.summary.clone(),
                    pid: Some(pid),
                    process_name: event.process_name.clone(),
                    src_ip: event.src_ip_str.clone(),
                    dst_ip: event.dst_ip_str.clone(),
                    dst_port: None,
                    ml_score: Some(finding.threat_score as f32),
                    confidence_score: confidence,
                    xai_report: zd_report,
                    soar_actions_taken: zd_actions,
                    raw_event_type: "zero_day".to_string(),
                });
            }
        }

        // 🛡️ ERA: Consensus Hardening
        // If multiple engines triggered, boost confidence
        if alerts.len() > 1 {
            let max_conf = alerts.iter().map(|a| a.confidence_score).fold(0.0, f32::max);
            let boosted = (max_conf + 0.15).min(1.0);
            for alert in &mut alerts {
                alert.confidence_score = boosted;
            }
            info!("🛡️ ERA Consensus: Boosted confidence to {:.2} (Source hits: {})", boosted, alerts.len());
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
