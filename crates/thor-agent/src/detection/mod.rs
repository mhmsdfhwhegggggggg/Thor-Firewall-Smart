//! Detection Engine — unified threat detection:
//! Sigma (condition-aware), YARA, IOC, ML/ONNX, IDS (Suricata-compatible), FIM
//! Axis 4 Zero-Day Detection (behavioral anomaly + exploit primitive heuristics)

pub mod ioc_check;
pub mod sigma;
pub mod sigma_compiler;
pub mod yara;
pub mod zero_day;

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
    sigma:       SigmaEngine,
    yara:        YaraEngine,
    ioc_checker: IocChecker,
    ids:         Arc<IdsEngine>,
    ml:          Arc<MlEngine>,
}

impl DetectionEngine {
    pub fn new(
        sigma_rules_dir: &Path,
        yara_rules_dir:  &Path,
        ids_rules_dir:   &Path,
        ml:              Arc<MlEngine>,
    ) -> Result<Self> {
        let sigma = SigmaEngine::load(sigma_rules_dir)
            .map_err(|e| { warn!("Sigma load error: {}", e); e })?;

        let yara = YaraEngine::load(yara_rules_dir)
            .map_err(|e| { warn!("YARA load error: {}", e); e })?;

        let ioc_checker = IocChecker::new();
        let ids = Arc::new(IdsEngine::load_from_dir(ids_rules_dir));

        info!(
            "🔍 Detection engine initialized — Sigma:{} YARA:{} IDS:{}",
            sigma.rule_count(),
            yara.rule_count(),
            ids.rule_count(),
        );

        Ok(Self { sigma, yara, ioc_checker, ids, ml })
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
        if let Some(score) = self.ml.score(event).await {
            if score > 0.70 {
                alerts.push(Alert {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: chrono::Utc::now(),
                    source: event.hostname.clone().unwrap_or_default(),
                    rule_name: "ML:AnomalyScore".to_string(),
                    rule_type: RuleType::Ml,
                    threat_level: ThreatLevel::from_score(score),
                    description: format!(
                        "ML anomaly score: {:.3} (threshold: 0.70) — {}",
                        score, classify_anomaly(score)
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
}

fn classify_anomaly(score: f32) -> &'static str {
    if score >= 0.95      { "Likely attack in progress" }
    else if score >= 0.85 { "Highly suspicious behavior" }
    else if score >= 0.70 { "Anomalous activity" }
    else                  { "Low anomaly" }
}
