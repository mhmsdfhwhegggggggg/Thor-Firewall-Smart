//! Detection engine — Sigma, YARA, IOC, and ML-based threat detection

pub mod sigma;
pub mod yara;
pub mod ioc_check;

use std::path::Path;
use std::sync::Arc;
use anyhow::Result;
use tracing::{info, warn};

use crate::events::{Alert, RuleType};
use crate::events::enrichment::EnrichedEvent;
use crate::ml::MlEngine;
use thor_common::ThreatLevel;

use sigma::SigmaEngine;
use yara::YaraEngine;
use ioc_check::IocChecker;

pub struct DetectionEngine {
    sigma: SigmaEngine,
    yara: YaraEngine,
    ioc_checker: IocChecker,
    ml: Arc<MlEngine>,
}

impl DetectionEngine {
    pub fn new(
        sigma_rules_dir: &Path,
        yara_rules_dir: &Path,
        ml: Arc<MlEngine>,
    ) -> Result<Self> {
        let sigma = SigmaEngine::load(sigma_rules_dir)
            .map_err(|e| { warn!("Sigma load error: {}", e); e })?;
        let yara = YaraEngine::load(yara_rules_dir)
            .map_err(|e| { warn!("YARA load error: {}", e); e })?;
        let ioc_checker = IocChecker::new();
        info!("🔍 Detection engine initialized");
        Ok(Self { sigma, yara, ioc_checker, ml })
    }

    pub async fn detect(&self, event: &EnrichedEvent) -> Result<Vec<Alert>> {
        let mut alerts = Vec::new();

        // 1. Sigma rule matching
        if let Some(mut alert) = self.sigma.check(event) {
            alerts.push(alert);
        }

        // 2. IOC check
        if let Some(alert) = self.ioc_checker.check(event) {
            alerts.push(alert);
        }

        // 3. YARA scan (CPU-heavy — spawn_blocking)
        let yara_alerts = tokio::task::spawn_blocking({
            let yara = self.yara.clone();
            let event_clone = event.clone();
            move || yara.scan(&event_clone)
        }).await.unwrap_or_default();
        alerts.extend(yara_alerts);

        // 4. ML anomaly detection
        if let Some(score) = self.ml.score(event).await {
            if score > 0.7 {
                alerts.push(Alert {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: chrono::Utc::now(),
                    source: event.hostname.clone().unwrap_or_default(),
                    rule_name: "ML:AnomalyScore".to_string(),
                    rule_type: RuleType::Ml,
                    threat_level: ThreatLevel::from_score(score),
                    description: format!("ML anomaly score: {:.3}", score),
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
    pub fn yara_rule_count(&self) -> usize { self.yara.rule_count() }
}
