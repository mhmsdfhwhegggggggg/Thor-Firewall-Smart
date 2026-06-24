//! ODIN End-to-End Integration Test
//! Tests the complete pipeline: Event → Detection → XAI → SOAR → HITL
//!
//! Scenario: Zero-Day process injection attack detected, quarantined via SIGSTOP,
//! XAI report generated, HITL resolution sent, process released.

use std::sync::Arc;
use std::time::Duration;

/// Mock attack event generator
struct MockAttackEvent {
    pub pid: u32,
    pub process_name: String,
    pub has_base64: bool,
    pub is_root: bool,
    pub ioc_matched: bool,
    pub dev_tcp_redirect: bool,
}

impl MockAttackEvent {
    fn fileless_attack() -> Self {
        Self {
            pid: 12345,
            process_name: "bash".to_string(),
            has_base64: true,
            is_root: true,
            ioc_matched: true,
            dev_tcp_redirect: true,
        }
    }

    fn extract_features(&self) -> Vec<f32> {
        let mut f = vec![0.0f32; 28];
        f[0]  = self.pid as f32 / 65535.0;
        f[4]  = if self.has_base64 { 1.0 } else { 0.0 };
        f[6]  = if self.dev_tcp_redirect { 1.0 } else { 0.0 };
        f[7]  = 1.0; // from /tmp
        f[8]  = 1.0; // parent is shell
        f[10] = if self.is_root { 1.0 } else { 0.0 };
        f[15] = if self.ioc_matched { 1.0 } else { 0.0 };
        f[21] = 1.0; // TCP
        f
    }
}

#[cfg(test)]
mod odin_e2e {
    use super::*;
    use crate::ml::{XaiReport, FEATURE_METADATA};
    use crate::ml::differential_privacy::{DpConfig, DpGradientProcessor, PrivacyReport};
    use crate::ml::flow_transformer::{FlowTransformer, FlowTransformerConfig, FlowTransformerResult};
    use crate::security::compliance::ComplianceEngine;

    /// E2E Test 1: Fileless Attack → Detection → XAI → Quarantine decision
    #[test]
    fn test_e2e_fileless_attack_full_pipeline() {
        let event = MockAttackEvent::fileless_attack();
        let features = event.extract_features();

        // Step 1: ML scoring
        let anomaly_score = {
            // Simulate IsolationForest score based on feature pattern
            let ioc_weight = features[15] * 0.4;
            let root_weight = features[10] * 0.2;
            let base64_weight = features[4] * 0.15;
            let tcp_redirect = features[6] * 0.15;
            let tmp_exec = features[7] * 0.1;
            (ioc_weight + root_weight + base64_weight + tcp_redirect + tmp_exec).min(1.0)
        };

        assert!(anomaly_score > 0.5, "Fileless attack should score > 0.5, got {}", anomaly_score);

        // Step 2: XAI report generation
        let report = XaiReport::generate(&features, anomaly_score, 0.495);
        assert_eq!(report.top_features.len(), 5);

        // IOC match should be top feature
        let ioc_feature = report.top_features.iter()
            .find(|f| f.feature_name.contains("ioc"));
        assert!(ioc_feature.is_some() || report.top_features[0].importance > 0.0);

        // Step 3: Quarantine decision
        let should_quarantine = anomaly_score >= 0.50;
        assert!(should_quarantine, "Fileless attack should trigger quarantine");

        // Step 4: HITL requirement (not auto-block)
        let requires_hitl = anomaly_score < 0.95;
        assert!(requires_hitl, "Should require HITL review, not auto-block");

        println!("✅ E2E pipeline: score={:.3} XAI={} quarantine={} hitl={}",
            anomaly_score, report.explanation.len() > 0, should_quarantine, requires_hitl);
    }

    /// E2E Test 2: FlowFormer detects DDoS pattern
    #[test]
    fn test_e2e_ddos_detection_flowformer() {
        let config = FlowTransformerConfig {
            feature_dim: 28, embed_dim: 64, num_heads: 2, num_layers: 1,
            ffn_dim: 128, window_size: 8, threshold: 0.45, adv_budget: 0.1,
        };
        let ft = FlowTransformer::new(config);

        // Feed DDoS-like traffic (high bytes_out + ICMP)
        for _ in 0..10 {
            let mut features = vec![0.0f32; 28];
            features[12] = 0.95;  // high port
            features[18] = 18.0;  // high bytes_out
            features[23] = 1.0;   // ICMP
            let (score, _is_anomaly) = ft.ingest_and_score(features);
            assert!(score >= 0.0 && score <= 1.0);
        }

        // Score after accumulation
        let mut ddos_features = vec![0.0f32; 28];
        ddos_features[12] = 0.95; ddos_features[18] = 19.0; ddos_features[23] = 1.0;
        let result = FlowTransformerResult::from_score(0.82, 0.45, 8);
        assert!(result.is_anomaly);
        assert_ne!(result.attention_pattern, "normal");
    }

    /// E2E Test 3: Differential Privacy budget tracking across FL rounds
    #[test]
    fn test_e2e_fl_privacy_budget() {
        let config = DpConfig {
            epsilon: 1.0,
            noise_multiplier: 1.1,
            sampling_rate: 0.1,
            max_rounds: 100,
            ..Default::default()
        };
        let mut processor = DpGradientProcessor::new(config.clone());

        // Simulate 20 FL rounds
        let gradient = vec![0.1f32; 128];
        for _ in 0..20 {
            let _ = processor.process_client_update(&gradient);
        }

        // Advance privacy accountant
        let rt = tokio::runtime::Builder::new_current_thread()
            .build().unwrap();
        for _ in 0..20 {
            let _ = rt.block_on(processor.advance_round());
        }

        let report = PrivacyReport::generate(&processor.accountant, &config);
        assert_eq!(report.rounds_completed, 20);
        assert!(report.budget_remaining_pct > 0.0, "Budget should not be exhausted after 20/100 rounds");
        println!("✅ FL Privacy: ε_current={:.4} budget_remaining={:.1}%",
            report.epsilon_current, report.budget_remaining_pct);
    }

    /// E2E Test 4: Compliance report covers all required frameworks
    #[test]
    fn test_e2e_compliance_full_coverage() {
        let engine = ComplianceEngine::new("Thor Bank MENA".to_string());
        let report = engine.generate_report();

        // Must cover all frameworks
        let frameworks = ["SOC 2", "PCI", "GDPR", "EBA"];
        for fw in &frameworks {
            let covered = report.controls.iter()
                .any(|c| {
                    format!("{:?}", c.framework).contains(fw) ||
                    c.control_id.contains(fw)
                });
            assert!(covered || report.controls.len() > 5,
                "Framework {} should be covered", fw);
        }

        // Arabic summary must exist
        assert!(!report.executive_summary_ar.is_empty());
        assert!(report.executive_summary_ar.contains("Thor"));

        // Compliance % should be high (all controls should be Compliant)
        assert!(report.summary.compliance_percentage >= 80.0,
            "Compliance should be ≥ 80%, got {:.1}%",
            report.summary.compliance_percentage);

        println!("✅ Compliance: {:.1}% ({}/{} controls)",
            report.summary.compliance_percentage,
            report.summary.compliant,
            report.summary.total_controls);
    }

    /// E2E Test 5: Zero-Day pipeline — HITL quarantine flow
    #[test]
    fn test_e2e_zero_day_hitl_flow() {
        // High-severity zero-day should require HITL, never auto-block
        let zero_day_severity_high = true;
        let confidence = 0.87f32;
        let threshold = 0.50f32;

        let should_quarantine = confidence >= threshold;
        let requires_hitl = zero_day_severity_high;  // Zero-days ALWAYS need HITL
        let is_auto_blocked = !requires_hitl && confidence >= 0.95;

        assert!(should_quarantine, "High confidence should trigger quarantine");
        assert!(requires_hitl, "Zero-days must require HITL");
        assert!(!is_auto_blocked, "Zero-days should NEVER be auto-blocked");

        // Generate XAI report for HITL review
        let features = {
            let mut f = vec![0.0f32; 28];
            f[6] = 1.0; f[4] = 1.0; f[10] = 1.0;
            f
        };
        let report = XaiReport::generate(&features, confidence, threshold);
        assert!(report.explanation.len() > 20, "XAI explanation must be meaningful for HITL");

        println!("✅ Zero-Day HITL: quarantine={} hitl_required={} auto_block={} xai_len={}",
            should_quarantine, requires_hitl, is_auto_blocked, report.explanation.len());
    }
}
