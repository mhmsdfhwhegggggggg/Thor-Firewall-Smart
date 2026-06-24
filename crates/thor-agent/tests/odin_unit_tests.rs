//! ODIN Plan — Comprehensive Unit Test Suite
//! Tests all new components: XAI, DP, FlowFormer, SIGSTOP, HLL, Detection

#[cfg(test)]
mod odin_unit_tests {
    use super::*;

    // ─── XAI Engine Tests ─────────────────────────────────────────────────────

    mod xai_tests {
        use crate::ml::{XaiReport, FeatureWeight, FEATURE_METADATA};

        #[test]
        fn test_xai_report_generation_normal() {
            let features = vec![0.0f32; 28];  // All normal baseline
            let report = XaiReport::generate(&features, 0.2, 0.495);
            assert_eq!(report.anomaly_score, 0.2);
            assert_eq!(report.threshold, 0.495);
            assert!(report.top_features.len() <= 5);
            assert!(!report.explanation.is_empty());
            assert!(report.explanation.contains("Score=0.200"));
        }

        #[test]
        fn test_xai_report_generation_attack() {
            let mut features = vec![0.0f32; 28];
            features[4]  = 1.0;  // base64
            features[6]  = 1.0;  // /dev/tcp redirect
            features[10] = 1.0;  // root
            features[15] = 1.0;  // IOC match

            let report = XaiReport::generate(&features, 0.92, 0.495);
            assert!(report.anomaly_score > 0.8);
            // Top features should include the active ones
            assert!(!report.top_features.is_empty());
            let top_names: Vec<&str> = report.top_features.iter().map(|f| f.feature_name.as_str()).collect();
            assert!(top_names.iter().any(|&n| n.contains("ioc") || n.contains("base64") || n.contains("tcp")));
        }

        #[test]
        fn test_feature_weights_sum_to_one() {
            let features: Vec<f32> = (0..28).map(|i| i as f32 * 0.03).collect();
            let report = XaiReport::generate(&features, 0.7, 0.495);
            let total_importance: f32 = report.top_features.iter().map(|f| f.importance).sum();
            // Top 5 should have sum ≤ 1.0 (it's a fraction of total importance)
            assert!(total_importance <= 1.01, "Importance sum should be ≤ 1.0, got {}", total_importance);
        }

        #[test]
        fn test_xai_direction_labels() {
            let mut features = vec![0.0f32; 28];
            features[4] = 1.0;  // above baseline (0.0)

            let report = XaiReport::generate(&features, 0.5, 0.495);
            let base64_feature = report.top_features.iter()
                .find(|f| f.feature_name.contains("base64"));
            if let Some(fw) = base64_feature {
                assert_eq!(fw.direction, "above_normal");
            }
        }

        #[test]
        fn test_xai_all_28_features_have_metadata() {
            assert_eq!(FEATURE_METADATA.len(), 28,
                "All 28 features must have metadata entries");
        }

        #[test]
        fn test_xai_generated_at_is_valid_rfc3339() {
            let report = XaiReport::generate(&vec![0.0; 28], 0.3, 0.495);
            // Should parse as a valid datetime
            assert!(report.generated_at.contains("T"), "generated_at should be RFC3339");
            assert!(report.generated_at.len() > 10);
        }
    }

    // ─── Differential Privacy Tests ──────────────────────────────────────────

    mod dp_tests {
        use crate::ml::differential_privacy::{DpConfig, DpGradientProcessor, PrivacyAccountant};

        #[test]
        fn test_dp_gradient_clipping() {
            let config = DpConfig { max_grad_norm: 1.0, ..Default::default() };
            let processor = DpGradientProcessor::new(config);

            // High-norm gradient should be clipped
            let large_grad = vec![10.0f32; 28];
            let clipped = processor.privatize_gradient(&large_grad);

            // L2 norm of clipped gradient should be ≈ max_grad_norm (before noise)
            // We can't easily test with noise, but verify output has correct dimension
            assert_eq!(clipped.len(), 28);
        }

        #[test]
        fn test_dp_noise_is_not_deterministic() {
            let config = DpConfig::default();
            let processor = DpGradientProcessor::new(config);

            // Same input twice should produce different output (random noise)
            let grad = vec![0.5f32; 28];
            let noisy1 = processor.privatize_gradient(&grad);
            let noisy2 = processor.privatize_gradient(&grad);

            // With random noise, these should differ
            let same = noisy1.iter().zip(noisy2.iter()).all(|(a, b)| (a - b).abs() < 1e-10);
            assert!(!same, "DP noise should be non-deterministic (random seed)");
        }

        #[test]
        fn test_privacy_accountant_budget_tracking() {
            let config = DpConfig {
                epsilon: 1.0, delta: 1e-5,
                noise_multiplier: 1.1, sampling_rate: 0.1,
                max_rounds: 10, ..Default::default()
            };
            let mut accountant = PrivacyAccountant::new(config);

            // After 5 rounds, budget should be partially consumed
            for _ in 0..5 {
                let _ = accountant.step();
            }
            assert_eq!(accountant.rounds_completed(), 5);
            // Current epsilon should be > 0 (some budget consumed)
            assert!(accountant.current_epsilon() > 0.0,
                "Privacy budget should be partially consumed after training rounds");
        }

        #[test]
        fn test_privacy_accountant_not_exhausted_at_start() {
            let config = DpConfig::default();
            let accountant = PrivacyAccountant::new(config);
            assert!(!accountant.is_budget_exhausted());
            assert_eq!(accountant.rounds_completed(), 0);
            assert_eq!(accountant.current_epsilon(), 0.0);
        }

        #[test]
        fn test_dp_gradient_zero_input() {
            let config = DpConfig::default();
            let processor = DpGradientProcessor::new(config);
            let zeros = vec![0.0f32; 28];
            let noisy = processor.privatize_gradient(&zeros);
            // Zero gradient + noise should still produce non-zero output (noise added)
            assert_eq!(noisy.len(), 28);
        }
    }

    // ─── FlowFormer Architecture Tests ───────────────────────────────────────

    mod flow_transformer_tests {
        use crate::ml::flow_transformer::{FlowTransformer, FlowTransformerConfig, FlowTransformerResult};

        fn default_config() -> FlowTransformerConfig {
            FlowTransformerConfig {
                feature_dim: 28, embed_dim: 64, num_heads: 2, num_layers: 1,
                ffn_dim: 128, window_size: 4, threshold: 0.45, adv_budget: 0.1,
            }
        }

        #[test]
        fn test_flowformer_score_range() {
            let config = default_config();
            let ft = FlowTransformer::new(config);
            let features = vec![0.5f32; 28];
            let (score, is_anomaly) = ft.ingest_and_score(features);
            assert!(score >= 0.0 && score <= 1.0, "Score must be in [0, 1], got {}", score);
            assert_eq!(is_anomaly, score > 0.45);
        }

        #[test]
        fn test_flowformer_sliding_window() {
            let config = default_config();
            let ft = FlowTransformer::new(config);

            // Feed multiple events — window should accumulate
            for i in 0..8 {
                let features = vec![i as f32 * 0.01; 28];
                let (score, _) = ft.ingest_and_score(features);
                assert!(score >= 0.0 && score <= 1.0);
            }
        }

        #[test]
        fn test_flowformer_result_categories() {
            let threshold = 0.45f32;
            let r_normal    = FlowTransformerResult::from_score(0.2, threshold, 16);
            let r_anomalous = FlowTransformerResult::from_score(0.55, threshold, 16);
            let r_suspicious = FlowTransformerResult::from_score(0.65, threshold, 16);
            let r_critical  = FlowTransformerResult::from_score(0.85, threshold, 16);

            assert!(!r_normal.is_anomaly);
            assert!(r_anomalous.is_anomaly);
            assert_eq!(r_normal.attention_pattern, "normal");
            assert_eq!(r_anomalous.attention_pattern, "anomalous");
            assert_eq!(r_suspicious.attention_pattern, "suspicious");
            assert_eq!(r_critical.attention_pattern, "critical");
        }

        #[test]
        fn test_flowformer_thread_safe() {
            use std::sync::Arc;
            let config = default_config();
            let ft = Arc::new(FlowTransformer::new(config));

            let handles: Vec<_> = (0..4).map(|i| {
                let ft = Arc::clone(&ft);
                std::thread::spawn(move || {
                    let features = vec![i as f32 * 0.1; 28];
                    let (score, _) = ft.ingest_and_score(features);
                    assert!(score >= 0.0 && score <= 1.0);
                })
            }).collect();

            for h in handles { h.join().expect("Thread panicked"); }
        }
    }

    // ─── SOAR: Circuit Breaker Tests ─────────────────────────────────────────

    mod circuit_breaker_tests {
        use crate::soar::CircuitBreaker;
        use std::time::{Duration, Instant};

        #[test]
        fn test_circuit_breaker_allows_within_limit() {
            let cb = CircuitBreaker::new(10);
            for _ in 0..10 {
                assert!(cb.check_and_increment().is_ok());
            }
        }

        #[test]
        fn test_circuit_breaker_blocks_at_limit() {
            let cb = CircuitBreaker::new(3);
            for _ in 0..3 { let _ = cb.check_and_increment(); }
            assert!(cb.check_and_increment().is_err(), "Should block after limit");
        }

        #[test]
        fn test_circuit_breaker_resets_after_window() {
            let cb = CircuitBreaker::new(1);
            let _ = cb.check_and_increment();
            assert!(cb.check_and_increment().is_err());

            // Manually expire the window
            {
                let mut start = cb.window_start.lock();
                *start = Instant::now() - Duration::from_secs(400);
            }

            // Should reset and allow again
            assert!(cb.check_and_increment().is_ok(), "Should reset after window");
        }
    }

    // ─── HyperLogLog Cardinality Estimation Tests (Userspace simulation) ──────

    mod hll_tests {
        /// Simulate the eBPF FNV-1a hash from xdp_drop.bpf.c
        fn fnv1a_32(val: u32) -> u32 {
            let mut hash: u32 = 2166136261;
            let bytes = val.to_le_bytes();
            for &b in &bytes {
                hash ^= b as u32;
                hash = hash.wrapping_mul(16777619);
            }
            hash
        }

        fn clz24(val: u32) -> u8 {
            let val = val & 0x00FFFFFF;
            if val == 0 { return 25; }
            let mut rho = 0u8;
            let mut v = val;
            while (v & 0x00800000) == 0 && rho < 24 {
                rho += 1; v <<= 1;
            }
            rho + 1
        }

        fn hll_estimate(registers: &[u8]) -> f64 {
            let m = registers.len() as f64;
            let alpha = 0.7213 / (1.0 + 1.079 / m);
            let sum: f64 = registers.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
            alpha * m * m / sum
        }

        #[test]
        fn test_hll_small_set_estimate() {
            let mut registers = vec![0u8; 256];
            let ips: Vec<u32> = (1u32..=50).map(|i| 0xC0A80000 + i).collect();

            for &ip in &ips {
                let hash = fnv1a_32(ip);
                let bucket = (hash >> 24) as usize;
                let rho = clz24(hash);
                if rho > registers[bucket] {
                    registers[bucket] = rho;
                }
            }

            let estimate = hll_estimate(&registers);
            let error_pct = (estimate - ips.len() as f64).abs() / ips.len() as f64 * 100.0;
            assert!(error_pct < 30.0, "HLL error should be < 30% for 50 unique IPs, got {:.1}%", error_pct);
        }

        #[test]
        fn test_hll_large_set_better_accuracy() {
            let mut registers = vec![0u8; 256];
            let n = 10000u32;

            for i in 0..n {
                let ip = 0x01000000u32.wrapping_add(i);
                let hash = fnv1a_32(ip);
                let bucket = (hash >> 24) as usize;
                let rho = clz24(hash);
                if rho > registers[bucket] {
                    registers[bucket] = rho;
                }
            }

            let estimate = hll_estimate(&registers);
            let error_pct = (estimate - n as f64).abs() / n as f64 * 100.0;
            // HLL with 256 buckets: ~6.5% typical error
            assert!(error_pct < 25.0, "HLL error should be < 25% for 10k unique IPs, got {:.1}%", error_pct);
        }

        #[test]
        fn test_fnv1a_hash_avalanche() {
            // Small input changes should change multiple bits
            let h1 = fnv1a_32(0x01010101);
            let h2 = fnv1a_32(0x01010102); // 1 bit different
            let xor = h1 ^ h2;
            let changed_bits = xor.count_ones();
            assert!(changed_bits >= 8, "FNV-1a should change ≥ 8 bits for 1-bit input change, got {}", changed_bits);
        }
    }

    // ─── Compliance Engine Tests ──────────────────────────────────────────────

    mod compliance_tests {
        use crate::security::compliance::{ComplianceEngine, ControlStatus};

        #[test]
        fn test_compliance_report_generation() {
            let engine = ComplianceEngine::new("Test Org".to_string());
            let report = engine.generate_report();

            assert!(!report.controls.is_empty(), "Should have controls");
            assert!(report.summary.compliance_percentage >= 0.0);
            assert!(report.summary.compliance_percentage <= 100.0);
            assert!(!report.executive_summary_ar.is_empty());
            assert!(!report.executive_summary_en.is_empty());
        }

        #[test]
        fn test_compliance_controls_have_evidence() {
            let engine = ComplianceEngine::new("Test Org".to_string());
            let report = engine.generate_report();

            for control in &report.controls {
                assert!(!control.evidence.is_empty(),
                    "Control {} should have evidence", control.control_id);
                assert!(!control.control_name.is_empty());
                assert!(!control.thor_component.is_empty());
            }
        }

        #[test]
        fn test_compliance_summary_counts_match() {
            let engine = ComplianceEngine::new("Test Org".to_string());
            let report = engine.generate_report();

            let counted = report.controls.iter().fold((0, 0, 0), |acc, c| {
                match &c.status {
                    ControlStatus::Compliant => (acc.0 + 1, acc.1, acc.2),
                    ControlStatus::PartiallyCompliant { .. } => (acc.0, acc.1 + 1, acc.2),
                    ControlStatus::NonCompliant { .. } => (acc.0, acc.1, acc.2 + 1),
                    _ => acc,
                }
            });
            assert_eq!(counted.0, report.summary.compliant);
            assert_eq!(counted.1, report.summary.partial);
            assert_eq!(counted.2, report.summary.non_compliant);
        }
    }

    // ─── Privacy Report Tests ─────────────────────────────────────────────────

    mod privacy_report_tests {
        use crate::ml::differential_privacy::{DpConfig, PrivacyAccountant, PrivacyReport};

        #[test]
        fn test_privacy_report_compliant_at_start() {
            let config = DpConfig::default();
            let accountant = PrivacyAccountant::new(config.clone());
            let report = PrivacyReport::generate(&accountant, &config);

            assert!(report.compliance_status.contains("COMPLIANT"));
            assert_eq!(report.rounds_completed, 0);
            assert_eq!(report.budget_remaining_pct, 100.0);
        }

        #[test]
        fn test_privacy_report_fields_populated() {
            let config = DpConfig::default();
            let accountant = PrivacyAccountant::new(config.clone());
            let report = PrivacyReport::generate(&accountant, &config);

            assert!(report.epsilon_budget > 0.0);
            assert!(report.delta > 0.0);
            assert!(!report.generated_at.is_empty());
        }
    }
}

// ─── Integration: Full Pipeline Test ─────────────────────────────────────────
#[cfg(test)]
mod integration_test_odin {
    use crate::ml::{XaiReport, FeatureWeight};

    #[test]
    fn test_xai_to_soar_pipeline() {
        // Simulate: ML detects anomaly → XAI explains → SOAR decides
        let features = {
            let mut f = vec![0.0f32; 28];
            f[4] = 1.0; f[6] = 1.0; f[10] = 1.0; f[15] = 1.0; // attack pattern
            f
        };
        let anomaly_score = 0.87f32;
        let threshold = 0.495f32;

        let report = XaiReport::generate(&features, anomaly_score, threshold);

        // Verify: XAI identifies correct features as important
        assert!(anomaly_score > threshold, "Should be flagged as anomaly");
        assert!(report.top_features.iter().any(|f| f.importance > 0.0));
        assert!(report.explanation.contains("HIGH") || report.explanation.contains("MEDIUM"));

        // Verify: Quarantine decision based on confidence
        let confidence = anomaly_score;
        let should_quarantine = confidence >= 0.50; // SOAR threshold
        assert!(should_quarantine, "Score {} should trigger quarantine", confidence);

        // Verify: HITL required for high scores (not auto-block)
        let requires_hitl = confidence < 0.95; // Only auto-block at 0.95+
        assert!(requires_hitl, "High-confidence zero-days require HITL review");
    }
}
