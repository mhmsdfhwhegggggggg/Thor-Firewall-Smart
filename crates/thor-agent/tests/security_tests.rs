//! Security integration tests for Thor Firewall Smart
//! Run with: cargo test --package thor-agent

#[cfg(test)]
mod auth_tests {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use thor_agent::api::auth_middleware::{generate_token, Claims, ThorRole};

    fn set_test_secret() {
        std::env::set_var("THOR_JWT_SECRET", "test_secret_for_unit_tests_only_64_chars_long_aaaaaaa");
        std::env::set_var("THOR_JWT_EXPIRY_HOURS", "1");
    }

    #[test]
    fn test_token_generation_admin() {
        set_test_secret();
        let token = generate_token("test_admin", ThorRole::Admin);
        assert!(token.is_ok(), "Token generation should succeed");
    }

    #[test]
    fn test_token_contains_correct_role() {
        set_test_secret();
        let token = generate_token("test_user", ThorRole::Analyst).unwrap();
        let secret = std::env::var("THOR_JWT_SECRET").unwrap();
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        let data = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        );
        assert!(data.is_ok());
        assert_eq!(data.unwrap().claims.role, ThorRole::Analyst);
    }

    #[test]
    fn test_rbac_admin_meets_analyst() {
        assert!(ThorRole::Admin.meets(&ThorRole::Analyst));
        assert!(ThorRole::Admin.meets(&ThorRole::Readonly));
        assert!(ThorRole::Admin.meets(&ThorRole::Admin));
    }

    #[test]
    fn test_rbac_analyst_cannot_meet_admin() {
        assert!(!ThorRole::Analyst.meets(&ThorRole::Admin));
        assert!(ThorRole::Analyst.meets(&ThorRole::Readonly));
        assert!(ThorRole::Analyst.meets(&ThorRole::Analyst));
    }

    #[test]
    fn test_rbac_readonly_minimal() {
        assert!(!ThorRole::Readonly.meets(&ThorRole::Admin));
        assert!(!ThorRole::Readonly.meets(&ThorRole::Analyst));
        assert!(ThorRole::Readonly.meets(&ThorRole::Readonly));
    }
}

#[cfg(test)]
mod audit_tests {
    use std::fs;

    use thor_agent::audit::{AuditAction, AuditLogger, AuditResult};

    fn temp_db() -> String {
        format!("/tmp/thor_test_audit_{}", uuid::Uuid::new_v4())
    }

    #[test]
    fn test_audit_log_creates_entries() {
        let path = temp_db();
        let logger = AuditLogger::open(&path).unwrap();

        logger.log(
            "admin", "Admin", AuditAction::Login,
            "login", AuditResult::Success, "127.0.0.1", "test",
        );
        logger.log(
            "analyst1", "Analyst", AuditAction::ApiAccess,
            "/api/v1/stats", AuditResult::Success, "10.0.1.5", "",
        );

        let entries = logger.recent(10);
        assert_eq!(entries.len(), 2);
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn test_audit_chain_integrity_after_writes() {
        let path = temp_db();
        let logger = AuditLogger::open(&path).unwrap();

        for i in 0..10 {
            logger.log(
                &format!("user{}", i), "Analyst", AuditAction::ApiAccess,
                "/api/v1/stats", AuditResult::Success, "10.0.0.1", "",
            );
        }

        assert!(logger.verify_chain(), "Chain must be intact after sequential writes");
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn test_audit_entries_ordered_most_recent_first() {
        let path = temp_db();
        let logger = AuditLogger::open(&path).unwrap();

        logger.log("u1", "Admin", AuditAction::Login,       "x", AuditResult::Success, "1.2.3.4", "");
        logger.log("u2", "Admin", AuditAction::LoginFailed, "x", AuditResult::Failure, "1.2.3.4", "");

        let entries = logger.recent(10);
        // Most recent (LoginFailed) should be first
        assert!(matches!(entries[0].action, AuditAction::LoginFailed));
        let _ = fs::remove_dir_all(&path);
    }
}

#[cfg(test)]
mod sigma_tests {
    use thor_agent::detection::sigma::SigmaEngine;
    use std::path::Path;

    #[test]
    fn test_empty_engine_loads_without_panic() {
        let engine = SigmaEngine::empty();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn test_empty_engine_evaluate_returns_empty() {
        let engine = SigmaEngine::empty();
        let matches = engine.evaluate("some malicious payload cmd.exe /c whoami");
        assert!(matches.is_empty());
    }

    #[tokio::test]
    async fn test_inject_dynamic_rule_enters_shadow_mode() {
        let engine = SigmaEngine::empty();
        let yaml = r#"
title: Test Rule
id: test-001
detection:
  keywords:
    - malware.exe
  condition: keywords
level: high
"#;
        let result = engine.ingest_llm_rule(
            "test-001".to_string(),
            yaml.to_string(),
            "Test Rule".to_string(),
        ).await;

        assert!(result.is_ok(), "Valid rule should be accepted");

        // Rule must be in pending (shadow mode), NOT in dynamic_rules (enforce)
        assert!(engine.dynamic_rules.is_empty(), "Shadow rules must not be in dynamic_rules");
        assert!(engine.guardian.pending_approval.contains_key("test-001"),
                "Rule should be in pending approval queue");
    }

    #[tokio::test]
    async fn test_broad_rule_rejected_by_guardian() {
        let engine = SigmaEngine::empty();
        let broad_yaml = r#"
title: Block Everything
detection:
  keywords:
    - any
  condition: keywords
level: critical
"#;
        let result = engine.ingest_llm_rule(
            "broad-001".to_string(),
            broad_yaml.to_string(),
            "Block Everything".to_string(),
        ).await;

        assert!(result.is_err(), "Overly broad rule must be rejected");
    }

    #[tokio::test]
    async fn test_rule_enforced_only_after_human_approval() {
        let engine = SigmaEngine::empty();
        let yaml = r#"
title: Specific Rule
id: specific-001
detection:
  keywords:
    - c2beacon.exe
  condition: keywords
level: high
"#;
        engine.ingest_llm_rule("specific-001".to_string(), yaml.to_string(), "Specific Rule".to_string())
            .await.unwrap();

        // Before approval — should NOT match (shadow mode)
        let matches_before = engine.evaluate("c2beacon.exe running");
        assert!(matches_before.is_empty(), "Shadow rule must not trigger enforcement");

        // Approve rule
        engine.guardian.human_approve_rule("specific-001", &engine.dynamic_rules).await.unwrap();

        // After approval — should match
        let matches_after = engine.evaluate("c2beacon.exe running");
        assert!(!matches_after.is_empty(), "Approved rule must trigger on match");
    }
}

#[cfg(test)]
mod siem_tests {
    use thor_agent::siem::{alert_to_cef, alert_to_leef};
    use thor_agent::events::{Alert, RuleType};
    use thor_common::ThreatLevel;
    use chrono::Utc;

    fn mock_alert() -> Alert {
        Alert {
            id: "test-alert-001".into(),
            timestamp: Utc::now(),
            source: "srv-prod-01".into(),
            rule_name: "C2 Beacon|Detected".into(),
            rule_type: RuleType::Sigma,
            threat_level: ThreatLevel::Critical,
            description: "Outbound C2 beacon\ndetected".into(),
            pid: Some(4242),
            process_name: Some("svchost.exe".into()),
            src_ip: Some("10.0.1.50".into()),
            dst_ip: Some("185.220.101.1".into()),
            dst_port: Some(443),
            ml_score: Some(0.97),
            soar_actions_taken: vec!["network_isolated:pid=4242".into()],
            raw_event_type: "network".into(),
        }
    }

    #[test]
    fn test_cef_output_single_line() {
        let cef = alert_to_cef(&mock_alert());
        assert!(!cef.contains('\n'), "CEF must be a single line");
        assert!(!cef.contains('\r'));
    }

    #[test]
    fn test_cef_header_format() {
        let cef = alert_to_cef(&mock_alert());
        let parts: Vec<&str> = cef.splitn(8, '|').collect();
        assert_eq!(parts[0], "CEF:0");
        assert_eq!(parts[1], "ThorSecurity");
        assert_eq!(parts[2], "ThorFirewallSmart");
    }

    #[test]
    fn test_cef_pipe_in_rule_name_escaped() {
        let cef = alert_to_cef(&mock_alert());
        assert!(cef.contains("C2 Beacon\\|Detected"));
    }

    #[test]
    fn test_leef_output_single_line() {
        let leef = alert_to_leef(&mock_alert());
        assert!(!leef.contains('\n'));
        assert!(leef.starts_with("LEEF:2.0|"));
    }

    #[test]
    fn test_cef_critical_severity_is_10() {
        let cef = alert_to_cef(&mock_alert());
        // Severity field is 7th pipe-separated field
        let parts: Vec<&str> = cef.splitn(8, '|').collect();
        assert_eq!(parts[6], "10");
    }
}

#[cfg(test)]
mod rate_limit_tests {
    use thor_agent::api::rate_limit::RateLimiter;
    use std::time::Duration;

    #[test]
    fn test_rate_limit_allows_within_limit() {
        let limiter = RateLimiter::new(5, Duration::from_secs(60), "test");
        for _ in 0..5 {
            assert!(limiter.check("192.168.1.1"), "Should allow within limit");
        }
    }

    #[test]
    fn test_rate_limit_blocks_over_limit() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60), "test");
        for _ in 0..3 { limiter.check("10.0.0.1"); }
        assert!(!limiter.check("10.0.0.1"), "Should block after limit exceeded");
    }

    #[test]
    fn test_rate_limit_different_ips_independent() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60), "test");
        for _ in 0..2 { limiter.check("1.1.1.1"); }
        assert!(!limiter.check("1.1.1.1"), "IP 1 should be blocked");
        assert!(limiter.check("2.2.2.2"),  "IP 2 should still be allowed");
    }
}

#[cfg(test)]
mod validation_tests {
    use thor_agent::api::validation::sanitize_string;

    #[test]
    fn test_sanitize_removes_null_bytes() {
        assert_eq!(sanitize_string("hello\x00world"), "helloworld");
    }

    #[test]
    fn test_sanitize_removes_control_chars() {
        assert_eq!(sanitize_string("hello\x01\x02world"), "helloworld");
    }

    #[test]
    fn test_sanitize_keeps_newlines() {
        assert_eq!(sanitize_string("line1\nline2"), "line1\nline2");
    }

    #[test]
    fn test_sanitize_keeps_normal_text() {
        let input = "Normal text with numbers 123 and symbols !@#";
        assert_eq!(sanitize_string(input), input);
    }
}
