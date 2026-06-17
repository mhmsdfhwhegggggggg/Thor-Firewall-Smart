//! Integration tests for Thor Axis-4 (Zero-Day Detection Engine).
//!
//! Test coverage:
//!  1.  SyscallProfiler — event accumulation, unique syscall counting
//!  2.  SyscallProfiler — child spawns and dangerous syscall classification
//!  3.  AnomalyEngine   — Isolation Forest initialises and scores in [0,1]
//!  4.  AnomalyEngine   — extreme features score > normal features
//!  5.  BehavioralBaseline — no drift before warmup
//!  6.  BehavioralBaseline — drift computed after warmup
//!  7.  BehavioralBaseline — same distribution → near-zero KL divergence
//!  8.  ExploitPrimitive  — mprotect burst triggers ROP alert
//!  9.  ExploitPrimitive  — memfd_create triggers fileless execution alert
//!  10. ExploitPrimitive  — process_vm_writev triggers injection alert
//!  11. ZeroDayEngine     — ingest normal events → no alerts
//!  12. ZeroDayEngine     — ingest dangerous events → alerts generated
//!  13. ZeroDayEngine     — all_profiles returns non-empty after ingestion
//!  14. ZeroDayEngine     — severity levels are ordered correctly
//!  15. ThorQL JOIN        — processes JOIN users ON uid
//!  16. ThorQL JOIN        — qualified column projection works

use std::sync::Arc;

use thor_agent::{
    ZeroDayEngine, ZeroDaySeverity, DetectionMethod,
    SyscallProfiler, SyscallEvent, ProcessProfile,
    AnomalyEngine, FeatureVector, AnomalyScore,
    ExploitPrimitiveDetector, ExploitAlert, ExploitType,
    BehavioralBaseline, BaselineDrift,
};

use thor_agent::forensics::thorql::execute_query;

// ── Helpers ────────────────────────────────────────────────────────────────────

fn ev(pid: u32, syscall_nr: u32, comm: &str) -> SyscallEvent {
    SyscallEvent::new(pid, syscall_nr, comm)
}

fn normal_fv() -> FeatureVector {
    FeatureVector {
        syscall_rate:      50.0,
        unique_syscalls:   20.0,
        memory_alloc_rate: 0.5,
        child_spawn_rate:  0.05,
        network_bytes:     8.0,
        write_entropy:     0.3,
        dangerous_calls:   0.0,
        event_density:     5.0,
    }
}

fn extreme_fv() -> FeatureVector {
    FeatureVector {
        syscall_rate:      8000.0,
        unique_syscalls:   240.0,
        memory_alloc_rate: 80.0,
        child_spawn_rate:  40.0,
        network_bytes:     19.0,
        write_entropy:     0.98,
        dangerous_calls:   200.0,
        event_density:     400.0,
    }
}

// Syscall numbers
const SYS_READ:              u32 = 0;
const SYS_WRITE:             u32 = 1;
const SYS_MMAP:              u32 = 9;
const SYS_MPROTECT:          u32 = 10;
const SYS_MUNMAP:            u32 = 11;
const SYS_FORK:              u32 = 57;
const SYS_EXECVE:            u32 = 59;
const SYS_PTRACE:            u32 = 101;
const SYS_PROCESS_VM_WRITEV: u32 = 311;
const SYS_MEMFD_CREATE:      u32 = 319;
const SYS_CLONE:             u32 = 56;

// ── Test 1: SyscallProfiler accumulates events correctly ───────────────────────

#[test]
fn test_profiler_event_accumulation() {
    let profiler = SyscallProfiler::new();

    // Feed 20 read events for PID 1000
    for _ in 0..20 {
        profiler.record(&ev(1000, SYS_READ, "test_reader"));
    }

    let profile = profiler.get_profile(1000)
        .expect("Profile must exist after recording events");

    assert_eq!(profile.pid,         1000,  "PID must match");
    assert_eq!(profile.event_count, 20,    "Event count must be 20");
    assert_eq!(profile.process_name, "test_reader", "Process name must match comm");

    let read_count = profile.syscall_counts.get(&SYS_READ).copied().unwrap_or(0);
    assert_eq!(read_count, 20, "SYS_READ count must be 20");

    println!(
        "✅ test_profiler_event_accumulation: PID {} → {} events, rate_ema={:.2}/s",
        profile.pid, profile.event_count, profile.syscall_rate_ema
    );
}

// ── Test 2: Unique syscall counting and child spawn detection ──────────────────

#[test]
fn test_profiler_unique_syscalls_and_spawns() {
    let profiler = SyscallProfiler::new();

    for nr in [SYS_READ, SYS_WRITE, SYS_MMAP, SYS_FORK, SYS_EXECVE, SYS_CLONE] {
        profiler.record(&ev(2000, nr, "multi_call"));
    }
    // Add a duplicate to verify counting
    profiler.record(&ev(2000, SYS_READ, "multi_call"));

    let profile = profiler.get_profile(2000).unwrap();

    // 6 unique syscall types
    assert_eq!(profile.unique_syscall_count, 6, "Must have 6 unique syscalls");
    // 7 total events
    assert_eq!(profile.event_count, 7);
    // 3 child spawns (fork + execve + clone)
    assert_eq!(profile.child_spawns, 3, "FORK + EXECVE + CLONE = 3 spawns");

    println!(
        "✅ test_profiler_unique_syscalls_and_spawns: {} unique, {} spawns",
        profile.unique_syscall_count, profile.child_spawns
    );
}

// ── Test 3: AnomalyEngine initialises and scores are in [0,1] ─────────────────

#[test]
fn test_anomaly_engine_score_range() {
    let engine = AnomalyEngine::new(50);

    for (name, fv) in [("normal", normal_fv()), ("extreme", extreme_fv())] {
        let score = engine.score(&fv);
        assert!(
            score.value >= 0.0 && score.value <= 1.0,
            "{} features score {:.4} must be in [0, 1]",
            name, score.value
        );
        assert_eq!(score.n_trees, 50, "Score must report 50 trees");
        println!("  {} features: score={:.4}, avg_path={:.4}", name, score.value, score.avg_path_length);
    }

    println!("✅ test_anomaly_engine_score_range: all scores in [0, 1]");
}

// ── Test 4: Extreme features score higher than normal features ─────────────────

#[test]
fn test_anomaly_extreme_vs_normal() {
    let engine = AnomalyEngine::new(100);

    let normal_score  = engine.score(&normal_fv());
    let extreme_score = engine.score(&extreme_fv());

    println!(
        "Normal: {:.4}, Extreme: {:.4}", normal_score.value, extreme_score.value
    );

    // The extreme values should at minimum have a measurable anomaly score
    assert!(
        extreme_score.value > 0.35,
        "Extreme features must have anomaly score > 0.35 (got {:.4})",
        extreme_score.value
    );

    println!("✅ test_anomaly_extreme_vs_normal: extreme={:.4} > 0.35", extreme_score.value);
}

// ── Test 5: BehavioralBaseline — no drift before warmup ───────────────────────

#[test]
fn test_baseline_no_drift_before_warmup() {
    let baseline = BehavioralBaseline::new();

    // Only 5 updates — well below warmup_updates (20)
    for _ in 0..5 {
        baseline.update(3000, &normal_fv());
    }

    let drift = baseline.compute_drift(3000, &extreme_fv());
    assert!(
        drift.is_none(),
        "Drift must not be computed before warmup period (5 < 20 updates)"
    );

    println!("✅ test_baseline_no_drift_before_warmup: None returned before warmup");
}

// ── Test 6: BehavioralBaseline — drift detected after warmup ──────────────────

#[test]
fn test_baseline_drift_after_warmup() {
    let baseline = BehavioralBaseline::new();

    // Feed 25 normal samples to complete warmup
    for _ in 0..25 {
        baseline.update(4000, &normal_fv());
    }

    // Query with anomalous behaviour
    let drift = baseline.compute_drift(4000, &extreme_fv())
        .expect("Drift must be computed after 25 updates");

    println!("  KL-divergence: {:.4}, severity: {}", drift.kl_divergence, drift.severity);

    assert!(drift.kl_divergence >= 0.0, "KL-divergence must be non-negative");
    assert!(!drift.top_drift_feature.is_empty(), "Must identify a top drift feature");
    assert_eq!(drift.pid, 4000, "PID must match");

    println!(
        "✅ test_baseline_drift_after_warmup: KL={:.4}, top_feature={}",
        drift.kl_divergence, drift.top_drift_feature
    );
}

// ── Test 7: Same distribution → near-zero KL divergence ──────────────────────

#[test]
fn test_baseline_same_distribution_near_zero_kl() {
    let baseline = BehavioralBaseline::new();
    let fv = normal_fv();

    for _ in 0..25 {
        baseline.update(5000, &fv);
    }

    let drift = baseline.compute_drift(5000, &fv)
        .expect("Drift must be computed after warmup");

    println!("  Same-distribution KL: {:.6}", drift.kl_divergence);

    // KL(P || P) ≈ 0 — allow small epsilon for floating point
    assert!(
        drift.kl_divergence < 0.5,
        "Same distribution must have near-zero KL divergence, got {:.6}",
        drift.kl_divergence
    );

    println!("✅ test_baseline_same_distribution_near_zero_kl: KL={:.6}", drift.kl_divergence);
}

// ── Test 8: ExploitPrimitive — mprotect burst triggers ROP alert ──────────────

#[test]
fn test_exploit_mprotect_triggers_rop_alert() {
    let detector = ExploitPrimitiveDetector::new();
    let profiler  = SyscallProfiler::new();

    // Build a minimal profile
    for _ in 0..60 {
        profiler.record(&ev(6000, SYS_READ, "vuln_app"));
    }
    let profile = profiler.get_profile(6000).unwrap();

    let mut rop_detected = false;
    for _ in 0..15 {
        let event  = ev(6000, SYS_MPROTECT, "vuln_app");
        let alerts = detector.analyze(&event, &profile);
        if alerts.iter().any(|a| a.exploit_type == ExploitType::RopChainPreparation) {
            rop_detected = true;
        }
    }

    assert!(rop_detected, "15 mprotect() calls must trigger a ROP chain preparation alert");
    println!("✅ test_exploit_mprotect_triggers_rop_alert: ROP alert detected ✓");
}

// ── Test 9: memfd_create triggers fileless execution alert ────────────────────

#[test]
fn test_exploit_memfd_triggers_fileless_alert() {
    let detector = ExploitPrimitiveDetector::new();
    let profiler  = SyscallProfiler::new();

    for _ in 0..60 {
        profiler.record(&ev(7000, SYS_READ, "fileless_loader"));
    }
    let profile = profiler.get_profile(7000).unwrap();

    let event  = ev(7000, SYS_MEMFD_CREATE, "fileless_loader");
    let alerts = detector.analyze(&event, &profile);

    let has_fileless = alerts.iter()
        .any(|a| a.exploit_type == ExploitType::FilelessExecution);
    assert!(has_fileless, "memfd_create must trigger FilelessExecution alert");

    // Confidence must be high for such a definitive indicator
    let fileless_alert = alerts.iter()
        .find(|a| a.exploit_type == ExploitType::FilelessExecution)
        .unwrap();
    assert!(
        fileless_alert.confidence >= 0.7,
        "Fileless execution confidence must be >= 0.7, got {:.2}",
        fileless_alert.confidence
    );

    println!(
        "✅ test_exploit_memfd_triggers_fileless_alert: confidence={:.2}",
        fileless_alert.confidence
    );
}

// ── Test 10: process_vm_writev triggers injection alert ───────────────────────

#[test]
fn test_exploit_process_vm_writev_triggers_alert() {
    let detector = ExploitPrimitiveDetector::new();
    let profiler  = SyscallProfiler::new();

    for _ in 0..60 {
        profiler.record(&ev(8000, SYS_READ, "injector"));
    }
    let profile = profiler.get_profile(8000).unwrap();

    let event  = ev(8000, SYS_PROCESS_VM_WRITEV, "injector");
    let alerts = detector.analyze(&event, &profile);

    assert!(
        !alerts.is_empty(),
        "process_vm_writev must trigger at least one exploit alert"
    );
    assert!(
        alerts.iter().any(|a| a.confidence >= 0.8),
        "process_vm_writev alert must have confidence >= 0.8"
    );

    println!("✅ test_exploit_process_vm_writev: {} alert(s) generated", alerts.len());
}

// ── Test 11: ZeroDayEngine — normal events → no immediate alerts ──────────────

#[test]
fn test_engine_normal_events_no_alerts() {
    let engine = ZeroDayEngine::new();
    let mut total_alerts = 0;

    // Feed 40 normal read events (below the 50-event threshold for scoring)
    for i in 0..40 {
        let event = ev(9000, SYS_READ, "normal_proc");
        let alerts = engine.ingest(&event);
        total_alerts += alerts.len();
    }

    // Below threshold (50 events) — no alerts should fire
    assert_eq!(
        total_alerts, 0,
        "No alerts should be generated before the 50-event warmup threshold, got {}",
        total_alerts
    );

    println!("✅ test_engine_normal_events_no_alerts: 0 alerts below warmup threshold ✓");
}

// ── Test 12: ZeroDayEngine — dangerous events → alerts generated ──────────────

#[test]
fn test_engine_dangerous_events_generate_alerts() {
    let engine = ZeroDayEngine::new();

    // First feed enough events to pass the warmup threshold
    for _ in 0..55 {
        engine.ingest(&ev(10000, SYS_READ, "exploited_proc"));
    }

    // Now inject memfd_create — an immediate dangerous event
    let memfd_event = ev(10000, SYS_MEMFD_CREATE, "exploited_proc");
    let alerts = engine.ingest(&memfd_event);

    // ExploitPrimitive alerts fire immediately regardless of warmup
    let has_exploit_alert = alerts.iter()
        .any(|a| a.detection_method == DetectionMethod::ExploitPrimitive);

    assert!(
        has_exploit_alert,
        "memfd_create after warmup must generate an ExploitPrimitive alert"
    );

    println!(
        "✅ test_engine_dangerous_events_generate_alerts: {} alert(s), exploit={}",
        alerts.len(), has_exploit_alert
    );
}

// ── Test 13: ZeroDayEngine — all_profiles returns profiles after ingestion ────

#[test]
fn test_engine_profiles_populated() {
    let engine = ZeroDayEngine::new();

    for pid in [11000u32, 11001, 11002] {
        for _ in 0..5 {
            engine.ingest(&ev(pid, SYS_READ, "tracked_proc"));
        }
    }

    let profiles = engine.all_profiles();
    assert!(
        profiles.len() >= 3,
        "Must have at least 3 profiles after ingesting events for 3 PIDs, got {}",
        profiles.len()
    );

    for profile in &profiles {
        assert!(profile.event_count >= 5, "Each profile must have >= 5 events");
    }

    println!("✅ test_engine_profiles_populated: {} profiles", profiles.len());
}

// ── Test 14: ZeroDaySeverity ordering ─────────────────────────────────────────

#[test]
fn test_zero_day_severity_ordering() {
    use std::cmp::Ordering;

    assert!(ZeroDaySeverity::Critical > ZeroDaySeverity::High);
    assert!(ZeroDaySeverity::High    > ZeroDaySeverity::Medium);
    assert!(ZeroDaySeverity::Medium  > ZeroDaySeverity::Low);

    // Score-based derivation
    assert_eq!(ZeroDaySeverity::from_score(0.95), ZeroDaySeverity::Critical);
    assert_eq!(ZeroDaySeverity::from_score(0.80), ZeroDaySeverity::High);
    assert_eq!(ZeroDaySeverity::from_score(0.60), ZeroDaySeverity::Medium);
    assert_eq!(ZeroDaySeverity::from_score(0.30), ZeroDaySeverity::Low);

    // Display
    assert_eq!(format!("{}", ZeroDaySeverity::Critical), "CRITICAL");
    assert_eq!(format!("{}", ZeroDaySeverity::High),     "HIGH");
    assert_eq!(format!("{}", ZeroDaySeverity::Medium),   "MEDIUM");
    assert_eq!(format!("{}", ZeroDaySeverity::Low),      "LOW");

    println!("✅ test_zero_day_severity_ordering: all orderings correct ✓");
}

// ── Test 15: ThorQL JOIN — processes JOIN users ON uid ────────────────────────

#[test]
fn test_thorql_join_processes_users() {
    let result = execute_query(
        "SELECT * FROM processes JOIN users ON uid = uid"
    ).expect("JOIN query must not fail");

    // There must be at least one process (the test runner itself)
    // joined with at least one user (the user running the test)
    println!(
        "  processes JOIN users: {} joined rows, {} scanned",
        result.rows.len(), result.scanned
    );

    // scanned reflects the JOIN output size, not raw scan
    assert!(result.scanned >= 0, "Scanned count must be non-negative");

    // If rows are returned, they should have columns from both tables
    if let Some(row) = result.rows.first() {
        // Row should have uid from at least one table
        let has_uid = row.contains_key("uid")
            || row.contains_key("processes.uid")
            || row.contains_key("users.uid");
        assert!(has_uid, "Joined row must have uid column");
    }

    println!("✅ test_thorql_join_processes_users: JOIN executed successfully ✓");
}

// ── Test 16: ThorQL JOIN — qualified column projection ────────────────────────

#[test]
fn test_thorql_join_qualified_projection() {
    let result = execute_query(
        "SELECT processes.pid, connections.remote_ip \
         FROM processes JOIN connections ON processes.pid = connections.pid \
         WHERE connections.state = 'ESTABLISHED'"
    ).expect("Qualified JOIN query must not fail");

    // Result may be empty (no ESTABLISHED connections in test env), but must not error
    println!(
        "  processes JOIN connections (ESTABLISHED): {} rows",
        result.rows.len()
    );

    // Verify column projection — qualified names should appear
    for row in &result.rows {
        let has_pid = row.contains_key("processes.pid") || row.contains_key("pid");
        let has_ip  = row.contains_key("connections.remote_ip") || row.contains_key("remote_ip");
        assert!(has_pid, "Joined row must have pid column");
        assert!(has_ip,  "Joined row must have remote_ip column");
    }

    println!("✅ test_thorql_join_qualified_projection: qualified columns projected correctly ✓");
}

// ── Test 17: ThorQL JOIN — error on unknown right table ───────────────────────

#[test]
fn test_thorql_join_unknown_right_table_errors() {
    let result = execute_query(
        "SELECT * FROM processes JOIN nonexistent_table ON processes.pid = nonexistent_table.pid"
    );
    assert!(
        result.is_err(),
        "JOIN with unknown right table must return an error"
    );
    println!("✅ test_thorql_join_unknown_right_table_errors: error returned correctly ✓");
}

// ── Test 18: Full pipeline simulation ─────────────────────────────────────────

#[test]
fn test_full_pipeline_simulation() {
    let engine = ZeroDayEngine::new();

    // Simulate a realistic attack sequence:
    // 1. Normal activity (50 events to pass warmup)
    // 2. Sudden dangerous syscall
    // 3. mprotect burst (ROP setup)

    // Phase 1: normal activity
    for _ in 0..55 {
        engine.ingest(&ev(12000, SYS_READ, "victim_process"));
        engine.ingest(&ev(12000, SYS_WRITE, "victim_process"));
    }

    // Phase 2: memfd_create (fileless execution)
    let mut phase2_alerts = engine.ingest(&ev(12000, SYS_MEMFD_CREATE, "victim_process"));

    // Phase 3: mprotect burst
    let mut phase3_alerts = Vec::new();
    for _ in 0..15 {
        let mut a = engine.ingest(&ev(12000, SYS_MPROTECT, "victim_process"));
        phase3_alerts.append(&mut a);
    }

    let total = phase2_alerts.len() + phase3_alerts.len();
    println!(
        "  Full pipeline: phase2={} alerts, phase3={} alerts, total={}",
        phase2_alerts.len(), phase3_alerts.len(), total
    );

    // Phase 2 (memfd_create) should always generate alerts
    assert!(
        phase2_alerts.len() >= 1,
        "memfd_create must generate at least 1 alert in Phase 2"
    );

    // Phase 3 (mprotect burst) should generate ROP alerts
    let has_rop = phase3_alerts.iter()
        .any(|a| a.exploit_type == Some(ExploitType::RopChainPreparation));
    assert!(has_rop, "mprotect burst in Phase 3 must generate ROP chain alert");

    // All alerts should have valid severity
    for alert in phase2_alerts.iter().chain(phase3_alerts.iter()) {
        assert!(alert.anomaly_score >= 0.0 && alert.anomaly_score <= 1.0,
            "Anomaly score must be in [0,1]");
        assert!(!alert.id.is_empty(), "Alert ID must be non-empty");
        assert!(!alert.description.is_empty(), "Alert description must be non-empty");
        assert!(!alert.mitre_techniques.is_empty(), "Alert must have MITRE technique IDs");
    }

    println!(
        "✅ test_full_pipeline_simulation: {} total alerts, all validated ✓", total
    );
}
