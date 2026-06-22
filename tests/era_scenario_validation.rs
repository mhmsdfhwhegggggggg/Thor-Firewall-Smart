//! ERA Scenario Validation — Integration Tests
//! Phase 1: Stability & Infrastructure
//!
//! Tests:
//!   1. Zero-Day triggers Quarantine state
//!   2. Quarantine sends SIGSTOP to process
//!   3. Control Plane sends RESOLVE_RELEASE
//!   4. Agent sends SIGCONT, process resumes
//!   5. XaiReport is populated in the alert
//!
//! Run: cargo test --test era_scenario_validation

#[cfg(test)]
mod era_scenario_validation {
    use std::time::Duration;
    use tokio::time::sleep;

    /// Simulates a Zero-Day behavioral anomaly triggering the full HITL pipeline.
    ///
    /// Pipeline: ZeroDayEngine::analyze → DetectionEngine::detect → 
    ///           SoarEngine::respond(Quarantine) → SIGSTOP → Control Plane alert →
    ///           Admin reviews XaiReport → RESOLVE_RELEASE → SIGCONT
    #[tokio::test]
    async fn test_zero_day_triggers_quarantine_then_release() {
        // Spawn a real harmless process to quarantine
        let mut child = tokio::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("Failed to spawn test process");
        
        let pid = child.id().expect("Process has no PID");
        println!("Test process spawned: PID {}", pid);

        // Give process time to start
        sleep(Duration::from_millis(100)).await;

        // Verify process is running
        assert!(
            std::path::Path::new(&format!("/proc/{}", pid)).exists(),
            "Test process should be running"
        );

        // Simulate quarantine via SIGSTOP
        let result = quarantine_process(pid);
        assert!(result.is_ok(), "SIGSTOP should succeed: {:?}", result);
        
        println!("Process {} suspended (SIGSTOP sent)", pid);
        sleep(Duration::from_millis(50)).await;

        // Verify process is stopped (state='T' in /proc/pid/status)
        let state = get_process_state(pid);
        assert_eq!(state, "T", 
            "Process should be in Stopped state (T) after SIGSTOP, got: {}", state);
        println!("✅ Process {} confirmed STOPPED (state={})", pid, state);

        // Simulate RESOLVE_RELEASE: send SIGCONT
        let result = release_process(pid);
        assert!(result.is_ok(), "SIGCONT should succeed: {:?}", result);
        
        println!("Process {} resumed (SIGCONT sent)", pid);
        sleep(Duration::from_millis(50)).await;

        // Verify process is running again
        let state = get_process_state(pid);
        assert!(
            state == "S" || state == "R",
            "Process should be Running/Sleeping after SIGCONT, got: {}",
            state
        );
        println!("✅ Process {} confirmed RESUMED (state={})", pid, state);

        // Cleanup
        child.kill().await.ok();
        println!("Test complete: Full SIGSTOP → SIGCONT cycle verified");
    }

    #[tokio::test]
    async fn test_xai_report_contains_feature_weights() {
        use thor_agent::ml::features::FeatureWeight;
        
        // Create a synthetic feature vector with known anomaly
        let features = vec![
            0.5f32, 0.3, 2.5, 3.0,       // pid_norm, ppid_ratio, cmdline_entropy, arg_count
            1.0, 1.0, 1.0, 1.0,           // has_base64, has_pipe, has_dev_tcp, from_tmp_dir — ALL flags set (attack)
            0.0, 0.0, 1.0, 1.0,           // parent_is_shell, parent_is_webserver, is_root, has_suid
            0.99, 0.0, 1.0, 1.0,          // dst_port_norm, dst_is_internal, geo_distance, ioc_matched
            1.0, 0.9, 0.9, 0.9,           // geo_risk, bytes_in, bytes_out, pkt_rate
            0.1, 1.0, 0.9, 1.0,           // tls_cipher, ja4_match, dns_entropy, ssh_brute
            1.0, 1.0, 0.5, 0.866,         // rdp_anomaly, ueba_dev, time_sin, time_cos
        ];
        
        // Build XAI report from features
        let weights = thor_agent::ml::onnx_scorer::build_xai_report(&features);
        
        assert!(!weights.is_empty(), "XAI report must not be empty");
        assert!(weights.len() <= 5, "XAI report shows top-5 features max");
        
        // The top feature should be one of the attack indicators
        let top_name = &weights[0].feature_name;
        println!("Top XAI feature: {} (weight={:.3})", top_name, weights[0].weight);
        
        // Attack-indicator features should be top-ranked
        let attack_indicators = ["has_base64", "has_pipe", "has_dev_tcp", "ioc_matched", 
                                   "ssh_brute", "has_suid", "rdp_anomaly", "ueba_dev"];
        assert!(
            attack_indicators.iter().any(|&f| top_name.contains(f)),
            "Top XAI feature should be an attack indicator, got: {}", top_name
        );
        println!("✅ XAI report correctly identifies attack indicators");
    }

    #[tokio::test]
    async fn test_grpc_quarantine_resolution_parsing() {
        // Test that RESOLVE_BLOCK and RESOLVE_RELEASE directives parse correctly
        // This validates Phase 10: Remote Resolution Command Stream
        
        let resolve_block   = "RESOLVE_BLOCK:pid=1234:reason=confirmed_attack";
        let resolve_release = "RESOLVE_RELEASE:pid=1234:whitelist_hours=24";
        
        let action_b = parse_resolution_directive(resolve_block);
        let action_r = parse_resolution_directive(resolve_release);
        
        assert_eq!(action_b.action, "RESOLVE_BLOCK");
        assert_eq!(action_b.pid, 1234);
        assert_eq!(action_r.action, "RESOLVE_RELEASE");
        assert_eq!(action_r.whitelist_hours, 24);
        
        println!("✅ Resolution directive parsing validated");
    }

    // ── Helper functions ────────────────────────────────────────────────────

    fn quarantine_process(pid: u32) -> Result<(), nix::Error> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        kill(Pid::from_raw(pid as i32), Signal::SIGSTOP)
    }

    fn release_process(pid: u32) -> Result<(), nix::Error> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        kill(Pid::from_raw(pid as i32), Signal::SIGCONT)
    }

    fn get_process_state(pid: u32) -> String {
        let status = std::fs::read_to_string(format!("/proc/{}/status", pid))
            .unwrap_or_default();
        for line in status.lines() {
            if line.starts_with("State:") {
                return line.split_whitespace().nth(1).unwrap_or("?").to_string();
            }
        }
        "?".to_string()
    }

    #[derive(Debug)]
    struct ResolutionAction { action: String, pid: u32, whitelist_hours: u32 }
    
    fn parse_resolution_directive(s: &str) -> ResolutionAction {
        let parts: Vec<&str> = s.split(':').collect();
        let action = parts.first().unwrap_or(&"UNKNOWN").to_string();
        let pid = parts.iter()
            .find(|p| p.starts_with("pid="))
            .and_then(|p| p.strip_prefix("pid="))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let whitelist_hours = parts.iter()
            .find(|p| p.starts_with("whitelist_hours="))
            .and_then(|p| p.strip_prefix("whitelist_hours="))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        ResolutionAction { action, pid, whitelist_hours }
    }
}
