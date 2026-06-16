//! Integration tests for Thor Axis-3 (DFIR) — forensics module.
//!
//! These are real integration tests that exercise live system state.
//! Each test targets a specific capability:
//!
//! 1. ThorQL process filtering
//! 2. Artifact execution and column validation
//! 3. Evidence collector chain-of-custody hashing
//! 4. Memory scanner permission handling (no panics)
//! 5. Artifact → API command routing simulation

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

// Re-import the crate's modules directly via path (integration test style)
use thor_agent::forensics::{
    artifacts::{run_artifact, ArtifactRegistry},
    collector::{collect_evidence, CollectionRequest, ForensicCollector},
    memory_scanner::{builtin_memory_rules, MemoryScanner, ScanError},
    thorql::execute_query,
};

// ─── Test 1: ThorQL process filtering ────────────────────────────────────────

/// Verify that a ThorQL query filters processes by name and returns correct
/// columns.  The test process itself (cargo/rustc test runner) should match
/// `pid > 0`, ensuring the result set is non-empty.
#[test]
fn test_thorql_process_filtering() {
    // All processes have pid > 0
    let result = execute_query("SELECT pid, name, cmdline FROM processes WHERE pid > 0")
        .expect("ThorQL query must not fail");

    assert!(
        !result.rows.is_empty(),
        "Process query should return at least one row (the test runner itself)"
    );

    // Every row must have the three projected columns
    for (i, row) in result.rows.iter().enumerate() {
        assert!(
            row.contains_key("pid"),
            "Row {i} missing 'pid' column"
        );
        assert!(
            row.contains_key("name"),
            "Row {i} missing 'name' column"
        );
        assert!(
            row.contains_key("cmdline"),
            "Row {i} missing 'cmdline' column"
        );
    }

    // scanned must be >= returned rows
    assert!(
        result.scanned >= result.rows.len(),
        "Scanned ({}) must be >= rows returned ({})",
        result.scanned, result.rows.len()
    );

    // Test LIKE filter — select rows whose name contains a letter
    let filtered = execute_query(
        "SELECT pid, name FROM processes WHERE name LIKE '%a%'"
    ).expect("LIKE query must not fail");

    // Every returned row must satisfy the filter
    for row in &filtered.rows {
        let name = row.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            name.contains('a') || name.contains('A'),
            "Row with name '{}' should not match LIKE '%a%'", name
        );
    }

    println!(
        "✅ test_thorql_process_filtering: {} processes, {} matched LIKE '%%a%%'",
        result.rows.len(), filtered.rows.len()
    );
}

// ─── Test 2: Artifact execution with column validation ───────────────────────

/// Execute the `linux.network.active_connections` artifact and verify that
/// the result contains the expected schema columns when rows are present.
#[test]
fn test_artifact_execution() {
    let result = run_artifact("linux.network.active_connections")
        .expect("linux.network.active_connections artifact must execute without error");

    // Even with zero connections, columns should be defined when rows exist
    if let Some(first_row) = result.rows.first() {
        let required_cols = ["pid", "local_ip", "remote_ip"];
        for col in &required_cols {
            assert!(
                first_row.contains_key(*col),
                "Expected column '{}' missing from active_connections result. \
                 Found columns: {:?}",
                col, first_row.keys().collect::<Vec<_>>()
            );
        }
    }

    // Validate all returned rows have state = ESTABLISHED (per artifact query)
    for row in &result.rows {
        if let Some(state) = row.get("state").and_then(|v| v.as_str()) {
            assert_eq!(
                state, "ESTABLISHED",
                "active_connections artifact should only return ESTABLISHED connections"
            );
        }
    }

    // Run a second artifact to confirm registry handles multiple artifacts
    let cron_result = run_artifact("linux.persistence.cron")
        .expect("linux.persistence.cron artifact must not fail");

    // Cron result rows should each have 'source' and 'entry' columns
    for row in &cron_result.rows {
        assert!(row.contains_key("source"), "Cron row missing 'source' column");
        assert!(row.contains_key("entry"),  "Cron row missing 'entry' column");
    }

    println!(
        "✅ test_artifact_execution: {} connections, {} cron entries",
        result.rows.len(), cron_result.rows.len()
    );
}

// ─── Test 3: Collector SHA-256 chain-of-custody ───────────────────────────────

/// Create a temporary file with known content, collect it, and verify that
/// the SHA-256 digest in the manifest matches the actual file content.
#[test]
fn test_collector_hashing() {
    let known_content = b"Thor chain-of-custody test payload 2024\n\x00\xFF\xAB";

    let mut tmp = NamedTempFile::new().expect("Cannot create temp file");
    tmp.write_all(known_content).expect("Cannot write test content");
    tmp.flush().expect("Cannot flush temp file");

    let pkg = collect_evidence(
        vec![tmp.path().to_path_buf()],
        Some("test-coc-001".into()),
    ).expect("collect_evidence must not fail");

    // Compute the expected SHA-256 of the known content
    let mut h = Sha256::new();
    h.update(known_content);
    let expected_sha256 = hex::encode(h.finalize());

    // Find the manifest entry for our temp file (excluding proc snapshot)
    let file_entry = pkg
        .manifest
        .iter()
        .find(|e| !e.path.contains("proc_snapshot"))
        .expect("Manifest must contain at least one non-snapshot entry");

    assert_eq!(
        file_entry.sha256,
        expected_sha256,
        "Manifest SHA-256 ({}) must match actual file content SHA-256 ({})",
        file_entry.sha256,
        expected_sha256
    );

    // Verify package-level integrity check passes
    assert!(
        pkg.verify_integrity(),
        "Package integrity verification must pass immediately after collection"
    );

    // Verify case label is preserved
    assert_eq!(
        pkg.case_label.as_deref(),
        Some("test-coc-001"),
        "Case label must be preserved in evidence package"
    );

    // Verify file size is correct
    assert_eq!(
        file_entry.size,
        known_content.len() as u64,
        "Manifest size must match actual content length"
    );

    println!(
        "✅ test_collector_hashing: SHA-256 match ({}...), package={} bytes",
        &file_entry.sha256[..8],
        pkg.archive_bytes.len()
    );
}

// ─── Test 4: Memory scanner permission handling ───────────────────────────────

/// Verify that scanning a privileged process (PID 1 = init/systemd) that may
/// deny access does NOT cause a panic, but returns a structured error or
/// a completed scan with zero matches.
#[test]
fn test_memory_scanner_permissions() {
    let rules = builtin_memory_rules();
    let scanner = MemoryScanner::new();

    // Test 4a: Scan PID 1 (likely EPERM in most environments)
    let result_pid1 = scanner.scan_process(1, &rules);
    match result_pid1 {
        Ok(scan) => {
            // If we got access (running as root in CI), verify the result is valid
            assert_eq!(scan.pid, 1);
            println!(
                "  PID 1 scan: {} matches, {}/{} regions, {} bytes",
                scan.matches.len(),
                scan.regions_scanned,
                scan.regions_scanned + scan.regions_skipped,
                scan.bytes_read
            );
        }
        Err(ScanError::PermissionDenied) => {
            // Expected in non-root environments — this is the correct behaviour
            println!("  PID 1: EPERM (expected in non-root environment)");
        }
        Err(ScanError::ProcessNotFound) => {
            // PID 1 should always exist, but handle gracefully
            println!("  PID 1: not found (unusual but handled)");
        }
        Err(ScanError::IoError(ref msg)) => {
            // IoError is acceptable in highly constrained container environments
            println!("  PID 1: IoError (constrained env): {}", msg);
        }
        Err(ScanError::RuleCompilationError(ref msg)) => {
            panic!("Built-in YARA rules must compile without errors: {}", msg);
        }
    }

    // Test 4b: Scan a non-existent PID — must return ProcessNotFound or IoError
    let ghost_pid = 99_999_999u32;
    let result_ghost = scanner.scan_process(ghost_pid, &rules);
    match result_ghost {
        Err(ScanError::ProcessNotFound)   => {} // correct
        Err(ScanError::PermissionDenied)  => {} // acceptable
        Err(ScanError::IoError(_))        => {} // acceptable in some kernels
        Err(ScanError::RuleCompilationError(ref msg)) => {
            panic!("Built-in rules must always compile: {}", msg);
        }
        Ok(scan) => {
            // If somehow the OS returns a result, file_count should be 0
            assert_eq!(scan.matches.len(), 0, "Ghost PID should have 0 matches");
        }
    }

    // Test 4c: Scan our own PID — must not panic, YARA match possible but not required
    let self_pid = std::process::id();
    let result_self = scanner.scan_process(self_pid, &rules);
    match result_self {
        Ok(scan) => {
            assert_eq!(scan.pid, self_pid);
            assert!(
                scan.regions_scanned + scan.regions_skipped > 0,
                "Our own process should have at least one memory region"
            );
            println!(
                "  Self PID {}: {} matches, {} regions",
                self_pid, scan.matches.len(), scan.regions_scanned
            );
        }
        Err(ScanError::PermissionDenied) => {
            // Possible in highly locked-down container (e.g. seccomp strict)
            println!("  Self scan: EPERM (strict seccomp env)");
        }
        Err(e) => panic!("Scanning own process should not return: {:?}", e),
    }

    println!("✅ test_memory_scanner_permissions: all permission cases handled gracefully");
}

// ─── Test 5: API command routing simulation ───────────────────────────────────

/// Simulate the routing logic that the API layer performs when it receives an
/// `RunArtifact` command.  This validates the dispatch path without needing a
/// running HTTP server.
#[test]
fn test_api_command_routing() {
    /// Simulates the command dispatcher in `forensics_api.rs`.
    fn dispatch_command(
        command: &str,
        params:  &HashMap<&str, &str>,
    ) -> Result<String, String> {
        match command {
            "RunThorQLQuery" => {
                let query = params.get("query").copied().unwrap_or("");
                if query.is_empty() {
                    return Err("empty_query".into());
                }
                execute_query(query)
                    .map(|r| format!("{{\"row_count\":{}}}", r.rows.len()))
                    .map_err(|e| format!("query_error: {}", e))
            }
            "RunArtifact" => {
                let id = params.get("artifact_id").copied().unwrap_or("");
                if id.is_empty() {
                    return Err("empty_artifact_id".into());
                }
                run_artifact(id)
                    .map(|r| format!("{{\"row_count\":{}}}", r.rows.len()))
                    .map_err(|e| format!("artifact_error: {}", e))
            }
            "CollectFiles" => {
                let path = params.get("path").copied().unwrap_or("");
                if path.is_empty() {
                    return Err("no_paths".into());
                }
                let mut tmp = NamedTempFile::new().map_err(|e| e.to_string())?;
                tmp.write_all(b"routing test").map_err(|e| e.to_string())?;

                collect_evidence(vec![tmp.path().to_path_buf()], None)
                    .map(|pkg| format!("{{\"file_count\":{}}}", pkg.file_count))
                    .map_err(|e| format!("collection_error: {}", e))
            }
            "ScanProcessMemory" => {
                let pid_str = params.get("pid").copied().unwrap_or("0");
                let pid: u32 = pid_str.parse().map_err(|_| "invalid_pid".to_string())?;
                if pid == 0 {
                    return Err("invalid_pid: PID 0 cannot be scanned".into());
                }
                let rules = builtin_memory_rules();
                MemoryScanner::new()
                    .scan_process(pid, &rules)
                    .map(|r| format!("{{\"match_count\":{}}}", r.matches.len()))
                    .map_err(|e| format!("scan_error: {}", e))
            }
            unknown => Err(format!("unknown_command: {}", unknown)),
        }
    }

    // 5a: RunThorQLQuery — valid
    let mut params = HashMap::new();
    params.insert("query", "SELECT pid, name FROM processes WHERE pid > 0");
    let result = dispatch_command("RunThorQLQuery", &params);
    assert!(result.is_ok(), "RunThorQLQuery must succeed: {:?}", result);
    println!("  RunThorQLQuery → {}", result.unwrap());

    // 5b: RunArtifact — valid artifact
    let mut params = HashMap::new();
    params.insert("artifact_id", "linux.credentials.user_accounts");
    let result = dispatch_command("RunArtifact", &params);
    assert!(result.is_ok(), "RunArtifact with valid ID must succeed: {:?}", result);
    println!("  RunArtifact → {}", result.unwrap());

    // 5c: RunArtifact — unknown artifact returns error (not panic)
    let mut params = HashMap::new();
    params.insert("artifact_id", "nonexistent.artifact.xyz");
    let result = dispatch_command("RunArtifact", &params);
    assert!(result.is_err(), "RunArtifact with unknown ID must return error");
    assert!(
        result.unwrap_err().contains("artifact_error"),
        "Error message must indicate artifact_error"
    );
    println!("  RunArtifact (unknown) → error ✓");

    // 5d: RunThorQLQuery — empty query returns error
    let params = HashMap::new();
    let result = dispatch_command("RunThorQLQuery", &params);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "empty_query");
    println!("  RunThorQLQuery (empty) → error ✓");

    // 5e: CollectFiles — collect a temp file
    let mut params = HashMap::new();
    params.insert("path", "/tmp");
    let result = dispatch_command("CollectFiles", &params);
    assert!(result.is_ok(), "CollectFiles must succeed: {:?}", result);
    println!("  CollectFiles → {}", result.unwrap());

    // 5f: ScanProcessMemory — invalid PID
    let mut params = HashMap::new();
    params.insert("pid", "0");
    let result = dispatch_command("ScanProcessMemory", &params);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("invalid_pid"));
    println!("  ScanProcessMemory (pid=0) → error ✓");

    // 5g: Unknown command
    let params = HashMap::new();
    let result = dispatch_command("UnknownCommand", &params);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("unknown_command"));
    println!("  UnknownCommand → error ✓");

    println!("✅ test_api_command_routing: all 7 dispatch cases validated");
}

// ─── Bonus test: ArtifactRegistry completeness ────────────────────────────────

/// Verify the artifact registry is self-consistent:
/// every artifact ID round-trips through get() successfully.
#[test]
fn test_artifact_registry_self_consistent() {
    let registry = ArtifactRegistry::new();
    let list = registry.list();

    assert!(
        list.len() >= 10,
        "Registry must contain at least 10 built-in artifacts, got {}",
        list.len()
    );

    for (id, _desc) in &list {
        let artifact = registry.get(id)
            .unwrap_or_else(|_| panic!("Artifact '{}' in list() must be findable via get()", id));
        assert_eq!(
            artifact.id.as_str(),
            *id,
            "Artifact ID mismatch: list says '{}' but struct says '{}'",
            id, artifact.id
        );
        assert!(!artifact.query.is_empty(), "Artifact '{}' must have a non-empty query", id);
        assert!(!artifact.description.is_empty(), "Artifact '{}' must have a description", id);
    }

    println!(
        "✅ test_artifact_registry_self_consistent: {} artifacts validated",
        list.len()
    );
}
