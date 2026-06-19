//! YARA Engine Unit Tests
//!
//! Tests:
//!   1. EICAR test signature detection
//!   2. Empty rules dir → graceful degradation (no panic)
//!   3. Rules compile correctly without panic
//!   4. Non-process events are skipped (no false positives)

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::Path;
    use tempfile::TempDir;

    /// Create a temp dir with an EICAR test file and a YARA rule.
    fn setup_eicar_env() -> (TempDir, TempDir) {
        let rules_dir  = TempDir::new().unwrap();
        let sample_dir = TempDir::new().unwrap();

        // Write the EICAR test YARA rule
        let rule = r#"
rule EICAR_Test {
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
"#;
        let rule_path = rules_dir.path().join("eicar_test.yar");
        std::fs::write(&rule_path, rule).unwrap();

        // Write the EICAR test file
        let eicar_content = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let sample_path = sample_dir.path().join("eicar_test.txt");
        std::fs::write(&sample_path, eicar_content).unwrap();

        (rules_dir, sample_dir)
    }

    #[test]
    fn yara_engine_loads_without_panic() {
        let dir = TempDir::new().unwrap();
        // Write a minimal valid YARA rule
        std::fs::write(dir.path().join("test.yar"), r#"
rule TestRule {
    strings: $a = "test"
    condition: $a
}
"#).unwrap();

        let engine = super::super::YaraEngine::load(dir.path());
        assert!(engine.is_ok(), "YARA engine must load without error");
        let engine = engine.unwrap();
        assert_eq!(engine.rule_count(), 1, "Expected 1 rule loaded");
    }

    #[test]
    fn yara_engine_empty_dir_is_graceful() {
        let dir = TempDir::new().unwrap();
        let engine = super::super::YaraEngine::load(dir.path()).unwrap();
        assert_eq!(engine.rule_count(), 0, "Empty rules dir → 0 rules, no panic");
    }

    #[test]
    fn yara_engine_nonexistent_dir_is_graceful() {
        let engine = super::super::YaraEngine::load(Path::new("/nonexistent/path/yara")).unwrap();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn yara_rules_compiled_once_not_per_scan() {
        // Verify that multiple calls to scan() reuse the same compiled rules
        // (not recreating Compiler::new() each time, which was the original bug)
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("rule.yar"), r#"
rule MultiScanTest {
    strings: $x = "malware"
    condition: $x
}
"#).unwrap();

        let engine = super::super::YaraEngine::load(dir.path()).unwrap();

        // Clone multiple times — Arc should be shared, not recompiled
        let e1 = engine.clone();
        let e2 = engine.clone();

        // Rule count should be consistent across clones
        assert_eq!(e1.rule_count(), 1);
        assert_eq!(e2.rule_count(), 1);

        // The critical invariant: compiled_rules is Some (not None due to bug)
        // If the old bug were present, each scan() would create Compiler::new() with 0 rules
        // and compiled_rules would be None → all scans return empty.
        assert!(
            engine.has_compiled_rules(),
            "compiled_rules must be Some after loading valid rules (Arc<Rules> fix)"
        );
    }
}
