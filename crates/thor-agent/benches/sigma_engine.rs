//! Criterion benchmark: Sigma Engine — measures rule indexing performance.
//!
//! Run with: cargo bench --bench sigma_engine
//!
//! Target from roadmap Phase 3:
//!   - 10x speedup from HashMap category indexing
//!   - Parallel evaluation via Rayon par_iter

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use std::time::Duration;

/// Generate a minimal Sigma YAML rule string.
fn make_sigma_rule(id: u32, category: &str) -> String {
    format!(
        r#"title: Bench Rule {id}
id: bench-{id:08x}-0000-0000-0000-000000000000
status: stable
description: "Benchmark rule {id}"
level: medium
logsource:
  category: {category}
detection:
  keywords:
    - malicious_token_{id}
  condition: keywords
"#
    )
}

fn bench_sigma_load(c: &mut Criterion) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cats = ["process_creation", "network_connection", "dns_query", "file_event"];

    for i in 0..100u32 {
        let cat = cats[(i % 4) as usize];
        let rule = make_sigma_rule(i, cat);
        std::fs::write(tmp.path().join(format!("rule_{:04}.yml", i)), rule)
            .expect("write rule");
    }

    c.bench_function("sigma_load_100_rules", |b| {
        b.iter(|| {
            use thor_agent::detection::sigma_compiler::SigmaCompiler;
            let rules = SigmaCompiler::load_directory(black_box(tmp.path()));
            black_box(rules.len())
        })
    });
}

criterion_group!(benches, bench_sigma_load);
criterion_main!(benches);
