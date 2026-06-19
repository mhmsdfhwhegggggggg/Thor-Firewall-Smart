//! Criterion benchmark: Detection engines (YARA, ML, IDS).
//!
//! Run with: cargo bench --bench detection_engines
//!
//! Target performance (from roadmap):
//!   YARA scan:     < 2ms (cached Arc<Rules>)
//!   ML inference:  < 30µs (ORT ONNX)
//!   IDS rule:      < 100µs per packet

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use std::time::Duration;

// ── YARA benchmark ────────────────────────────────────────────────────────────

fn bench_yara(c: &mut Criterion) {
    use std::path::Path;
    use thor_agent::detection::yara::YaraEngine;

    let tmp = tempfile::tempdir().expect("tempdir");

    // Write EICAR test rule
    let eicar_rule = r#"
rule EICAR_Test {
    meta:
        description = "EICAR antivirus test string"
    strings:
        $eicar = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
"#;
    std::fs::write(tmp.path().join("eicar.yar"), eicar_rule).expect("write");

    let engine = YaraEngine::load(tmp.path()).expect("YaraEngine::load");

    let mut group = c.benchmark_group("yara");
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("load_rules", |b| {
        b.iter(|| {
            let e = YaraEngine::load(black_box(tmp.path())).expect("load");
            black_box(e)
        })
    });

    group.finish();
}

// ── ML benchmark ──────────────────────────────────────────────────────────────

fn bench_ml_features(c: &mut Criterion) {
    use thor_agent::ml::features::{N_FEATURES, extract_features};

    let mut group = c.benchmark_group("ml");
    group.throughput(Throughput::Elements(1));

    // Benchmark feature extraction (critical hot path)
    group.bench_function("extract_28_features", |b| {
        // TODO: construct a synthetic EnrichedEvent
        b.iter(|| {
            // placeholder — will be filled when event types are stabilized
            let v: Vec<f32> = (0..N_FEATURES).map(|i| i as f32 / 100.0).collect();
            black_box(v)
        })
    });

    group.finish();
}

criterion_group!(benches, bench_yara, bench_ml_features);
criterion_main!(benches);
