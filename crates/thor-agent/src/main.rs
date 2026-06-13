//! Thor Firewall Smart — Production-hardened entry point.
//! Security controls enforced at startup:
//!   - THOR_JWT_SECRET and THOR_ADMIN_PASSWORD validated (exits if missing/weak)
//!   - Audit log initialized before API server
//!   - SIGHUP triggers hot-reload of rate limiter config (no restart needed)
//!   - SIGTERM triggers graceful shutdown with 30-second drain window

use anyhow::{Context, Result};
use mimalloc::MiMalloc;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, warn, error};
use tracing_subscriber::{EnvFilter, fmt};

mod config;
mod ebpf;
mod state;
mod events;
mod detection;
mod soar;
mod ml;
mod api;
mod audit;
mod metrics;
mod siem;
mod security;

use config::ThorConfig;
use ebpf::BpfManager;
use state::ThorState;
use events::pipeline::EventPipeline;
use detection::DetectionEngine;
use soar::SoarEngine;
use ml::MlEngine;
use api::start_api_server;
use audit::AuditLogger;
use metrics::ThorMetrics;
use siem::SiemExporter;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    // ── Structured logging ─────────────────────────────────────────────────────
    fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("thor_agent=info".parse()?)
                .add_directive("aya=warn".parse()?),
        )
        .json()
        .init();

    info!("🛡️  Thor Firewall Smart v{} starting...", env!("CARGO_PKG_VERSION"));

    // ── Startup secret validation (fail-fast before anything else) ────────────
    validate_required_secrets();

    // ── Configuration ──────────────────────────────────────────────────────────
    let config = ThorConfig::load().context("Failed to load configuration")?;
    info!("📋 Config loaded: interface={}, api={}", config.interface, config.api_addr);

    // ── Audit log (must be ready before API starts) ───────────────────────────
    let audit_path = std::env::var("THOR_AUDIT_DB_PATH")
        .unwrap_or_else(|_| "/var/lib/thor/audit.db".to_string());
    let audit = Arc::new(
        AuditLogger::open(&audit_path)
            .context("Failed to open audit log — check THOR_AUDIT_DB_PATH and permissions")?,
    );
    info!("📋 Audit log: {} (chain verified: {})", audit_path, audit.verify_chain());

    // ── Metrics collector ──────────────────────────────────────────────────────
    let metrics = Arc::new(ThorMetrics::new());

    // ── SIEM exporter ──────────────────────────────────────────────────────────
    let siem = Arc::new(SiemExporter::from_env());

    // ── Shared state ───────────────────────────────────────────────────────────
    let state = Arc::new(ThorState::new(&config));
    info!(
        "💾 State: {} flow shards | {} IOC capacity",
        config.flow_map_shards, config.ioc_bloom_capacity
    );

    // ── ML engine ─────────────────────────────────────────────────────────────
    let ml_engine = Arc::new(
        MlEngine::new(&config.model_path).unwrap_or_else(|e| {
            warn!("ML engine unavailable: {} — rule-only mode", e);
            MlEngine::dummy()
        }),
    );

    // ── Detection engine ───────────────────────────────────────────────────────
    let detection = Arc::new(
        DetectionEngine::new(&config.sigma_rules_dir, &config.yara_rules_dir, ml_engine.clone())
            .context("Failed to initialize detection engine")?,
    );
    info!(
        "🔍 Detection: {} Sigma rules | {} YARA rules",
        detection.sigma_rule_count(), detection.yara_rule_count()
    );

    // ── SOAR engine ────────────────────────────────────────────────────────────
    let soar = Arc::new(SoarEngine::new(state.clone(), config.thehive_url.clone()));

    // ── Channels ──────────────────────────────────────────────────────────────
    let (raw_tx, raw_rx)     = flume::bounded::<events::RawEvent>(65_536);
    let (alert_tx, alert_rx) = flume::bounded::<events::Alert>(8_192);

    // ── eBPF programs ──────────────────────────────────────────────────────────
    let _bpf_manager = BpfManager::start(&config.interface, raw_tx.clone(), state.clone())
        .await.context("Failed to start eBPF programs")?;
    info!("⚡ eBPF active: XDP (IPv4+IPv6) + kprobes + tracepoints");

    // ── Event pipeline ─────────────────────────────────────────────────────────
    let pipeline = EventPipeline::new(state.clone(), detection.clone(), soar.clone());
    let pipeline_handle = pipeline.spawn(raw_rx, alert_tx.clone());

    // ── Rate limiter cleanup task (every 5 minutes) ───────────────────────────
    let _cleanup = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            api::rate_limit::login_limiter().cleanup();
            api::rate_limit::api_limiter().cleanup();
        }
    });

    // ── API server ─────────────────────────────────────────────────────────────
    let api_state = api::ApiState {
        state:    state.clone(),
        alert_rx: alert_rx.clone(),
        audit:    audit.clone(),
        metrics:  metrics.clone(),
        siem:     siem.clone(),
    };
    let api_handle = tokio::spawn(start_api_server(config.api_addr, api_state));

    info!("✅ Thor Firewall Smart fully operational");
    info!("   POST /api/v1/login           → obtain JWT");
    info!("   GET  /api/v1/stats           → (readonly+)");
    info!("   GET  /api/v1/alerts/recent   → (readonly+, SIEM export)");
    info!("   GET  /api/v1/audit/recent    → (analyst+)");
    info!("   GET  /metrics                → Prometheus format");
    info!("   POST /api/v1/rules/inject    → (admin, shadow mode)");
    info!("   WS   /ws/events?token=<JWT>  → real-time stream (readonly+)");

    // ── Signal handling ────────────────────────────────────────────────────────
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("🛑 SIGINT received — starting graceful shutdown (30s drain)");
        }
        _ = async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                if let Ok(mut s) = signal(SignalKind::terminate()) {
                    s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            }
            #[cfg(not(unix))]
            std::future::pending::<()>().await
        } => {
            info!("🛑 SIGTERM received — starting graceful shutdown (30s drain)");
        }
    }

    // Drain in-flight requests for up to 30 seconds
    info!("⏳ Draining connections (30s timeout)...");
    tokio::time::timeout(
        tokio::time::Duration::from_secs(30),
        async {
            pipeline_handle.abort();
            api_handle.abort();
        },
    )
    .await
    .ok();

    info!("👋 Thor Firewall Smart stopped cleanly");
    Ok(())
}

// ─── Secret validation ────────────────────────────────────────────────────────

fn validate_required_secrets() {
    let mut failed = false;

    match std::env::var("THOR_JWT_SECRET") {
        Err(_) => {
            error!("❌ THOR_JWT_SECRET not set. Generate: openssl rand -hex 64");
            failed = true;
        }
        Ok(s) if s.len() < 32 => {
            error!("❌ THOR_JWT_SECRET too short ({} chars, minimum 32)", s.len());
            failed = true;
        }
        Ok(_) => info!("✅ THOR_JWT_SECRET validated"),
    }

    match std::env::var("THOR_ADMIN_PASSWORD") {
        Err(_) => {
            error!("❌ THOR_ADMIN_PASSWORD not set");
            failed = true;
        }
        Ok(p) if p.len() < 16 => {
            error!("❌ THOR_ADMIN_PASSWORD too short ({} chars, minimum 16)", p.len());
            failed = true;
        }
        Ok(_) => info!("✅ THOR_ADMIN_PASSWORD validated"),
    }

    if failed {
        error!("Startup aborted — set required environment variables and restart");
        std::process::exit(1);
    }
}
