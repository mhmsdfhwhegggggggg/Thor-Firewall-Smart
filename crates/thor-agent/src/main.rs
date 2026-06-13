//! Thor Firewall Smart — Main agent entry point
//! Security hardened:
//!   - JWT secret loaded from THOR_JWT_SECRET env var (panics if missing)
//!   - Immutable audit log initialized before API server starts
//!   - All API routes require authentication
//!   - AI rules enter shadow mode and need human approval

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

    // ── Validate required environment variables early ─────────────────────────
    if std::env::var("THOR_JWT_SECRET").is_err() {
        error!("❌ THOR_JWT_SECRET is not set. Generate with: openssl rand -hex 64");
        std::process::exit(1);
    }
    if std::env::var("THOR_ADMIN_PASSWORD")
        .map(|p| p.len() < 16)
        .unwrap_or(true)
    {
        error!("❌ THOR_ADMIN_PASSWORD is not set or too short (minimum 16 chars)");
        std::process::exit(1);
    }

    // ── Configuration ──────────────────────────────────────────────────────────
    let config = ThorConfig::load().context("Failed to load configuration")?;
    info!("📋 Config loaded: interface={}", config.interface);

    // ── Audit log (must start before API) ────────────────────────────────────
    let audit_path = std::env::var("THOR_AUDIT_DB_PATH")
        .unwrap_or_else(|_| "/var/lib/thor/audit.db".to_string());
    let audit = Arc::new(
        AuditLogger::open(&audit_path)
            .context("Failed to open audit log — check THOR_AUDIT_DB_PATH permissions")?,
    );
    info!("📋 Audit log ready: {}", audit_path);

    // ── Shared state ───────────────────────────────────────────────────────────
    let state = Arc::new(ThorState::new(&config));
    info!(
        "💾 State initialized: {} flow shards, {} IOC capacity",
        config.flow_map_shards, config.ioc_bloom_capacity
    );

    // ── ML engine (graceful degradation if model not present) ─────────────────
    let ml_engine = Arc::new(
        MlEngine::new(&config.model_path)
            .unwrap_or_else(|e| {
                warn!("ML engine unavailable ({}), using rule-only mode", e);
                MlEngine::dummy()
            }),
    );

    // ── Detection engine ───────────────────────────────────────────────────────
    let detection = Arc::new(
        DetectionEngine::new(
            &config.sigma_rules_dir,
            &config.yara_rules_dir,
            ml_engine.clone(),
        )
        .context("Failed to initialize detection engine")?,
    );
    info!(
        "🔍 Detection engine: {} Sigma rules, {} YARA rules",
        detection.sigma_rule_count(),
        detection.yara_rule_count()
    );

    // ── SOAR engine ────────────────────────────────────────────────────────────
    let soar = Arc::new(SoarEngine::new(state.clone(), config.thehive_url.clone()));

    // ── Event pipeline channels ────────────────────────────────────────────────
    let (raw_tx, raw_rx) = flume::bounded::<events::RawEvent>(65_536);
    let (alert_tx, alert_rx) = flume::bounded::<events::Alert>(8_192);

    // ── eBPF programs ──────────────────────────────────────────────────────────
    let bpf_manager = BpfManager::start(
        &config.interface,
        raw_tx.clone(),
        state.clone(),
    )
    .await
    .context("Failed to start eBPF programs")?;
    info!("⚡ eBPF programs active: XDP (IPv4+IPv6) + tracepoints + kprobes");

    // ── Event pipeline ─────────────────────────────────────────────────────────
    let pipeline = EventPipeline::new(state.clone(), detection.clone(), soar.clone());
    let pipeline_handle = pipeline.spawn(raw_rx, alert_tx.clone());

    // ── API server (authentication + audit enforced) ───────────────────────────
    let api_state = api::ApiState {
        state: state.clone(),
        alert_rx: alert_rx.clone(),
        audit: audit.clone(),
    };
    let api_handle = tokio::spawn(start_api_server(config.api_addr, api_state));
    info!("🌐 API server on {} — JWT auth + RBAC + audit enabled", config.api_addr);
    info!("   POST /api/v1/login        → obtain JWT token");
    info!("   GET  /api/v1/stats        → (readonly+)");
    info!("   GET  /api/v1/alerts/recent → (readonly+)");
    info!("   GET  /api/v1/audit/recent  → (analyst+)");
    info!("   POST /api/v1/rules/inject  → (admin only, shadow mode)");

    info!("✅ Thor Firewall Smart is fully operational");

    // ── Graceful shutdown ──────────────────────────────────────────────────────
    match signal::ctrl_c().await {
        Ok(()) => info!("🛑 Shutdown signal received"),
        Err(e) => error!("Signal handler error: {}", e),
    }

    pipeline_handle.abort();
    api_handle.abort();
    info!("👋 Thor Firewall Smart stopped cleanly");
    Ok(())
}
