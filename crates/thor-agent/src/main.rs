//! Thor Firewall Smart — Main agent entry point
//! Orchestrates: eBPF programs, event pipeline, detection engine, SOAR, API server

use anyhow::{Context, Result};
use mimalloc::MiMalloc;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, warn, error};
use tracing_subscriber::{EnvFilter, fmt};

// Sub-modules
mod config;
mod ebpf;
mod state;
mod events;
mod detection;
mod soar;
mod ml;
mod api;

use config::ThorConfig;
use ebpf::BpfManager;
use state::ThorState;
use events::pipeline::EventPipeline;
use detection::DetectionEngine;
use soar::SoarEngine;
use ml::MlEngine;
use api::start_api_server;

// Global allocator — 20-30% faster allocation
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    // Initialize structured logging
    fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("thor_agent=info".parse()?)
            .add_directive("aya=warn".parse()?))
        .json()
        .init();

    info!("🛡️  Thor Firewall Smart v{} starting...", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = ThorConfig::load().context("Failed to load configuration")?;
    info!("📋 Configuration loaded: interface={}", config.interface);

    // Initialize shared state
    let state = Arc::new(ThorState::new(&config));
    info!("💾 State initialized: {} flow shards, {} IOC capacity",
        config.flow_map_shards, config.ioc_bloom_capacity);

    // Load ML engine
    let ml_engine = Arc::new(
        MlEngine::new(&config.model_path)
            .unwrap_or_else(|e| { warn!("ML engine unavailable ({}), using rule-only mode", e); MlEngine::dummy() })
    );

    // Load detection engine (Sigma + YARA + IOC)
    let detection = Arc::new(
        DetectionEngine::new(&config.sigma_rules_dir, &config.yara_rules_dir, ml_engine.clone())
            .context("Failed to initialize detection engine")?
    );
    info!("🔍 Detection engine: {} Sigma rules, {} YARA rules",
        detection.sigma_rule_count(), detection.yara_rule_count());

    // Initialize SOAR engine
    let soar = Arc::new(SoarEngine::new(state.clone(), config.thehive_url.clone()));

    // Setup event pipeline channels (flume — 30-50% faster than tokio::mpsc)
    let (raw_tx, raw_rx) = flume::bounded::<events::RawEvent>(65_536);
    let (alert_tx, alert_rx) = flume::bounded::<events::Alert>(8_192);

    // Start eBPF program manager
    let bpf_manager = BpfManager::start(
        &config.interface,
        raw_tx.clone(),
        state.clone(),
    ).await.context("Failed to start eBPF programs")?;
    info!("⚡ eBPF programs active: XDP + tracepoints + kprobes");

    // Start event processing pipeline
    let pipeline = EventPipeline::new(state.clone(), detection.clone(), soar.clone());
    let pipeline_handle = pipeline.spawn(raw_rx, alert_tx.clone());

    // Start API server
    let api_state = api::ApiState { state: state.clone(), alert_rx: alert_rx.clone() };
    let api_handle = tokio::spawn(start_api_server(config.api_addr, api_state));
    info!("🌐 API server listening on {}", config.api_addr);

    info!("✅ Thor Firewall Smart is fully operational");
    info!("   📊 Dashboard: http://{}/swagger-ui", config.api_addr);
    info!("   📡 WebSocket: ws://{}/ws/events", config.api_addr);

    // Wait for shutdown signal
    match signal::ctrl_c().await {
        Ok(()) => info!("🛑 Shutdown signal received, stopping..."),
        Err(e) => error!("Signal handler error: {}", e),
    }

    // Graceful shutdown
    pipeline_handle.abort();
    api_handle.abort();
    info!("👋 Thor Firewall Smart stopped cleanly");
    Ok(())
}
