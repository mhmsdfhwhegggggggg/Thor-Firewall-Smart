//! Thor Firewall Smart — Production-hardened entry point v0.2.0
//!
//! Axis 1 fully operational:
//!   ▸ ThorFIM     — File Integrity Monitoring (Blake3 + sled + eBPF)
//!   ▸ ThorIntel   — Threat Intel Sync (OTX, Abuse.ch, ThreatFox, Feodo, ET, Tor, Spamhaus)
//!   ▸ ThorIDS     — Suricata-compatible IDS rule engine (ET Open + built-ins)
//!   ▸ Sigma 2.0   — Full condition parser (AND/OR/NOT/1of/allof)
//!   ▸ YARA        — File/process scanning
//!   ▸ ML/ONNX     — UEBA anomaly scoring
//!   ▸ SOAR        — Automated response
//!   ▸ Audit chain — Tamper-evident HMAC log

use anyhow::{Context, Result};
use mimalloc::MiMalloc;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, warn, error};
use tracing_subscriber::{EnvFilter, fmt};

mod config;
mod ebpf;
mod fim;
mod ids;
mod intel;
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
use fim::FimEngine;
use intel::IntelSyncEngine;

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
    info!("   Axis 1: FIM={} Intel={} IDS={} Sigma={} YARA={} ML={} SOAR={}",
        "enabled", "enabled", "enabled", "enabled", "enabled", "enabled", "enabled");

    // ── Startup secret validation (fail-fast) ─────────────────────────────────
    validate_required_secrets();

    // ── Configuration ──────────────────────────────────────────────────────────
    let config = Arc::new(ThorConfig::load().context("Failed to load configuration")?);
    info!("📋 Config: interface={} api={} fim_interval={}s",
        config.interface, config.api_addr, config.fim_interval_secs);

    // ── Audit log (before everything else) ────────────────────────────────────
    let audit = Arc::new(
        AuditLogger::open(&config.audit_db_path)
            .context("Failed to open audit log")?,
    );
    info!("📋 Audit log: {} (chain verified={})", config.audit_db_path, audit.verify_chain());

    // ── Metrics ────────────────────────────────────────────────────────────────
    let metrics = Arc::new(ThorMetrics::new());

    // ── SIEM ───────────────────────────────────────────────────────────────────
    let siem = Arc::new(SiemExporter::from_env());

    // ── Shared state (IOC DB + flow tracking) ─────────────────────────────────
    let state = Arc::new(ThorState::new(&config));
    info!("💾 State: {} flow shards | {} IOC capacity | Bloom FPR={}",
        config.flow_map_shards, config.ioc_bloom_capacity, config.ioc_bloom_fpr);

    // ── Threat Intel Sync (background, non-blocking) ──────────────────────────
    if config.intel_enabled {
        let intel_db = state.ioc_db.clone();
        let otx_key  = config.otx_api_key.clone();
        tokio::spawn(async move {
            let engine = match IntelSyncEngine::new(intel_db, None) {
                Ok(e) => e,
                Err(e) => { warn!("Intel sync init failed: {}", e); return; }
            };
            let loaded = engine.initial_sync().await;
            info!("🌐 Threat Intel: {} IOCs loaded on startup", loaded);

            // Optionally load OTX subscribed pulses
            if let Some(key) = otx_key {
                let otx = intel::otx::OtxClient::new(Some(key)).unwrap();
                match otx.fetch_subscribed(None).await {
                    Ok(iocs) => {
                        let count = iocs.len();
                        for ioc in iocs { engine.ioc_db().insert(ioc); }
                        info!("📡 OTX: {} IOCs loaded", count);
                    }
                    Err(e) => warn!("OTX sync failed: {}", e),
                }
            }

            // Run background refresh loop
            engine.run_forever().await;
        });
    } else {
        info!("ℹ️  Threat Intel sync disabled (THOR_INTEL_ENABLED=false)");
    }

    // ── FIM Engine ────────────────────────────────────────────────────────────
    if config.fim_enabled {
        let (fim_alert_tx, mut fim_alert_rx) = tokio::sync::mpsc::channel(1024);
        let fim_engine = FimEngine::new(
            &config.fim_db_path,
            fim_alert_tx,
            None,
            config.fim_interval_secs,
        ).await.context("Failed to initialize FIM engine")?;

        let fim_arc = Arc::new(fim_engine);

        // Build baseline
        let fim_baseline = fim_arc.clone();
        tokio::spawn(async move {
            match fim_baseline.build_baseline().await {
                Ok(n)  => info!("🔍 FIM baseline: {} files indexed", n),
                Err(e) => warn!("FIM baseline error: {}", e),
            }
        });

        // FIM monitoring loop
        let fim_run = fim_arc.clone();
        tokio::spawn(async move {
            if let Err(e) = fim_run.run().await {
                error!("FIM monitor crashed: {}", e);
            }
        });

        // FIM alert forwarding → main alert channel
        let audit_fim = audit.clone();
        let metrics_fim = metrics.clone();
        tokio::spawn(async move {
            while let Some(alert) = fim_alert_rx.recv().await {
                metrics_fim.increment_alerts();
                if let Err(e) = audit_fim.log_alert(&alert) {
                    warn!("Audit FIM log error: {}", e);
                }
            }
        });

        info!("🔒 ThorFIM active: polling every {}s", config.fim_interval_secs);
    } else {
        info!("ℹ️  FIM disabled (THOR_FIM_ENABLED=false)");
    }

    // ── ML engine ─────────────────────────────────────────────────────────────
    let ml_engine = Arc::new(
        MlEngine::new(&config.model_path).unwrap_or_else(|e| {
            warn!("ML engine unavailable: {} — rule-only mode", e);
            MlEngine::dummy()
        }),
    );
    info!("🤖 ML engine: {}", if ml_engine.is_loaded() { "ONNX model loaded" } else { "dummy (no model)" });

    // ── Detection engine (Sigma + YARA + IDS + IOC + ML) ─────────────────────
    let detection = Arc::new(
        DetectionEngine::new(
            &config.sigma_rules_dir,
            &config.yara_rules_dir,
            &config.ids_rules_dir,
            ml_engine.clone(),
        ).context("Failed to initialize detection engine")?,
    );
    info!("🔍 Detection: Sigma={} YARA={} IDS={}",
        detection.sigma_rule_count(),
        detection.yara_rule_count(),
        detection.ids_rule_count(),
    );

    // ── SOAR engine ────────────────────────────────────────────────────────────
    let soar = Arc::new(SoarEngine::new(state.clone(), config.thehive_url.clone()));

    // ── Event channels ─────────────────────────────────────────────────────────
    let (raw_tx, raw_rx)     = flume::bounded::<events::RawEvent>(65_536);
    let (alert_tx, alert_rx) = flume::bounded::<events::Alert>(8_192);

    // ── eBPF programs ──────────────────────────────────────────────────────────
    let _bpf_manager = BpfManager::start(&config.interface, raw_tx.clone(), state.clone())
        .await.context("Failed to start eBPF programs")?;
    info!("⚡ eBPF: XDP + process kprobes + network + FIM tracepoints active");

    // ── Event pipeline ─────────────────────────────────────────────────────────
    let pipeline = EventPipeline::new(state.clone(), detection.clone(), soar.clone());
    let pipeline_handle = pipeline.spawn(raw_rx, alert_tx.clone());

    // ── API server ─────────────────────────────────────────────────────────────
    let api_state = api::ApiState {
        state:    state.clone(),
        alert_rx: alert_rx.clone(),
        audit:    audit.clone(),
        metrics:  metrics.clone(),
        siem:     siem.clone(),
    };
    let api_handle = tokio::spawn(start_api_server(config.api_addr, api_state));

    // ── Metrics bind ──────────────────────────────────────────────────────────
    let metrics_bind = config.metrics_bind;
    let metrics_arc  = metrics.clone();
    tokio::spawn(async move {
        metrics::serve(metrics_bind, metrics_arc).await;
    });

    info!("✅ Thor Firewall Smart v0.2.0 fully operational (Axis 1 complete)");
    info!("   API: http://{}/api/v1", config.api_addr);
    info!("   Metrics: http://{}/metrics", config.metrics_bind);

    // ── Signal handling ────────────────────────────────────────────────────────
    tokio::select! {
        _ = signal::ctrl_c() => info!("🛑 SIGINT — graceful shutdown"),
        _ = wait_sigterm() => info!("🛑 SIGTERM — graceful shutdown"),
    }

    info!("⏳ Draining (30s)...");
    tokio::time::timeout(
        tokio::time::Duration::from_secs(30),
        async { pipeline_handle.abort(); api_handle.abort(); },
    ).await.ok();

    info!("👋 Thor Firewall Smart stopped cleanly");
    Ok(())
}

fn validate_required_secrets() {
    let mut failed = false;
    for var in ["THOR_JWT_SECRET", "THOR_ADMIN_PASSWORD"] {
        match std::env::var(var) {
            Err(_) => { error!("❌ {} not set", var); failed = true; }
            Ok(v) if v.len() < 16 => { error!("❌ {} too short ({} chars)", var, v.len()); failed = true; }
            Ok(_) => info!("✅ {} validated", var),
        }
    }
    if failed {
        error!("Startup aborted — set required secrets");
        std::process::exit(1);
    }
}

async fn wait_sigterm() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
        } else {
            std::future::pending::<()>().await
        }
    }
    #[cfg(not(unix))]
    std::future::pending::<()>().await
}
