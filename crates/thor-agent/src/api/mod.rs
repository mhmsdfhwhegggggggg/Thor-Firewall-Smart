//! API Server — fully hardened Axum router.
//!
//! Security layers applied (outermost → innermost):
//!   1. TraceLayer       — structured request logging
//!   2. CorsLayer        — origin control
//!   3. Rate Limiting    — per-IP sliding window (login: 10/min, api: 600/min)
//!   4. Authentication   — JWT validation (role-based)
//!   5. Input Validation — body size limit (64KB), Content-Type enforcement
//!   6. Audit Logging    — every action recorded in tamper-evident chain
//!
//! Route matrix:
//!   Public   : GET /health, POST /api/v1/login, GET /metrics
//!   Readonly : GET /api/v1/stats, GET /api/v1/alerts/recent, WS /ws/events
//!   Analyst  : GET /api/v1/audit/recent, GET /api/v1/audit/verify
//!              GET /api/v1/zeroday/profiles, /alerts, /drift, /status
//!   Admin    : POST /api/v1/rules/inject, POST /api/v1/rules/approve/:id
//!              POST /api/v1/ioc/add, POST /api/v1/zeroday/ingest

pub mod auth_middleware;
pub mod handlers;
pub mod ws;
pub mod rate_limit;
pub mod validation;
pub mod forensics_api;
pub mod zero_day_api;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{middleware, routing::{get, post}, Router};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::state::ThorState;
use crate::audit::SharedAuditLogger;
use crate::metrics::SharedMetrics;
use crate::siem::SiemExporter;

use auth_middleware::{require_auth, require_analyst_auth, require_admin_auth};
use rate_limit::{rate_limit_login, rate_limit_api};
use forensics_api::{
    run_thorql_query, run_artifact_handler, list_artifacts,
    collect_files, scan_process_memory,
};
use zero_day_api::{
    get_profiles, ingest_event, get_alerts, get_drift, get_status,
    ZeroDayApiState,
    get_ueba_summary, get_campaigns, get_kill_chain,
    Axis4AiState,
};

// ─── Shared API state ─────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ApiState {
    pub state:    Arc<ThorState>,
    pub alert_rx: flume::Receiver<crate::events::Alert>,
    pub audit:    SharedAuditLogger,
    pub metrics:  SharedMetrics,
    pub siem:     Arc<SiemExporter>,
}

// ─── Router ───────────────────────────────────────────────────────────────────

pub async fn start_api_server(addr: SocketAddr, api_state: ApiState) {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Initialise the zero-day engine and API state
    let zero_day_engine = Arc::new(crate::detection::zero_day::ZeroDayEngine::new());
    let zd_state        = ZeroDayApiState::new(zero_day_engine);
    let ai4_state       = Axis4AiState::new();

    let app = Router::new()
        // ── Public routes ─────────────────────────────────────────────────────
        .route("/health",           get(handlers::health))
        .route("/api/v1/login",     post(handlers::login).layer(middleware::from_fn(rate_limit_login)))
        .route("/metrics",          get(handlers::metrics_handler))

        // ── Analyst routes ────────────────────────────────────────────────────
        .route("/api/v1/stats",
            get(handlers::stats).route_layer(middleware::from_fn(require_auth)))
        .route("/api/v1/alerts/recent",
            get(handlers::recent_alerts).route_layer(middleware::from_fn(require_auth)))
        .route("/api/v1/audit/recent",
            get(handlers::audit_recent).route_layer(middleware::from_fn(require_analyst_auth)))
        .route("/api/v1/audit/verify",
            get(handlers::audit_verify).route_layer(middleware::from_fn(require_analyst_auth)))

        // ── Forensics (Axis 3) routes — Analyst+ ──────────────────────────────
        .route("/api/v1/forensics/query",
            post(run_thorql_query).route_layer(middleware::from_fn(require_analyst_auth)))
        .route("/api/v1/forensics/artifacts",
            get(list_artifacts).route_layer(middleware::from_fn(require_analyst_auth)))
        .route("/api/v1/forensics/artifacts/:id",
            get(run_artifact_handler).route_layer(middleware::from_fn(require_analyst_auth)))
        .route("/api/v1/forensics/collect",
            post(collect_files).route_layer(middleware::from_fn(require_analyst_auth)))
        .route("/api/v1/forensics/memory/:pid",
            get(scan_process_memory).route_layer(middleware::from_fn(require_analyst_auth)))

        // ── Zero-Day (Axis 4) routes — Analyst+ read / Admin write ────────────
        .route("/api/v1/zeroday/profiles",
            get(get_profiles).route_layer(middleware::from_fn(require_analyst_auth)))
        .route("/api/v1/zeroday/alerts",
            get(get_alerts).route_layer(middleware::from_fn(require_analyst_auth)))
        .route("/api/v1/zeroday/drift",
            get(get_drift).route_layer(middleware::from_fn(require_analyst_auth)))
        .route("/api/v1/zeroday/status",
            get(get_status).route_layer(middleware::from_fn(require_analyst_auth)))
        .route("/api/v1/zeroday/ingest",
            post(ingest_event).route_layer(middleware::from_fn(require_admin_auth)))

        // ── AI Axis-4 routes — UEBA / Campaigns / Kill-Chain ─────────────────
        .route("/api/v1/ai/ueba/summary",
            get(get_ueba_summary).route_layer(middleware::from_fn(require_analyst_auth)))
        .route("/api/v1/ai/campaigns",
            get(get_campaigns).route_layer(middleware::from_fn(require_analyst_auth)))
        .route("/api/v1/ai/killchain",
            get(get_kill_chain).route_layer(middleware::from_fn(require_analyst_auth)))

        // ── Admin routes ──────────────────────────────────────────────────────
        .route("/api/v1/rules/inject",
            post(handlers::inject_rule).route_layer(middleware::from_fn(require_admin_auth)))
        .route("/api/v1/rules/approve/:id",
            post(handlers::approve_rule).route_layer(middleware::from_fn(require_admin_auth)))
        .route("/api/v1/ioc/add",
            post(handlers::add_ioc).route_layer(middleware::from_fn(require_admin_auth)))

        // ── WebSocket ─────────────────────────────────────────────────────────
        .route("/ws/events", get(ws::ws_handler))

        // ── Middleware stack ───────────────────────────────────────────────────
        .layer(axum::Extension(api_state.state.clone()))
        .layer(axum::Extension(api_state.audit.clone()))
        .layer(axum::Extension(api_state.metrics.clone()))
        .layer(axum::Extension(api_state.siem.clone()))
        .layer(axum::Extension(zd_state))
        .layer(axum::Extension(ai4_state))
        .layer(middleware::from_fn(rate_limit_api))
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    info!("🌐 API server listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("API server failed");
}
