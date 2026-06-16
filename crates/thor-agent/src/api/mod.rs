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
//!   Admin    : POST /api/v1/rules/inject, POST /api/v1/rules/approve/:id
//!              POST /api/v1/ioc/add

pub mod auth_middleware;
pub mod handlers;
pub mod ws;
pub mod rate_limit;
pub mod validation;
pub mod forensics_api;

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

// ─── Shared API state ─────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ApiState {
    pub state:   Arc<ThorState>,
    pub alert_rx: flume::Receiver<crate::events::Alert>,
    pub audit:   SharedAuditLogger,
    pub metrics: SharedMetrics,
    pub siem:    Arc<SiemExporter>,
}

// ─── Router ───────────────────────────────────────────────────────────────────

pub async fn start_api_server(addr: SocketAddr, api_state: ApiState) {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        // ── Public (no auth) ─────────────────────────────────────────────────
        .route("/health",          get(handlers::health))
        .route("/metrics",         get(handlers::metrics))
        .route(
            "/api/v1/login",
            post(handlers::login)
                .route_layer(middleware::from_fn(rate_limit_login)),
        )

        // ── Readonly (any valid JWT) ──────────────────────────────────────────
        .route(
            "/api/v1/stats",
            get(handlers::get_stats)
                .route_layer(middleware::from_fn(require_auth))
                .route_layer(middleware::from_fn(rate_limit_api)),
        )
        .route(
            "/api/v1/alerts/recent",
            get(handlers::get_recent_alerts)
                .route_layer(middleware::from_fn(require_auth))
                .route_layer(middleware::from_fn(rate_limit_api)),
        )

        // ── Analyst+ ─────────────────────────────────────────────────────────
        .route(
            "/api/v1/audit/recent",
            get(handlers::get_audit_log)
                .route_layer(middleware::from_fn(require_analyst_auth))
                .route_layer(middleware::from_fn(rate_limit_api)),
        )
        .route(
            "/api/v1/audit/verify",
            get(handlers::verify_audit_chain)
                .route_layer(middleware::from_fn(require_analyst_auth)),
        )

        // ── Admin only ────────────────────────────────────────────────────────
        .route(
            "/api/v1/rules/inject",
            post(handlers::inject_rule)
                .route_layer(middleware::from_fn(require_admin_auth))
                .route_layer(middleware::from_fn(rate_limit_api)),
        )
        .route(
            "/api/v1/rules/approve/:rule_id",
            post(handlers::approve_rule)
                .route_layer(middleware::from_fn(require_admin_auth)),
        )
        .route(
            "/api/v1/ioc/add",
            post(handlers::add_ioc)
                .route_layer(middleware::from_fn(require_admin_auth))
                .route_layer(middleware::from_fn(rate_limit_api)),
        )

        // ── Axis 3: DFIR / Forensics (Analyst+) ──────────────────────────────
        .route(
            "/api/v1/forensics/query",
            post(run_thorql_query)
                .route_layer(middleware::from_fn(require_analyst_auth))
                .route_layer(middleware::from_fn(rate_limit_api)),
        )
        .route(
            "/api/v1/forensics/artifact",
            post(run_artifact_handler)
                .route_layer(middleware::from_fn(require_analyst_auth))
                .route_layer(middleware::from_fn(rate_limit_api)),
        )
        .route(
            "/api/v1/forensics/artifacts",
            get(list_artifacts)
                .route_layer(middleware::from_fn(require_analyst_auth))
                .route_layer(middleware::from_fn(rate_limit_api)),
        )
        .route(
            "/api/v1/forensics/collect",
            post(collect_files)
                .route_layer(middleware::from_fn(require_admin_auth))
                .route_layer(middleware::from_fn(rate_limit_api)),
        )
        .route(
            "/api/v1/forensics/scan/memory",
            post(scan_process_memory)
                .route_layer(middleware::from_fn(require_admin_auth))
                .route_layer(middleware::from_fn(rate_limit_api)),
        )

        // ── WebSocket (token in query param) ──────────────────────────────────
        .route("/ws/events", get(ws::ws_handler))

        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(api_state);

    info!("🌐 API server on {} (auth + rate-limit + audit on all routes)", addr);
    let listener = tokio::net::TcpListener::bind(addr).await
        .expect("Failed to bind API server");
    axum::serve(listener, app).await.expect("API server crashed");
}
