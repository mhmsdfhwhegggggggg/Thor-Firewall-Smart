//! API Server — Axum router with full authentication on every protected route.
//! Public:    GET /health
//! Readonly:  GET /api/v1/stats, GET /api/v1/alerts/recent     (any valid JWT)
//! Analyst:   GET /api/v1/audit/recent                         (analyst+)
//! Admin:     POST /api/v1/rules/inject, POST /api/v1/ioc/*    (admin only)
//!            POST /api/v1/login                               (public, issues token)

pub mod auth_middleware;
pub mod handlers;
pub mod ws;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::state::ThorState;
use crate::audit::SharedAuditLogger;
use auth_middleware::{require_auth, require_analyst_auth, require_admin_auth};

// ─── Shared API state ─────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ApiState {
    pub state: Arc<ThorState>,
    pub alert_rx: flume::Receiver<crate::events::Alert>,
    pub audit: SharedAuditLogger,
}

// ─── Router construction ──────────────────────────────────────────────────────

pub async fn start_api_server(addr: SocketAddr, api_state: ApiState) {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        // ── Public ────────────────────────────────────────────────────────────
        .route("/health", get(handlers::health))
        .route("/api/v1/login", post(handlers::login))

        // ── Readonly (any valid JWT) ───────────────────────────────────────────
        .route(
            "/api/v1/stats",
            get(handlers::get_stats)
                .route_layer(middleware::from_fn(require_auth)),
        )
        .route(
            "/api/v1/alerts/recent",
            get(handlers::get_recent_alerts)
                .route_layer(middleware::from_fn(require_auth)),
        )

        // ── Analyst + Admin ───────────────────────────────────────────────────
        .route(
            "/api/v1/audit/recent",
            get(handlers::get_audit_log)
                .route_layer(middleware::from_fn(require_analyst_auth)),
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
                .route_layer(middleware::from_fn(require_admin_auth)),
        )
        .route(
            "/api/v1/rules/approve/:rule_id",
            post(handlers::approve_rule)
                .route_layer(middleware::from_fn(require_admin_auth)),
        )
        .route(
            "/api/v1/ioc/add",
            post(handlers::add_ioc)
                .route_layer(middleware::from_fn(require_admin_auth)),
        )

        // ── WebSocket (token required as query param ?token=<JWT>) ────────────
        .route("/ws/events", get(ws::ws_handler))

        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(api_state);

    info!("🌐 API server on {} — auth enforced on all routes", addr);
    let listener = tokio::net::TcpListener::bind(addr).await
        .expect("Failed to bind API server");
    axum::serve(listener, app).await.expect("API server failed");
}
