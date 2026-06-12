//! REST API handlers — health, stats, alerts

use axum::{extract::State, Json, http::StatusCode};
use serde::Serialize;
use std::sync::atomic::Ordering;
use utoipa::ToSchema;
use crate::api::ApiState;
use crate::state::StateStats;
use crate::events::Alert;

/// Health check response
#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
}

static START_TIME: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// GET /health — Kubernetes/LB readiness probe
#[utoipa::path(get, path = "/health", responses((status = 200, body = HealthResponse)))]
pub async fn health() -> Json<HealthResponse> {
    let start = START_TIME.get_or_init(std::time::Instant::now);
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: start.elapsed().as_secs(),
    })
}

/// GET /api/v1/stats — live statistics
#[utoipa::path(get, path = "/api/v1/stats", responses((status = 200, body = StateStats)))]
pub async fn get_stats(State(api): State<ApiState>) -> Json<StateStats> {
    Json(api.state.stats())
}

/// GET /api/v1/alerts/recent — last 50 alerts
#[utoipa::path(get, path = "/api/v1/alerts/recent", responses((status = 200, body = Vec<Alert>)))]
pub async fn get_recent_alerts(State(api): State<ApiState>) -> Json<Vec<Alert>> {
    let mut alerts = Vec::with_capacity(50);
    while let Ok(alert) = api.alert_rx.try_recv() {
        alerts.push(alert);
        if alerts.len() >= 50 { break; }
    }
    alerts.reverse(); // Most recent first
    Json(alerts)
}
