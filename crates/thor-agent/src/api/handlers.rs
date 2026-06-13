//! REST API handlers — all security actions are audit-logged.

use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use tracing::warn;
use utoipa::ToSchema;

use crate::api::{auth_middleware::{Claims, ThorRole, generate_token}, ApiState};
use crate::audit::{AuditAction, AuditResult};
use crate::events::Alert;
use crate::state::StateStats;

// ─── Health ───────────────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
}

static START_TIME: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

pub async fn health() -> Json<HealthResponse> {
    let start = START_TIME.get_or_init(std::time::Instant::now);
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: start.elapsed().as_secs(),
    })
}

// ─── Login (issues JWT) ───────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
    pub role: String,
    pub expires_in_hours: u64,
}

pub async fn login(
    State(api): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let source_ip = extract_source_ip(&headers);

    let admin_user = std::env::var("THOR_ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_string());
    let admin_pass = std::env::var("THOR_ADMIN_PASSWORD").unwrap_or_default();

    if admin_pass.is_empty() {
        warn!("⚠️  THOR_ADMIN_PASSWORD not set — login disabled");
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let (sub, role) = if body.username == admin_user && body.password == admin_pass {
        (body.username.clone(), ThorRole::Admin)
    } else {
        api.audit.log(
            &body.username, "anonymous",
            AuditAction::LoginFailed,
            "login", AuditResult::Failure,
            &source_ip, "Invalid credentials",
        );
        warn!("🔐 Login failed for user '{}' from {}", body.username, source_ip);
        return Err(StatusCode::UNAUTHORIZED);
    };

    let expiry_hours: u64 = std::env::var("THOR_JWT_EXPIRY_HOURS")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(8);

    match generate_token(&sub, role.clone()) {
        Ok(token) => {
            api.audit.log(
                &sub, &format!("{:?}", role),
                AuditAction::Login,
                "login", AuditResult::Success,
                &source_ip, "Authenticated",
            );
            Ok(Json(LoginResponse {
                token,
                role: format!("{:?}", role),
                expires_in_hours: expiry_hours,
            }))
        }
        Err(e) => {
            warn!("Token generation failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ─── Stats (Readonly) ─────────────────────────────────────────────────────────

pub async fn get_stats(
    State(api): State<ApiState>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
) -> Json<StateStats> {
    api.audit.log(
        &claims.sub, &format!("{:?}", claims.role),
        AuditAction::ApiAccess,
        "/api/v1/stats", AuditResult::Success,
        &extract_source_ip(&headers), "",
    );
    Json(api.state.stats())
}

// ─── Alerts (Readonly) ────────────────────────────────────────────────────────

pub async fn get_recent_alerts(
    State(api): State<ApiState>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
) -> Json<Vec<Alert>> {
    let mut alerts = Vec::with_capacity(50);
    while let Ok(alert) = api.alert_rx.try_recv() {
        alerts.push(alert);
        if alerts.len() >= 50 { break; }
    }
    alerts.reverse();

    api.audit.log(
        &claims.sub, &format!("{:?}", claims.role),
        AuditAction::ApiAccess,
        "/api/v1/alerts/recent", AuditResult::Success,
        &extract_source_ip(&headers),
        &format!("returned {} alerts", alerts.len()),
    );
    Json(alerts)
}

// ─── Audit Log (Analyst+) ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuditQuery {
    pub limit: Option<usize>,
}

pub async fn get_audit_log(
    State(api): State<ApiState>,
    Extension(claims): Extension<Claims>,
) -> Json<Vec<crate::audit::AuditEntry>> {
    let entries = api.audit.recent(100);
    api.audit.log(
        &claims.sub, &format!("{:?}", claims.role),
        AuditAction::AlertExported,
        "audit_log", AuditResult::Success,
        "internal", &format!("exported {} entries", entries.len()),
    );
    Json(entries)
}

pub async fn verify_audit_chain(
    State(api): State<ApiState>,
    Extension(claims): Extension<Claims>,
) -> Json<serde_json::Value> {
    let intact = api.audit.verify_chain();
    api.audit.log(
        &claims.sub, &format!("{:?}", claims.role),
        AuditAction::ApiAccess,
        "audit_chain_verify",
        if intact { AuditResult::Success } else { AuditResult::Failure },
        "internal", "",
    );
    Json(serde_json::json!({ "chain_intact": intact }))
}

// ─── Rule Injection (Admin only) ──────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct InjectRuleRequest {
    pub yaml_content: String,
    pub title: String,
}

pub async fn inject_rule(
    State(api): State<ApiState>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
    Json(body): Json<InjectRuleRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let source_ip = extract_source_ip(&headers);

    let result = api.state.sigma_engine
        .read()
        .await
        .ingest_llm_rule(
            uuid::Uuid::new_v4().to_string(),
            body.yaml_content,
            body.title.clone(),
        )
        .await;

    match result {
        Ok(_) => {
            api.audit.log(
                &claims.sub, &format!("{:?}", claims.role),
                AuditAction::RuleInjected,
                &body.title, AuditResult::Success,
                &source_ip, "Entered shadow mode, awaiting human approval",
            );
            Ok(Json(serde_json::json!({
                "status": "shadow_mode",
                "message": "Rule entered 1-hour shadow observation. Use /api/v1/rules/approve/:id to enforce."
            })))
        }
        Err(e) => {
            api.audit.log(
                &claims.sub, &format!("{:?}", claims.role),
                AuditAction::RuleRejected,
                &body.title, AuditResult::Failure,
                &source_ip, &e,
            );
            warn!("Rule injection rejected: {}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

pub async fn approve_rule(
    State(api): State<ApiState>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
    Path(rule_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let source_ip = extract_source_ip(&headers);
    let engine = api.state.sigma_engine.read().await;

    let result = engine.guardian
        .human_approve_rule(&rule_id, &engine.dynamic_rules)
        .await;

    match result {
        Ok(_) => {
            api.audit.log(
                &claims.sub, &format!("{:?}", claims.role),
                AuditAction::RuleApproved,
                &rule_id, AuditResult::Success,
                &source_ip, "Rule promoted to enforcement",
            );
            Ok(Json(serde_json::json!({ "status": "enforced", "rule_id": rule_id })))
        }
        Err(e) => {
            api.audit.log(
                &claims.sub, &format!("{:?}", claims.role),
                AuditAction::RuleRejected,
                &rule_id, AuditResult::Failure,
                &source_ip, &e,
            );
            Err(StatusCode::NOT_FOUND)
        }
    }
}

// ─── IOC Management (Admin only) ─────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct AddIocRequest {
    pub value: String,
    pub ioc_type: String,
    pub source: String,
}

pub async fn add_ioc(
    State(api): State<ApiState>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
    Json(body): Json<AddIocRequest>,
) -> Json<serde_json::Value> {
    api.audit.log(
        &claims.sub, &format!("{:?}", claims.role),
        AuditAction::IocAdded,
        &body.value, AuditResult::Success,
        &extract_source_ip(&headers),
        &format!("type={} source={}", body.ioc_type, body.source),
    );
    Json(serde_json::json!({ "status": "added", "ioc": body.value }))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn extract_source_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}
