//! REST API handlers — every state-changing action is audit-logged.

use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::warn;
use utoipa::ToSchema;

use crate::api::{
    auth_middleware::{Claims, ThorRole, generate_token},
    validation::{ValidatedJson, sanitize_string},
    ApiState,
};
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

static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

pub async fn health() -> Json<HealthResponse> {
    let start = START.get_or_init(std::time::Instant::now);
    Json(HealthResponse {
        status: "healthy".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        uptime_secs: start.elapsed().as_secs(),
    })
}

// ─── Prometheus Metrics (public, no auth) ─────────────────────────────────────

pub async fn metrics(State(api): State<ApiState>) -> impl IntoResponse {
    let body = api.metrics.render(&api.state);
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

// ─── Login ────────────────────────────────────────────────────────────────────

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
    ValidatedJson(body): ValidatedJson<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let source_ip = extract_source_ip(&headers);
    let username  = sanitize_string(&body.username);

    let admin_user = std::env::var("THOR_ADMIN_USERNAME").unwrap_or_else(|_| "admin".into());
    let admin_pass = std::env::var("THOR_ADMIN_PASSWORD").unwrap_or_default();

    if admin_pass.is_empty() {
        warn!("⚠️  THOR_ADMIN_PASSWORD not set");
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let (sub, role) = if username == admin_user && body.password == admin_pass {
        (username.clone(), ThorRole::Admin)
    } else {
        api.audit.log(
            &username, "anonymous", AuditAction::LoginFailed,
            "login", AuditResult::Failure, &source_ip, "Invalid credentials",
        );
        warn!("🔐 Login failed: user='{}' ip={}", username, source_ip);
        return Err(StatusCode::UNAUTHORIZED);
    };

    let expiry_hours: u64 = std::env::var("THOR_JWT_EXPIRY_HOURS")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(8);

    match generate_token(&sub, role.clone()) {
        Ok(token) => {
            api.audit.log(
                &sub, &format!("{:?}", role), AuditAction::Login,
                "login", AuditResult::Success, &source_ip, "Authenticated",
            );
            api.metrics.endpoint_counter.inc("/api/v1/login", 200);
            Ok(Json(LoginResponse { token, role: format!("{:?}", role), expires_in_hours: expiry_hours }))
        }
        Err(e) => { warn!("Token gen failed: {}", e); Err(StatusCode::INTERNAL_SERVER_ERROR) }
    }
}

// ─── Stats ────────────────────────────────────────────────────────────────────

pub async fn get_stats(
    State(api): State<ApiState>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
) -> Json<StateStats> {
    api.audit.log(
        &claims.sub, &format!("{:?}", claims.role), AuditAction::ApiAccess,
        "/api/v1/stats", AuditResult::Success, &extract_source_ip(&headers), "",
    );
    api.metrics.endpoint_counter.inc("/api/v1/stats", 200);
    Json(api.state.stats())
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

pub async fn get_recent_alerts(
    State(api): State<ApiState>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
) -> Json<Vec<Alert>> {
    let mut alerts = Vec::with_capacity(50);
    while let Ok(alert) = api.alert_rx.try_recv() {
        // Export to SIEM asynchronously
        let siem = api.siem.clone();
        let a = alert.clone();
        tokio::spawn(async move { let _ = siem.send(&a).await; });

        alerts.push(alert);
        if alerts.len() >= 50 { break; }
    }
    alerts.reverse();

    api.audit.log(
        &claims.sub, &format!("{:?}", claims.role), AuditAction::ApiAccess,
        "/api/v1/alerts/recent", AuditResult::Success,
        &extract_source_ip(&headers), &format!("{} alerts", alerts.len()),
    );
    api.metrics.endpoint_counter.inc("/api/v1/alerts/recent", 200);
    Json(alerts)
}

// ─── Audit Log ────────────────────────────────────────────────────────────────

pub async fn get_audit_log(
    State(api): State<ApiState>,
    Extension(claims): Extension<Claims>,
) -> Json<Vec<crate::audit::AuditEntry>> {
    let entries = api.audit.recent(200);
    api.audit.log(
        &claims.sub, &format!("{:?}", claims.role), AuditAction::AlertExported,
        "audit_log", AuditResult::Success, "internal",
        &format!("exported {} entries", entries.len()),
    );
    Json(entries)
}

pub async fn verify_audit_chain(
    State(api): State<ApiState>,
    Extension(claims): Extension<Claims>,
) -> Json<serde_json::Value> {
    let intact = api.audit.verify_chain();
    api.audit.log(
        &claims.sub, &format!("{:?}", claims.role), AuditAction::ApiAccess,
        "audit_chain_verify",
        if intact { AuditResult::Success } else { AuditResult::Failure },
        "internal", "",
    );
    Json(serde_json::json!({ "chain_intact": intact, "timestamp": chrono::Utc::now() }))
}

// ─── Rule Management ──────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct InjectRuleRequest {
    pub yaml_content: String,
    pub title: String,
}

pub async fn inject_rule(
    State(api): State<ApiState>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
    ValidatedJson(body): ValidatedJson<InjectRuleRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let source_ip = extract_source_ip(&headers);
    let title = sanitize_string(&body.title);
    let yaml  = sanitize_string(&body.yaml_content);

    let result = api.state.sigma_engine
        .read().await
        .ingest_llm_rule(uuid::Uuid::new_v4().to_string(), yaml, title.clone())
        .await;

    match result {
        Ok(_) => {
            api.audit.log(
                &claims.sub, &format!("{:?}", claims.role), AuditAction::RuleInjected,
                &title, AuditResult::Success, &source_ip,
                "Entered shadow mode — awaiting human approval",
            );
            Ok(Json(serde_json::json!({
                "status": "shadow_mode",
                "message": "Rule enters 1-hour shadow observation. Approve via /api/v1/rules/approve/:id"
            })))
        }
        Err(e) => {
            api.audit.log(
                &claims.sub, &format!("{:?}", claims.role), AuditAction::RuleRejected,
                &title, AuditResult::Failure, &source_ip, &e,
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

    match engine.guardian.human_approve_rule(&rule_id, &engine.dynamic_rules).await {
        Ok(_) => {
            api.audit.log(
                &claims.sub, &format!("{:?}", claims.role), AuditAction::RuleApproved,
                &rule_id, AuditResult::Success, &source_ip, "Promoted to enforcement",
            );
            Ok(Json(serde_json::json!({ "status": "enforced", "rule_id": rule_id })))
        }
        Err(e) => {
            api.audit.log(
                &claims.sub, &format!("{:?}", claims.role), AuditAction::RuleRejected,
                &rule_id, AuditResult::Failure, &source_ip, &e,
            );
            Err(StatusCode::NOT_FOUND)
        }
    }
}

// ─── IOC Management ───────────────────────────────────────────────────────────

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
    ValidatedJson(body): ValidatedJson<AddIocRequest>,
) -> Json<serde_json::Value> {
    let value = sanitize_string(&body.value);
    api.audit.log(
        &claims.sub, &format!("{:?}", claims.role), AuditAction::IocAdded,
        &value, AuditResult::Success, &extract_source_ip(&headers),
        &format!("type={} source={}", body.ioc_type, body.source),
    );
    Json(serde_json::json!({ "status": "added", "ioc": value }))
}

// ─── Helper ───────────────────────────────────────────────────────────────────

fn extract_source_ip(headers: &HeaderMap) -> String {
    headers.get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}
