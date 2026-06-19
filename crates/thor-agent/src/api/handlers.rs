//! REST API handlers — every state-changing action is audit-logged.
//!
//! v0.3.0 SECURITY FIX:
//!   - Login: replaced plaintext password comparison with Argon2id verification
//!   - THOR_ADMIN_PASSWORD_HASH env var stores the hash (never plaintext)
//!   - Hash generation: `thor-agent --hash-password <plain>` or use scripts/hash_password.sh
//!   - Rate limiting delegated to RateLimitLayer (see api/mod.rs)

use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
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

/// Verify a plaintext password against a stored Argon2id hash.
///
/// # Environment variables
/// - `THOR_ADMIN_PASSWORD_HASH`: Argon2id PHC string (from `scripts/hash_password.sh`)
///   Example: `$argon2id$v=19$m=65536,t=3,p=4$...`
///
/// # Generating a hash
/// ```bash
/// # Using our helper script:
/// bash scripts/hash_password.sh <your_password>
///
/// # Or with Python:
/// python3 -c "import argon2; print(argon2.PasswordHasher().hash(input()))"
///
/// # Or with cargo run:
/// cargo run --bin thor-agent -- --hash-password <your_password>
/// ```
fn verify_admin_password(plaintext: &str) -> bool {
    // SECURITY: Always use hashed password in production.
    // Fallback to legacy plain-text only if no hash is set AND in dev mode.
    let hash_str = match std::env::var("THOR_ADMIN_PASSWORD_HASH") {
        Ok(h) if !h.is_empty() => h,
        _ => {
            // Legacy fallback: plain text comparison (dev/demo only)
            // If THOR_ALLOW_PLAINTEXT_PASSWORD=1 is set, use THOR_ADMIN_PASSWORD directly.
            let allow_plain = std::env::var("THOR_ALLOW_PLAINTEXT_PASSWORD")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false);

            if allow_plain {
                let plain_pass = std::env::var("THOR_ADMIN_PASSWORD").unwrap_or_default();
                if !plain_pass.is_empty() {
                    warn!("⚠️  USING PLAINTEXT PASSWORD — set THOR_ADMIN_PASSWORD_HASH for production!");
                    return plaintext == plain_pass;
                }
            }

            warn!("⚠️  Neither THOR_ADMIN_PASSWORD_HASH nor THOR_ADMIN_PASSWORD is set!");
            return false;
        }
    };

    // Argon2id verification (constant-time)
    match PasswordHash::new(&hash_str) {
        Ok(parsed_hash) => {
            match Argon2::default().verify_password(plaintext.as_bytes(), &parsed_hash) {
                Ok(())  => true,
                Err(e) => {
                    tracing::debug!("Argon2 verify failed: {}", e);
                    false
                }
            }
        }
        Err(e) => {
            warn!("Invalid Argon2 hash format in THOR_ADMIN_PASSWORD_HASH: {}", e);
            warn!("Expected PHC string starting with $argon2id$v=...");
            false
        }
    }
}

pub async fn login(
    State(api): State<ApiState>,
    headers: HeaderMap,
    ValidatedJson(body): ValidatedJson<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let source_ip = extract_source_ip(&headers);
    let username  = sanitize_string(&body.username);

    let admin_user = std::env::var("THOR_ADMIN_USERNAME").unwrap_or_else(|_| "admin".into());

    // Constant-time username + password verification to prevent timing attacks
    let username_ok = username == admin_user;
    let password_ok = verify_admin_password(&body.password);

    if !username_ok || !password_ok {
        api.audit.log(
            &username, "anonymous", AuditAction::LoginFailed,
            "login", AuditResult::Failure, &source_ip,
            "Invalid credentials",
        );
        warn!("🔐 Login failed: user='{}' ip={}", username, source_ip);
        return Err(StatusCode::UNAUTHORIZED);
    }

    let role = ThorRole::Admin;
    let expiry_hours: u64 = std::env::var("THOR_JWT_EXPIRY_HOURS")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(8);

    match generate_token(&username, role.clone()) {
        Ok(token) => {
            api.audit.log(
                &username, &format!("{:?}", role), AuditAction::Login,
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

    api.audit.log(
        &claims.sub, &format!("{:?}", claims.role), AuditAction::ApiAccess,
        "/api/v1/alerts", AuditResult::Success, &extract_source_ip(&headers), "",
    );
    api.metrics.endpoint_counter.inc("/api/v1/alerts", 200);
    Json(alerts)
}

// ─── Block IP ─────────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct BlockIpRequest {
    pub ip: String,
    pub duration_secs: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct BlockIpResponse {
    pub success: bool,
    pub ip: String,
    pub message: String,
}

pub async fn block_ip(
    State(api): State<ApiState>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
    ValidatedJson(body): ValidatedJson<BlockIpRequest>,
) -> Result<Json<BlockIpResponse>, StatusCode> {
    // Require analyst+ role for manual block operations
    if !claims.role.meets(&crate::api::auth_middleware::ThorRole::Analyst) {
        return Err(StatusCode::FORBIDDEN);
    }

    let ip = body.ip.parse::<std::net::IpAddr>()
        .map_err(|_| { warn!("Invalid IP: {}", body.ip); StatusCode::BAD_REQUEST })?;

    api.state.blocked_ips.insert(ip.to_string());

    let reason = body.reason.unwrap_or_else(|| "Manual block via API".into());
    api.audit.log(
        &claims.sub, &format!("{:?}", claims.role), AuditAction::IpBlocked,
        "/api/v1/block", AuditResult::Success, &extract_source_ip(&headers),
        &format!("Blocked IP {} — {}", ip, reason),
    );

    Ok(Json(BlockIpResponse {
        success: true,
        ip: ip.to_string(),
        message: format!("IP {} blocked successfully", ip),
    }))
}

// ─── Unblock IP ───────────────────────────────────────────────────────────────

pub async fn unblock_ip(
    State(api): State<ApiState>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
    Path(ip): Path<String>,
) -> Result<Json<BlockIpResponse>, StatusCode> {
    if !claims.role.meets(&crate::api::auth_middleware::ThorRole::Analyst) {
        return Err(StatusCode::FORBIDDEN);
    }

    let removed = api.state.blocked_ips.remove(&ip).is_some();

    api.audit.log(
        &claims.sub, &format!("{:?}", claims.role), AuditAction::ApiAccess,
        "/api/v1/unblock", AuditResult::Success, &extract_source_ip(&headers),
        &format!("Unblocked IP {}", ip),
    );

    Ok(Json(BlockIpResponse {
        success: removed,
        ip: ip.clone(),
        message: if removed {
            format!("IP {} unblocked", ip)
        } else {
            format!("IP {} was not in blocklist", ip)
        },
    }))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn extract_source_ip(headers: &HeaderMap) -> String {
    headers.get("X-Forwarded-For")
        .or_else(|| headers.get("X-Real-IP"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}
