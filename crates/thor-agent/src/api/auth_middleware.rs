//! JWT Authentication + RBAC Middleware
//! Reads JWT secret from THOR_JWT_SECRET env var — never hardcoded.
//! Roles: admin > analyst > readonly
//!
//! Usage in router:
//!   .route_layer(middleware::from_fn(require_analyst_auth))  // analyst+admin
//!   .route_layer(middleware::from_fn(require_admin_auth))    // admin only

use axum::{
    extract::Request,
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tracing::warn;

// ─── JWT Secret (loaded once from env, never hardcoded) ──────────────────────

static JWT_SECRET: OnceLock<String> = OnceLock::new();

fn jwt_secret() -> &'static str {
    JWT_SECRET.get_or_init(|| {
        std::env::var("THOR_JWT_SECRET").unwrap_or_else(|_| {
            panic!(
                "THOR_JWT_SECRET environment variable is not set. \
                 Generate one with: openssl rand -hex 64"
            )
        })
    })
}

// ─── Claims ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ThorRole {
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "analyst")]
    Analyst,
    #[serde(rename = "readonly")]
    Readonly,
}

impl ThorRole {
    pub fn level(&self) -> u8 {
        match self {
            ThorRole::Admin => 3,
            ThorRole::Analyst => 2,
            ThorRole::Readonly => 1,
        }
    }
    pub fn meets(&self, required: &ThorRole) -> bool {
        self.level() >= required.level()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // Username / Agent ID
    pub role: ThorRole,
    pub exp: usize, // Unix timestamp expiry
    pub iat: usize, // Issued at
    pub jti: String, // JWT ID (for revocation)
}

// ─── Token generation (used by login handler) ────────────────────────────────

pub fn generate_token(subject: &str, role: ThorRole) -> Result<String, jsonwebtoken::errors::Error> {
    let expiry_hours: u64 = std::env::var("THOR_JWT_EXPIRY_HOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = Claims {
        sub: subject.to_string(),
        role,
        exp: now + (expiry_hours as usize * 3600),
        iat: now,
        jti: uuid::Uuid::new_v4().to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret().as_bytes()),
    )
}

// ─── Token validation ────────────────────────────────────────────────────────

fn validate_token(auth_header: &str) -> Result<Claims, StatusCode> {
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret().as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| {
        warn!("JWT validation failed: {}", e);
        StatusCode::UNAUTHORIZED
    })
}

fn extract_auth_header(req: &Request) -> Result<&str, StatusCode> {
    req.headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)
}

// ─── Middleware: Readonly (any authenticated user) ────────────────────────────

pub async fn require_auth(
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = extract_auth_header(&req)?;
    let claims = validate_token(auth_header)?;
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

// ─── Middleware: Analyst or Admin ─────────────────────────────────────────────

pub async fn require_analyst_auth(
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = extract_auth_header(&req)?;
    let claims = validate_token(auth_header)?;

    if !claims.role.meets(&ThorRole::Analyst) {
        warn!("RBAC denied: user '{}' role {:?} needs Analyst", claims.sub, claims.role);
        return Err(StatusCode::FORBIDDEN);
    }

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

// ─── Middleware: Admin only ───────────────────────────────────────────────────

pub async fn require_admin_auth(
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = extract_auth_header(&req)?;
    let claims = validate_token(auth_header)?;

    if !claims.role.meets(&ThorRole::Admin) {
        warn!("RBAC denied: user '{}' role {:?} needs Admin", claims.sub, claims.role);
        return Err(StatusCode::FORBIDDEN);
    }

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
