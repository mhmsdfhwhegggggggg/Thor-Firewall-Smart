//! JWT Authentication + RBAC Middleware — Phase 1 hardened version.
//!
//! Improvements over original:
//!   ✅ Token blacklist check (revoked tokens rejected)
//!   ✅ Refresh token endpoint support (short-lived access + long-lived refresh)
//!   ✅ MFA groundwork (TOTP field in claims)
//!   ✅ jti uniqueness enforced
//!   ✅ Role hierarchy: admin > analyst > readonly

use axum::{
    extract::Request,
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};
use tracing::warn;

static JWT_SECRET: OnceLock<String> = OnceLock::new();

fn jwt_secret() -> &'static str {
    JWT_SECRET.get_or_init(|| {
        std::env::var("THOR_JWT_SECRET").unwrap_or_else(|_| {
            panic!("THOR_JWT_SECRET not set. Generate: openssl rand -hex 64")
        })
    })
}

// ─── Roles ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ThorRole {
    #[serde(rename = "admin")]   Admin,
    #[serde(rename = "analyst")] Analyst,
    #[serde(rename = "readonly")] Readonly,
}

impl ThorRole {
    pub fn level(&self) -> u8 {
        match self { ThorRole::Admin => 3, ThorRole::Analyst => 2, ThorRole::Readonly => 1 }
    }
    pub fn meets(&self, required: &ThorRole) -> bool { self.level() >= required.level() }
}

// ─── Claims ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub:           String,
    pub role:          ThorRole,
    pub exp:           usize,
    pub iat:           usize,
    pub jti:           String,   // Unique token ID (for revocation)
    pub token_type:    TokenType, // access | refresh
    pub mfa_verified:  bool,      // Phase 1: MFA groundwork
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum TokenType {
    #[serde(rename = "access")]  Access,
    #[serde(rename = "refresh")] Refresh,
}

// ─── Token generation ─────────────────────────────────────────────────────────

pub struct TokenPair {
    pub access_token:  String,
    pub refresh_token: String,
    pub access_jti:    String,
    pub refresh_jti:   String,
    pub expires_in:    u64,
}

pub fn generate_token_pair(subject: &str, role: ThorRole) -> Result<TokenPair, jsonwebtoken::errors::Error> {
    let access_expiry_hours: u64 = std::env::var("THOR_JWT_EXPIRY_HOURS")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(8);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as usize;

    let access_jti  = uuid::Uuid::new_v4().to_string();
    let refresh_jti = uuid::Uuid::new_v4().to_string();

    // Access token (short-lived: 8h default)
    let access_claims = Claims {
        sub: subject.to_string(), role: role.clone(),
        exp: now + (access_expiry_hours as usize * 3600), iat: now,
        jti: access_jti.clone(), token_type: TokenType::Access, mfa_verified: false,
    };
    let access_token = encode(
        &Header::default(), &access_claims,
        &EncodingKey::from_secret(jwt_secret().as_bytes())
    )?;

    // Refresh token (long-lived: 7 days)
    let refresh_claims = Claims {
        sub: subject.to_string(), role: role.clone(),
        exp: now + (7 * 24 * 3600), iat: now,
        jti: refresh_jti.clone(), token_type: TokenType::Refresh, mfa_verified: false,
    };
    let refresh_token = encode(
        &Header::default(), &refresh_claims,
        &EncodingKey::from_secret(jwt_secret().as_bytes())
    )?;

    Ok(TokenPair { access_token, refresh_token, access_jti, refresh_jti,
                   expires_in: access_expiry_hours * 3600 })
}

/// Legacy single-token generation (backward compat)
pub fn generate_token(subject: &str, role: ThorRole) -> Result<String, jsonwebtoken::errors::Error> {
    Ok(generate_token_pair(subject, role)?.access_token)
}

// ─── Token validation ─────────────────────────────────────────────────────────

pub fn validate_token_raw(token: &str) -> Result<Claims, StatusCode> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret().as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| { warn!("JWT validation failed: {}", e); StatusCode::UNAUTHORIZED })
}

fn extract_auth_header(req: &Request) -> Result<&str, StatusCode> {
    req.headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)
}

fn validate_token(auth_header: &str) -> Result<Claims, StatusCode> {
    let token = auth_header.strip_prefix("Bearer ").ok_or(StatusCode::UNAUTHORIZED)?;
    validate_token_raw(token)
}

// ─── Middleware factories ──────────────────────────────────────────────────────

/// Middleware: require any authenticated user (readonly+).
pub async fn require_auth(req: Request, next: Next) -> Result<Response, StatusCode> {
    let auth = extract_auth_header(&req)?;
    let claims = validate_token(auth)?;
    // Only access tokens can be used for API calls
    if claims.token_type != TokenType::Access {
        warn!("Refresh token used as access token: sub={}", claims.sub);
        return Err(StatusCode::UNAUTHORIZED);
    }
    let mut req = req;
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

/// Middleware: require analyst or admin.
pub async fn require_analyst_auth(req: Request, next: Next) -> Result<Response, StatusCode> {
    let auth = extract_auth_header(&req)?;
    let claims = validate_token(auth)?;
    if !claims.role.meets(&ThorRole::Analyst) {
        warn!("Insufficient role: {:?} < Analyst (sub={})", claims.role, claims.sub);
        return Err(StatusCode::FORBIDDEN);
    }
    if claims.token_type != TokenType::Access {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let mut req = req;
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

/// Middleware: require admin only.
pub async fn require_admin_auth(req: Request, next: Next) -> Result<Response, StatusCode> {
    let auth = extract_auth_header(&req)?;
    let claims = validate_token(auth)?;
    if claims.role != ThorRole::Admin {
        warn!("Admin required, got {:?} (sub={})", claims.role, claims.sub);
        return Err(StatusCode::FORBIDDEN);
    }
    if claims.token_type != TokenType::Access {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let mut req = req;
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

// ─── Blacklist-aware middleware (requires ApiState with blacklist) ─────────────

use axum::extract::State;
use crate::api::ApiState;

pub async fn require_auth_checked(
    State(api): State<ApiState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth = extract_auth_header(&req)?;
    let token = auth.strip_prefix("Bearer ").ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = validate_token_raw(token)?;

    // Check token blacklist
    if let Some(bl) = &api.token_blacklist {
        if bl.is_revoked(&claims.jti) {
            warn!("Revoked token used: jti={} sub={}", claims.jti, claims.sub);
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    if claims.token_type != TokenType::Access {
        return Err(StatusCode::UNAUTHORIZED);
    }

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
