//! API Rate Limiting Middleware
//! Protects against brute-force attacks on /api/v1/login and other endpoints.
//! Uses a sliding-window counter per IP address (DashMap, lock-free reads).
//!
//! Default limits (configurable via env vars):
//!   THOR_RATE_LOGIN_RPM=10     — login attempts per minute per IP
//!   THOR_RATE_API_RPM=600      — general API calls per minute per IP
//!   THOR_RATE_BURST=20         — maximum burst above the rate

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tracing::warn;

// ─── Config ───────────────────────────────────────────────────────────────────

fn rate_login_rpm() -> u32 {
    std::env::var("THOR_RATE_LOGIN_RPM").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(10)
}

fn rate_api_rpm() -> u32 {
    std::env::var("THOR_RATE_API_RPM").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(600)
}

// ─── Sliding window entry ─────────────────────────────────────────────────────

#[derive(Clone)]
struct WindowEntry {
    count: u32,
    window_start: Instant,
}

impl WindowEntry {
    fn new() -> Self {
        Self { count: 1, window_start: Instant::now() }
    }
    fn is_expired(&self, window: Duration) -> bool {
        self.window_start.elapsed() >= window
    }
}

// ─── Rate limiter ─────────────────────────────────────────────────────────────

pub struct RateLimiter {
    windows: DashMap<String, WindowEntry>,
    window_duration: Duration,
    max_requests: u32,
    label: &'static str,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_duration: Duration, label: &'static str) -> Self {
        Self {
            windows: DashMap::with_capacity(10_000),
            window_duration,
            max_requests,
            label,
        }
    }

    /// Returns true if the IP is allowed, false if rate-limited.
    pub fn check(&self, ip: &str) -> bool {
        let mut entry = self.windows.entry(ip.to_string()).or_insert_with(WindowEntry::new);

        if entry.is_expired(self.window_duration) {
            *entry = WindowEntry::new();
            return true;
        }

        entry.count += 1;
        if entry.count > self.max_requests {
            warn!(
                "🚫 Rate limit exceeded [{label}]: ip={ip} count={count} limit={limit}",
                label = self.label,
                ip = ip,
                count = entry.count,
                limit = self.max_requests,
            );
            return false;
        }
        true
    }

    /// Periodically evict expired entries (call from background task).
    pub fn cleanup(&self) {
        self.windows.retain(|_, v| !v.is_expired(self.window_duration * 2));
    }
}

// ─── Global limiters (initialized once) ──────────────────────────────────────

static LOGIN_LIMITER: OnceLock<Arc<RateLimiter>> = OnceLock::new();
static API_LIMITER:   OnceLock<Arc<RateLimiter>> = OnceLock::new();

pub fn login_limiter() -> Arc<RateLimiter> {
    LOGIN_LIMITER.get_or_init(|| {
        Arc::new(RateLimiter::new(
            rate_login_rpm(),
            Duration::from_secs(60),
            "login",
        ))
    }).clone()
}

pub fn api_limiter() -> Arc<RateLimiter> {
    API_LIMITER.get_or_init(|| {
        Arc::new(RateLimiter::new(
            rate_api_rpm(),
            Duration::from_secs(60),
            "api",
        ))
    }).clone()
}

// ─── Middleware: Login endpoint (strict) ──────────────────────────────────────

pub async fn rate_limit_login(req: Request, next: Next) -> Result<Response, StatusCode> {
    let ip = extract_ip(&req);
    if !login_limiter().check(&ip) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(next.run(req).await)
}

// ─── Middleware: General API (lenient) ────────────────────────────────────────

pub async fn rate_limit_api(req: Request, next: Next) -> Result<Response, StatusCode> {
    let ip = extract_ip(&req);
    if !api_limiter().check(&ip) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(next.run(req).await)
}

// ─── Helper ───────────────────────────────────────────────────────────────────

fn extract_ip(req: &Request) -> String {
    req.headers()
        .get("x-forwarded-for")
        .or_else(|| req.headers().get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("unknown")
        .trim()
        .to_string()
}
