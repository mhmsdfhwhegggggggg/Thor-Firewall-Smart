//! Request validation — size limits, content-type enforcement, sanitization.
//! Applied globally to prevent: large-payload DoS, injection via oversized fields.

use axum::{
    body::{Body, Bytes},
    extract::{FromRequest, Request},
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::de::DeserializeOwned;
use tracing::warn;

// ─── Config ───────────────────────────────────────────────────────────────────

const MAX_BODY_BYTES: usize = 64 * 1024;        // 64 KB max body
const MAX_STRING_LEN: usize = 8 * 1024;         // 8 KB max per string field

// ─── Validated JSON extractor ─────────────────────────────────────────────────

/// Drop-in replacement for `Json<T>` with size limits enforced.
/// Usage: `ValidatedJson(body): ValidatedJson<MyRequest>`
pub struct ValidatedJson<T>(pub T);

impl<T, S> axum::extract::FromRequest<S> for ValidatedJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // 1. Enforce Content-Type
        let content_type = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !content_type.starts_with("application/json") {
            return Err((StatusCode::UNSUPPORTED_MEDIA_TYPE, "Content-Type must be application/json"));
        }

        // 2. Read body with size limit
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|_| (StatusCode::BAD_REQUEST, "Failed to read request body"))?;

        if bytes.len() > MAX_BODY_BYTES {
            warn!(
                "Request body too large: {} bytes (max {})",
                bytes.len(), MAX_BODY_BYTES
            );
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "Request body too large (max 64KB)"));
        }

        // 3. Deserialize
        let value: T = serde_json::from_slice(&bytes)
            .map_err(|e| {
                warn!("JSON deserialization error: {}", e);
                (StatusCode::UNPROCESSABLE_ENTITY, "Invalid JSON body")
            })?;

        Ok(ValidatedJson(value))
    }
}

// ─── String sanitization helper ───────────────────────────────────────────────

/// Truncate and strip dangerous chars from user-supplied strings.
pub fn sanitize_string(input: &str) -> String {
    let truncated = if input.len() > MAX_STRING_LEN {
        warn!("String field truncated: {} -> {}", input.len(), MAX_STRING_LEN);
        &input[..MAX_STRING_LEN]
    } else {
        input
    };

    // Strip null bytes and control characters (except newlines/tabs)
    truncated
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || !c.is_control())
        .collect()
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_removes_null_bytes() {
        let input = "hello\x00world";
        let result = sanitize_string(input);
        assert_eq!(result, "helloworld");
    }

    #[test]
    fn test_sanitize_truncates_long_string() {
        let long = "a".repeat(MAX_STRING_LEN + 100);
        let result = sanitize_string(&long);
        assert_eq!(result.len(), MAX_STRING_LEN);
    }

    #[test]
    fn test_sanitize_preserves_newlines() {
        let input = "line1\nline2";
        assert_eq!(sanitize_string(input), input);
    }
}
