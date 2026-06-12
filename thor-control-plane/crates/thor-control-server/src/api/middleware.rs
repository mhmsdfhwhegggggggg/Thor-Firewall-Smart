use axum::{
    extract::Request,
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum Role {
    SocL1,
    SocL2,
    SecManager,
}

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: Role,
    pub exp: usize,
}

pub struct RequireRole(pub Role);

impl<S> axum::extract::FromRequestParts<S> for RequireRole 
where S: Send + Sync 
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut axum::http::request::Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts.headers.get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .ok_or((StatusCode::UNAUTHORIZED, "Missing token"))?;

        // This assumes a generated public key exists at paths defined, for now we will stub it or gently handle it:
        // Use a dummy static key for the example or read from file
        let public_key = std::env::var("SSO_PUBLIC_KEY").unwrap_or_else(|_| "dummy_public_key".to_string());
        let decoding_key = DecodingKey::from_rsa_pem(public_key.as_bytes())
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid key format"))?;

        let token_data = decode::<Claims>(auth_header, &decoding_key, &Validation::new(Algorithm::RS256))
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token"))?;

        if token_data.claims.role != Self.0 && token_data.claims.role != Role::SecManager {
            return Err((StatusCode::FORBIDDEN, "Insufficient privileges"));
        }

        Ok(Self(token_data.claims.role))
    }
}
