use axum::{
    extract::Request,
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // Agent ID or Admin ID
    pub role: String, // "admin", "analyst", "agent"
    pub exp: usize,   // Expiration time
}

pub async fn require_admin_auth(
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // 1. Extract Token
    let auth_header = req.headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // 2. Validate Signature
    // In production, loaded from secure file or HSM (we use a placeholder here)
    // To allow compilation, we will use from_secret for demonstration, 
    // replacing the actual generic PEM bytes file read with a mock loading technique.
    // Replace with: DecodingKey::from_rsa_pem(include_bytes!("../../certs/public_key.pem"))
    let decoding_key = DecodingKey::from_secret(b"secret_key");

    let mut validation = Validation::new(Algorithm::HS256); // HS256 for mock, RS256 for prod
    validation.validate_exp = true;

    let token_data = decode::<Claims>(auth_header, &decoding_key, &validation)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // 3. RBAC validation
    if token_data.claims.role != "admin" && token_data.claims.role != "system_controller" {
        return Err(StatusCode::FORBIDDEN);
    }

    // 4. Pass user identity to the next handler
    req.extensions_mut().insert(token_data.claims);
    Ok(next.run(req).await)
}
