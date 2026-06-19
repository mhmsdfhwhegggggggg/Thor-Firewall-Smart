//! WebSocket handler — authenticated real-time alert stream.
//!
//! v0.3.0 SECURITY FIX:
//!   Token moved from URL query param (?token=...) to first WS text message.
//!
//! RATIONALE: Token in URL query string is logged by proxies, load balancers,
//!   and web servers (nginx, Caddy, AWS ELB) in their access logs → token leakage.
//!
//! PROTOCOL:
//!   1. Client connects to ws://host/ws/events  (no token in URL)
//!   2. Server sends: {"type":"auth_required","message":"Send JWT token"}
//!   3. Client sends: {"type":"auth","token":"<JWT>"}
//!   4. Server validates and responds: {"type":"auth_ok","user":"..."}
//!      OR closes connection with 4001 Unauthorized
//!   5. Server streams alerts: {"type":"alert","data":{...}}
//!
//! BACKWARD COMPAT: Legacy ?token= param still accepted for 30 days but logs a warning.
//!   Set THOR_WS_LEGACY_TOKEN_DEPRECATED=1 to disable the legacy path.

use axum::{
    extract::{Query, State, WebSocketUpgrade},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum::extract::ws::{WebSocket, Message, CloseFrame};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tracing::{info, debug, warn};

use crate::api::ApiState;
use crate::api::auth_middleware::{Claims, ThorRole};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

// ─── Query params (legacy — deprecated) ──────────────────────────────────────

#[derive(Deserialize)]
pub struct WsQuery {
    /// Deprecated: Token in URL query param is logged by proxies.
    /// Moved to first WS text message {"type":"auth","token":"..."}.
    pub token: Option<String>,
}

// ─── WebSocket message types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    Auth { token: String },
    Ping,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage<'a> {
    AuthRequired  { message: &'a str },
    AuthOk        { user: String, role: String, version: &'a str },
    AuthError     { message: &'a str },
    Alert         { data: &'a serde_json::Value },
    Pong,
    Connected     { message: &'a str, user: String, role: String, version: &'a str },
}

// ─── Auth timeout ─────────────────────────────────────────────────────────────

/// Maximum time client has to send auth message after connecting.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

// ─── Handler ──────────────────────────────────────────────────────────────────

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    State(api): State<ApiState>,
) -> Response {
    // Check for deprecated legacy token in URL
    if let Some(ref legacy_token) = query.token {
        let legacy_disabled = std::env::var("THOR_WS_LEGACY_TOKEN_DEPRECATED")
            .map(|v| v == "1")
            .unwrap_or(false);

        if legacy_disabled {
            warn!("WS: legacy ?token= rejected (THOR_WS_LEGACY_TOKEN_DEPRECATED=1)");
            return StatusCode::BAD_REQUEST.into_response();
        }

        warn!("⚠️  WS: token passed in URL query param — this is DEPRECATED and insecure!");
        warn!("    Tokens in URL are logged by proxies. Use first-message auth instead.");
        warn!("    Client migration guide: send {{"type":"auth","token":"..."}} as first message.");

        // Legacy path: validate immediately, skip first-message auth
        match validate_ws_token(Some(legacy_token)) {
            Ok(claims) if claims.role.meets(&ThorRole::Readonly) => {
                return ws.on_upgrade(move |socket| {
                    handle_socket_authenticated(socket, api, claims)
                });
            }
            Ok(_) => return StatusCode::FORBIDDEN.into_response(),
            Err(code) => return code.into_response(),
        }
    }

    // New protocol: authenticate via first message
    ws.on_upgrade(move |socket| handle_socket_with_auth(socket, api))
}

// ─── New: first-message auth ─────────────────────────────────────────────────

async fn handle_socket_with_auth(mut socket: WebSocket, api: ApiState) {
    // 1. Challenge client to authenticate
    let challenge = serde_json::to_string(&ServerMessage::AuthRequired {
        message: "Send {"type":"auth","token":"<JWT>"} within 10 seconds",
    }).unwrap_or_default();

    if socket.send(Message::Text(challenge)).await.is_err() {
        return; // Client disconnected before auth
    }

    // 2. Wait for auth message (with timeout)
    let auth_result = tokio::time::timeout(AUTH_TIMEOUT, socket.next()).await;

    let claims = match auth_result {
        Ok(Some(Ok(Message::Text(text)))) => {
            match serde_json::from_str::<ClientMessage>(&text) {
                Ok(ClientMessage::Auth { token }) => {
                    match validate_ws_token(Some(&token)) {
                        Ok(c) => {
                            if !c.role.meets(&ThorRole::Readonly) {
                                let msg = serde_json::to_string(&ServerMessage::AuthError {
                                    message: "Insufficient role",
                                }).unwrap_or_default();
                                let _ = socket.send(Message::Text(msg)).await;
                                let _ = socket.close().await;
                                return;
                            }
                            c
                        }
                        Err(_) => {
                            let msg = serde_json::to_string(&ServerMessage::AuthError {
                                message: "Invalid or expired token",
                            }).unwrap_or_default();
                            let _ = socket.send(Message::Text(msg)).await;
                            let _ = socket.close().await;
                            return;
                        }
                    }
                }
                _ => {
                    let msg = serde_json::to_string(&ServerMessage::AuthError {
                        message: "Expected {"type":"auth","token":"..."}",
                    }).unwrap_or_default();
                    let _ = socket.send(Message::Text(msg)).await;
                    let _ = socket.close().await;
                    return;
                }
            }
        }
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) => return,
        Err(_) => {
            // Auth timeout
            warn!("WS: auth timeout — closing connection");
            let msg = serde_json::to_string(&ServerMessage::AuthError {
                message: "Authentication timeout (10s)",
            }).unwrap_or_default();
            let _ = socket.send(Message::Text(msg)).await;
            let _ = socket.close().await;
            return;
        }
        _ => return,
    };

    // 3. Auth OK — proceed to stream
    handle_socket_authenticated(socket, api, claims).await;
}

// ─── Socket handler (post-auth) ───────────────────────────────────────────────

async fn handle_socket_authenticated(socket: WebSocket, api: ApiState, claims: Claims) {
    let client_count = api.state.ws_clients.fetch_add(1, Ordering::Relaxed) + 1;
    info!(
        "📡 WS connected: user={} role={:?} total={}",
        claims.sub, claims.role, client_count
    );

    let (mut sender, mut receiver) = socket.split();

    // Welcome message
    let welcome = serde_json::to_string(&ServerMessage::Connected {
        message: "Thor Firewall Smart — authenticated real-time threat stream",
        user: claims.sub.clone(),
        role: format!("{:?}", claims.role),
        version: env!("CARGO_PKG_VERSION"),
    }).unwrap_or_default();
    let _ = sender.send(Message::Text(welcome)).await;

    let alert_rx = api.alert_rx.clone();
    let sub_clone = claims.sub.clone();

    // Broadcast task — stream alerts to client
    let mut send_task = tokio::spawn(async move {
        loop {
            match alert_rx.recv_async().await {
                Ok(alert) => {
                    let val = serde_json::to_value(&alert).unwrap_or_default();
                    let payload = serde_json::to_string(&ServerMessage::Alert { data: &val })
                        .unwrap_or_default();
                    match sender.send(Message::Text(payload)).await {
                        Ok(_)  => debug!("WS alert sent to {}", sub_clone),
                        Err(e) => { warn!("WS send failed: {}", e); break; }
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Receive task — handle pings/disconnect
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Close(_) => break,
                Message::Ping(_)  => debug!("WS ping"),
                Message::Text(t)  => {
                    // Handle client-initiated commands (future: filter changes, etc.)
                    debug!("WS client msg: {}", t);
                }
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }

    api.state.ws_clients.fetch_sub(1, Ordering::Relaxed);
    info!("📡 WS disconnected: user={}", claims.sub);
}

// ─── Token validation ─────────────────────────────────────────────────────────

fn validate_ws_token(token: Option<&str>) -> Result<Claims, StatusCode> {
    let token = token.ok_or(StatusCode::UNAUTHORIZED)?;
    let secret = std::env::var("THOR_JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|d| d.claims)
    .map_err(|e| {
        warn!("WS token invalid: {}", e);
        StatusCode::UNAUTHORIZED
    })
}
