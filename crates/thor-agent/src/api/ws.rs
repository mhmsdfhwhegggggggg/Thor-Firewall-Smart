//! WebSocket handler — authenticated real-time alert stream.
//! Token required as query parameter: ws://host/ws/events?token=<JWT>
//! Unauthenticated connections are rejected with 401 before upgrade.

use axum::{
    extract::{Query, State, WebSocketUpgrade},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum::extract::ws::{WebSocket, Message};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::Deserialize;
use std::sync::atomic::Ordering;
use tracing::{info, debug, warn};

use crate::api::ApiState;
use crate::api::auth_middleware::{Claims, ThorRole};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

// ─── Query params ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WsQuery {
    pub token: Option<String>,
}

// ─── Handler ──────────────────────────────────────────────────────────────────

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    State(api): State<ApiState>,
) -> Result<Response, StatusCode> {
    // Validate token BEFORE upgrading — reject unauthenticated connections
    let claims = validate_ws_token(query.token.as_deref())?;

    // Only readonly+ can subscribe to live events
    if !claims.role.meets(&ThorRole::Readonly) {
        warn!("WS rejected: role {:?} insufficient", claims.role);
        return Err(StatusCode::FORBIDDEN);
    }

    info!("📡 WebSocket auth OK: user={} role={:?}", claims.sub, claims.role);
    Ok(ws.on_upgrade(move |socket| handle_socket(socket, api, claims)))
}

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

// ─── Socket handler ───────────────────────────────────────────────────────────

async fn handle_socket(socket: WebSocket, api: ApiState, claims: Claims) {
    let client_count = api.state.ws_clients.fetch_add(1, Ordering::Relaxed) + 1;
    info!(
        "📡 WS connected: user={} role={:?} total={}",
        claims.sub, claims.role, client_count
    );

    let (mut sender, mut receiver) = socket.split();

    // Welcome message
    let welcome = serde_json::json!({
        "type": "connected",
        "message": "Thor Firewall Smart — authenticated real-time threat stream",
        "user": claims.sub,
        "role": format!("{:?}", claims.role),
        "version": env!("CARGO_PKG_VERSION"),
    });
    let _ = sender.send(Message::Text(welcome.to_string())).await;

    let alert_rx = api.alert_rx.clone();

    // Broadcast task
    let mut send_task = tokio::spawn(async move {
        loop {
            match alert_rx.recv_async().await {
                Ok(alert) => {
                    let payload = serde_json::json!({ "type": "alert", "data": alert });
                    match sender.send(Message::Text(payload.to_string())).await {
                        Ok(_)  => debug!("WS alert sent to {}", claims.sub),
                        Err(e) => { warn!("WS send failed: {}", e); break; }
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Receive task — handle pings/disconnect/heartbeat
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Close(_) => break,
                Message::Ping(_)  => debug!("WS ping"),
                Message::Text(t)  => debug!("WS client msg: {}", t),
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }

    let remaining = api.state.ws_clients.fetch_sub(1, Ordering::Relaxed) - 1;
    info!("📡 WS disconnected (remaining: {})", remaining);
}
