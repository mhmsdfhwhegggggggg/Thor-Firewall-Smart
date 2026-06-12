//! WebSocket handler — pub/sub real-time alert broadcasting
//! Each connection gets live alerts as they're generated

use axum::{
    extract::{State, WebSocketUpgrade},
    response::Response,
};
use axum::extract::ws::{WebSocket, Message};
use futures::{sink::SinkExt, stream::StreamExt};
use std::sync::atomic::Ordering;
use tracing::{info, debug, warn};
use crate::api::ApiState;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(api): State<ApiState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, api))
}

async fn handle_socket(socket: WebSocket, api: ApiState) {
    let client_count = api.state.ws_clients.fetch_add(1, Ordering::Relaxed) + 1;
    info!("📡 WebSocket client connected (total: {})", client_count);

    let (mut sender, mut receiver) = socket.split();

    // Send welcome message
    let welcome = serde_json::json!({
        "type": "connected",
        "message": "Thor Firewall Smart — real-time threat stream",
        "version": env!("CARGO_PKG_VERSION")
    });
    let _ = sender.send(Message::Text(welcome.to_string())).await;

    // Clone receiver end
    let alert_rx = api.alert_rx.clone();

    // Broadcast task — sends alerts to this client
    let mut send_task = tokio::spawn(async move {
        loop {
            match alert_rx.recv_async().await {
                Ok(alert) => {
                    let payload = serde_json::json!({
                        "type": "alert",
                        "data": alert
                    });
                    match sender.send(Message::Text(payload.to_string())).await {
                        Ok(_) => debug!("Sent alert to WebSocket client"),
                        Err(e) => { warn!("WS send failed: {}", e); break; }
                    }
                }
                Err(_) => break, // Channel disconnected
            }
        }
    });

    // Receive task — handle pings/disconnect
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Close(_) => break,
                Message::Ping(ping) => {
                    // Axum handles pong automatically
                    debug!("WS ping received");
                }
                Message::Text(text) => {
                    debug!("WS text from client: {}", text);
                }
                _ => {}
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }

    let remaining = api.state.ws_clients.fetch_sub(1, Ordering::Relaxed) - 1;
    info!("📡 WebSocket client disconnected (remaining: {})", remaining);
}
