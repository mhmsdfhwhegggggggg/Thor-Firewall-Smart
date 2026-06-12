//! Axum API server — REST + WebSocket + Swagger/OpenAPI docs

pub mod handlers;
pub mod ws;

use axum::{Router, routing::get};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tower_http::compression::CompressionLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use anyhow::Result;
use tracing::info;

use crate::state::ThorState;
use crate::events::Alert;

#[derive(Clone)]
pub struct ApiState {
    pub state: Arc<ThorState>,
    pub alert_rx: flume::Receiver<Alert>,
}

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::health,
        handlers::get_stats,
        handlers::get_recent_alerts,
    ),
    components(schemas(
        crate::state::StateStats,
        crate::events::Alert,
    )),
    info(
        title = "Thor Firewall Smart API",
        version = "0.1.0",
        description = "Real-time cybersecurity platform API",
    )
)]
struct ApiDoc;

pub async fn start_api_server(addr: SocketAddr, api_state: ApiState) -> Result<()> {
    let app = Router::new()
        // Health check (Kubernetes/LB probe)
        .route("/health", get(handlers::health))
        // Stats
        .route("/api/v1/stats", get(handlers::get_stats))
        // Recent alerts
        .route("/api/v1/alerts/recent", get(handlers::get_recent_alerts))
        // WebSocket real-time events
        .route("/ws/events", get(ws::ws_handler))
        // Swagger UI
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        // Middleware
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .with_state(api_state);

    info!("🌐 Starting API server on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
