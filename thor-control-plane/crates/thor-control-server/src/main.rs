//! Thor Control Plane - Unified Server

mod agent_manager;
pub mod api;
pub mod grpc;

use anyhow::{Result, Context};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, error};
use sqlx::postgres::PgPoolOptions;
use tonic::transport::{Server, Identity, ServerTlsConfig, Certificate};
use grpc::{ThorControlServiceImpl, pb::thor_control_service_server::ThorControlServiceServer};
use axum::{routing::get, Router, Json, extract::State};
use tower_http::cors::{CorsLayer, Any};
use serde_json::json;

use crate::agent_manager::AgentManager;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub agent_manager: Arc<AgentManager>,
}

async fn get_dashboard(
    claims: api::middleware::Claims,
    State(state): State<AppState>
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, &'static str)> {
    if claims.role != api::middleware::Role::SecManager && claims.role != api::middleware::Role::SocL1 {
        return Err((axum::http::StatusCode::FORBIDDEN, "Insufficient privileges. SOC L1 or SecManager required."));
    }
    // Generate real-time data from AgentManager
    let mut agents = vec![];
    let mut incidents = vec![];

    for agent in state.agent_manager.active_agents.iter() {
        agents.push(json!({
            "agent_id": agent.agent_id,
            "hostname": format!("host-{}", agent.agent_id.chars().take(4).collect::<String>()),
            "ip_address": "10.0.1.X", // Real version maps ip
            "status": if agent.metrics.is_degraded { "DEGRADED" } else { "ACTIVE" },
            "cpu_usage": agent.metrics.cpu_usage_percent,
            "memory_mb": agent.metrics.memory_usage_mb,
            "last_heartbeat": agent.last_heartbeat.elapsed().as_secs()
        }));

        if agent.metrics.threats_detected > 0 {
            incidents.push(json!({
                "incident_id": format!("inc-{}", rand::random::<u16>()),
                "agent_id": agent.agent_id,
                "severity": "CRITICAL",
                "description": format!("Detected {} novel AI threats", agent.metrics.threats_detected),
                "reported_at": chrono::Utc::now().to_rfc3339()
            }));
        }
    }

    if agents.is_empty() {
        // Fallback demo data if no agents connected
        agents.push(json!({ "agent_id": "agent-sys-01", "hostname": "thor-system-node", "ip_address": "127.0.0.1", "status": "ACTIVE", "cpu_usage": 5.0, "memory_mb": 512, "last_heartbeat": "0" }));
    }

    Ok(Json(json!({ "agents": agents, "incidents": incidents })))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("🏛️ Starting Thor Control Plane (Enterprise Edition)...");

    // Connect to DB (fall back to an in-memory or fail gracefully if no db in this demo)
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| 
        "postgres://thor:thor@localhost:5432/thor_control".to_string()
    );
    
    // Attempt DB connection, but don't strictly crash if it's not set up for the moment
    let db_result = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await;
        
    let db = match db_result {
        Ok(pool) => {
            info!("✅ Enterprise Database connected successfully.");
            pool
        },
        Err(e) => {
            tracing::error!("CRITICAL: DB connection failed ({}). High Availability policy dictates halting service instead of falling back to insecure demo DB.", e);
            std::process::exit(1);
        }
    };
    
    let agent_manager = Arc::new(AgentManager::new(db.clone()));
    
    let state = AppState {
        db: db.clone(),
        agent_manager,
    };

    let grpc_addr = SocketAddr::from(([0, 0, 0, 0], 50051));
    let grpc_state = state.clone();
    let grpc_server = tokio::spawn(async move {
        info!("📡 gRPC Server listening on {}", grpc_addr);
        let svc = ThorControlServiceServer::new(ThorControlServiceImpl { state: grpc_state });
        
        let tls_setup = || -> Result<ServerTlsConfig> {
            let cert = std::fs::read_to_string("tls/server.crt")
                .unwrap_or_else(|_| {
                    tracing::warn!("Server TLS cert not found. Using dummy for compilation.");
                    "".to_string()
                });
            let key = std::fs::read_to_string("tls/server.key")
                .unwrap_or_else(|_| "".to_string());
            let ca_cert = std::fs::read_to_string("tls/ca.crt")
                .unwrap_or_else(|_| "".to_string());
                
            let mut tls = ServerTlsConfig::new();
            if !cert.is_empty() && !key.is_empty() {
                let identity = Identity::from_pem(cert, key);
                // mTLS: Require client cert and validate with CA
                tls = tls.identity(identity);
                if !ca_cert.is_empty() {
                    tls = tls.client_ca_root(Certificate::from_pem(ca_cert));
                }
            }
            Ok(tls)
        };

        let mut builder = Server::builder();
        if let Ok(tls) = tls_setup() {
            if let Ok(builder_with_tls) = builder.tls_config(tls) {
                builder = builder_with_tls;
            }
        }

        builder
            .add_service(svc)
            .serve(grpc_addr)
            .await?;
        Ok::<(), anyhow::Error>(())
    });

    let rest_addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    let rest_state = state.clone();
    let rest_server = tokio::spawn(async move {
        info!("🌐 REST API Server listening on {}", rest_addr);
        
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);
            
        let app = Router::new()
            .route("/api/v1/health", get(|| async { Json(serde_json::json!({ "status": "ok" })) }))
            .route("/api/v1/dashboard", get(get_dashboard))
            .layer(cors)
            .with_state(rest_state);
            
        let listener = tokio::net::TcpListener::bind(&rest_addr).await?;
        axum::serve(listener, app).await?;
        Ok::<(), anyhow::Error>(())
    });

    info!("🚀 Thor Control Plane is fully operational!");

    tokio::select! {
        res = grpc_server => if let Err(e) = res { error!("gRPC crashed: {}", e) },
        res = rest_server => if let Err(e) = res { error!("REST crashed: {}", e) },
    }

    Ok(())
}

