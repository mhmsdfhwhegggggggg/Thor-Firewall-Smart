//! Thor Control Plane - Unified Server

mod agent_manager;
pub mod api;
pub mod grpc;
mod state_store;
mod metrics;
mod security;
mod telemetry;
// ── Production Hardening Modules ──────────────────────────────────────────────
/// Byzantine-Robust Federated Learning Aggregation (Phase 8)
pub mod fl_aggregator;
/// Break-Glass Emergency Override Protocol (Phase 9)
pub mod break_glass;
/// Policy Canary Rollout with Auto-Rollback (Phase 10)
pub mod canary_rollout;

use anyhow::{Result, Context};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, error};
use sqlx::postgres::PgPoolOptions;
use tonic::transport::{Server, Identity, ServerTlsConfig, Certificate};
use grpc::{ThorControlServiceImpl, pb::thor_control_service_server::ThorControlServiceServer};
use axum::{routing::{get, post}, Router, Json, extract::State};

#[derive(serde::Deserialize)]
struct CreatePolicyReq {
    policy_type: String,
    rule_id: String,
    content: String,
    enforcement_mode: String,
}

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub agent_manager: Arc<AgentManager>,
    pub policy_tx: broadcast::Sender<grpc::pb::PolicyUpdate>,
    pub signing_key: Arc<ed25519_dalek::SigningKey>,
    pub state_store: Arc<state_store::RedbStateStore>,
    pub metrics: Arc<metrics::ControlMetrics>,
    /// Phase 10: Broadcast channel for HITL resolution directives
    /// Admin API sends QuarantineResolution here → grpc.rs streams to agents
    pub resolution_tx: Arc<tokio::sync::broadcast::Sender<grpc::pb::QuarantineResolution>>,
}

async fn create_policy(
    claims: api::middleware::Claims, // REMOVED Option: Mandatory JWT
    State(state): State<AppState>,
    Json(payload): Json<CreatePolicyReq>
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, &'static str)> {
    // ENFORCEMENT: Only SocL2 or SecManager can create policies
    if claims.role == api::middleware::Role::SocL1 {
        return Err((axum::http::StatusCode::FORBIDDEN, "Insufficient permissions: L1 operators cannot modify global policies."));
    }

    let created_by = claims.sub;

    // Insert to DB
    let result = sqlx::query!(
        "INSERT INTO policies (version, policy_type, rule_id, content, enforcement_mode, created_by)
         VALUES ((SELECT COALESCE(MAX(version), 0) + 1 FROM policies), $1, $2, $3, $4, $5) RETURNING version",
        payload.policy_type, payload.rule_id, payload.content, payload.enforcement_mode, created_by
    ).fetch_one(&state.db).await.map_err(|e| {
        tracing::error!("DB error: {}", e);
        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    let _ = sqlx::query!(
        "INSERT INTO audit_logs (actor_id, action, resource_type, resource_id, details)
         VALUES ($1, $2, $3, $4, $5)",
        created_by.clone(), "CREATE_POLICY", "POLICY", payload.rule_id.clone(),
        serde_json::json!({"version": result.version})
    ).execute(&state.db).await;

    // Build and Sign the update for the Action Protocol
    let mut update = grpc::pb::PolicyUpdate {
        version: result.version as i64,
        policy_type: payload.policy_type,
        rule_id: payload.rule_id,
        content: payload.content,
        action: "CREATE".to_string(),
        enforcement_mode: payload.enforcement_mode,
        signature: vec![], // To be filled
    };

    grpc::ActionProtocol::sign_policy(&state.signing_key, &mut update);

    // Broadcast to agents
    let _ = state.policy_tx.send(update);

    Ok(Json(json!({"status": "Success", "version": result.version})))
}
use tower_http::cors::{CorsLayer, Any};
use serde_json::json;

use crate::agent_manager::AgentManager;

use tokio::sync::broadcast;

// Consolidated AppState above

async fn get_dashboard(
    claims: Option<api::middleware::Claims>,
    State(state): State<AppState>
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, &'static str)> {
    // If claims are present, we could check roles, for demo we allow it
    let mut agents_db = sqlx::query!(
        "SELECT agent_id, hostname, status, ip_address, cpu_usage, memory_mb, EXTRACT(EPOCH FROM (NOW() - last_heartbeat)) as \"heartbeat_secs!\" FROM agents ORDER BY last_heartbeat DESC LIMIT 50"
    ).fetch_all(&state.db).await.map_err(|e| {
        tracing::error!("DB error: {}", e);
        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    let mut incidents_db = sqlx::query!(
        "SELECT incident_id, agent_id, severity, description, reported_at::TEXT as reported_time FROM incidents ORDER BY reported_at DESC LIMIT 50"
    ).fetch_all(&state.db).await.map_err(|e| {
        tracing::error!("DB error: {}", e);
        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    let mut agents = vec![];
    for row in agents_db {
        agents.push(json!({
            "agent_id": row.agent_id,
            "hostname": row.hostname,
            "ip_address": row.ip_address.to_string(),
            "status": row.status,
            "cpu_usage": row.cpu_usage,
            "memory_mb": row.memory_mb,
            "last_heartbeat": row.heartbeat_secs
        }));
    }

    let mut incidents = vec![];
    for row in incidents_db {
        incidents.push(json!({
            "incident_id": row.incident_id,
            "agent_id": row.agent_id,
            "severity": row.severity,
            "description": row.description,
            "reported_at": row.reported_time
        }));
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
    
    // ── Cryptographic Infrastructure (KMS/Action Protocol) ───────────────────
    let signing_key = security::KmsService::get_action_signing_key().unwrap_or_else(|e| {
        error!("🚨 CRITICAL Security Failure: KMS unavailable ({}). Generating emergency ephemeral key.", e);
        ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
    });
    let public_key = signing_key.verifying_key();
    info!("🔑 Action Protocol Public Key: {}", hex::encode(public_key.to_bytes()));

    // ── Persistent State Store (Redb) ─────────────────────────────────────────
    let state_db_path = std::env::var("THOR_STATE_DB").unwrap_or_else(|_| "thor_state.db".to_string());
    let state_store = Arc::new(state_store::RedbStateStore::open(state_db_path).context("Failed to open state store")?);

    let (policy_tx, _) = broadcast::channel(100);
    let agent_manager = Arc::new(AgentManager::new()); 
    let metrics = Arc::new(metrics::ControlMetrics::new());

    let state = // Phase 10: Resolution broadcast channel for HITL quarantine flow
    let (resolution_tx, _) = tokio::sync::broadcast::channel::<grpc::pb::QuarantineResolution>(256);

    AppState {
        db: db.clone(),
        agent_manager,
        policy_tx,
        signing_key: Arc::new(signing_key),
        state_store,
        metrics: metrics.clone(),
        resolution_tx: Arc::new(resolution_tx),
    };

    // ── Metrics Server ────────────────────────────────────────────────────────
    let metrics_addr: SocketAddr = std::env::var("THOR_METRICS_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:9091".to_string())
        .parse()?;
    let metrics_state = state.clone();
    tokio::spawn(async move {
        metrics::serve(metrics_addr, metrics_state).await;
    });

    let grpc_addr = SocketAddr::from(([0, 0, 0, 0], 50051));
    let grpc_state = state.clone();
    let grpc_server = tokio::spawn(async move {
        info!("📡 gRPC Server listening on {}", grpc_addr);
        let svc = ThorControlServiceServer::new(ThorControlServiceImpl { state: grpc_state });
        
        let tls_setup = || -> Result<ServerTlsConfig> {
            let cert_path = std::env::var("THOR_SERVER_CERT").unwrap_or_else(|_| "tls/server.crt".to_string());
            let key_path = std::env::var("THOR_SERVER_KEY").unwrap_or_else(|_| "tls/server.key".to_string());
            let ca_cert_path = std::env::var("THOR_CA_CERT").unwrap_or_else(|_| "tls/ca.crt".to_string());

            let cert = std::fs::read_to_string(&cert_path).with_context(|| format!("Missing server TLS cert at {}", cert_path))?;
            let key = std::fs::read_to_string(&key_path).with_context(|| format!("Missing server TLS key at {}", key_path))?;
            let ca_cert = std::fs::read_to_string(&ca_cert_path).with_context(|| format!("Missing CA cert at {}", ca_cert_path))?;
                
            let identity = Identity::from_pem(cert, key);
            
            // Strict mTLS: Require client cert and validate with CA
            let tls = ServerTlsConfig::new()
                .identity(identity)
                .client_ca_root(Certificate::from_pem(ca_cert));
                
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
            .route("/api/v1/policies", post(create_policy))
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

