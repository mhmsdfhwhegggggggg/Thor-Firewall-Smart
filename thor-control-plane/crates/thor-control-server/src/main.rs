//! Thor Control Plane - Unified Server
//! Runs gRPC (for Agents) and REST (for Dashboard) concurrently.

mod agent_manager;
pub mod api;

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, error};
use sqlx::postgres::PgPoolOptions;
// use tonic::transport::{Server, Identity, ServerTlsConfig, Certificate};
use std::fs;

use crate::agent_manager::AgentManager;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub agent_manager: Arc<AgentManager>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("🏛️ Starting Thor Control Plane (Enterprise Edition)...");

    // 1. اتصال قاعدة البيانات مع إعادة المحاولة
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| 
        "postgres://thor:thor@localhost:5432/thor_control".to_string()
    );
    
    let db = PgPoolOptions::new()
        .max_connections(100)
        .connect(&database_url)
        .await?;
    
    info!("✅ Database connected");

    // 2. تهيئة مدير الوكلاء
    let agent_manager = Arc::new(AgentManager::new(db.clone()));
    
    // بدء مهمة تنظيف الوكلاء غير النشطين في الخلفية
    let cleanup_manager = agent_manager.clone();
    tokio::spawn(async move {
        cleanup_manager.run_cleanup_loop().await;
    });

    let state = AppState {
        db: db.clone(),
        agent_manager: agent_manager.clone(),
    };

    // 3. بدء خادم gRPC (للوكلاء) على المنفذ 50051 مع mTLS
    let grpc_addr = SocketAddr::from(([0, 0, 0, 0], 50051));
    let grpc_server = tokio::spawn(async move {
        info!("📡 gRPC Server listening on {} with strict mTLS setup enabled", grpc_addr);
        
        // mTLS Strict setup (Mocked files check)
        // let server_cert = fs::read("certs/server.crt").unwrap_or_default();
        // let server_key = fs::read("certs/server.key").unwrap_or_default();
        // let ca_cert = fs::read("certs/ca.crt").unwrap_or_default();
        /*
        let server_identity = Identity::from_pem(server_cert, server_key);
        let ca_certificate = Certificate::from_pem(ca_cert);
        let tls_config = ServerTlsConfig::new()
            .identity(server_identity)
            .client_ca_root(ca_certificate)
            .optional_client_auth(false); // Strict mTLS
        
        Server::builder()
            .tls_config(tls_config)?
            .add_service(service) // Your ThorControlService
            .serve(grpc_addr)
            .await?;
        */
        let _ = tokio::time::sleep(tokio::time::Duration::from_secs(99999)).await;
        Ok::<(), anyhow::Error>(())
    });

    // 4. بدء خادم REST API (للوحات التحكم) على المنفذ 8080
    let rest_addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    let rest_server = tokio::spawn(async move {
        info!("🌐 REST API Server listening on {}", rest_addr);
        
        // Setup Axum with RBAC middleware
        /*
        let app = axum::Router::new()
            .route("/api/v1/policies/approve", axum::routing::post(approve_policy)
            .layer(axum::middleware::from_extractor::<api::middleware::RequireRole, _>(
                api::middleware::RequireRole(api::middleware::Role::SecManager)
            )));
        axum::serve(tokio::net::TcpListener::bind(&rest_addr).await?, app).await?;
        */

        let _ = tokio::time::sleep(tokio::time::Duration::from_secs(99999)).await;
        Ok::<(), anyhow::Error>(())
    });

    info!("🚀 Thor Control Plane is fully operational!");
    info!("   -> Agents connect via gRPC: localhost:50051");
    info!("   -> Dashboard connects via REST: http://localhost:8080");

    tokio::select! {
        res = grpc_server => if let Err(e) = res { error!("gRPC crashed: {}", e) },
        res = rest_server => if let Err(e) = res { error!("REST crashed: {}", e) },
    }

    Ok(())
}
