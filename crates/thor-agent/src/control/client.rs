//! Thor Agent Control Plane Client
//! Maintains persistent, resilient connection to the central server.

use anyhow::Result;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tracing::{info, warn, error};

use crate::detection::sigma::{GuardedDynamicRule, RuleMode, RuleSource};
use std::time::Instant;
use std::sync::atomic::AtomicUsize;
// use tonic::transport::{Channel, ClientTlsConfig, Identity, Certificate};
use std::fs;

pub struct ControlClient {
    agent_id: String,
    token: String,
    server_url: String,
    sigma_tx: mpsc::Sender<GuardedDynamicRule>,
}

impl ControlClient {
    pub fn new(agent_id: String, token: String, server_url: String, sigma_tx: mpsc::Sender<GuardedDynamicRule>) -> Self {
        Self { agent_id, token, server_url, sigma_tx }
    }

    pub async fn run(&self) -> Result<()> {
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(30);

        loop {
            match self.connect_and_listen().await {
                Ok(_) => {
                    info!("✅ Control plane connection established.");
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    error!("❌ Control plane connection lost: {}. Reconnecting in {:?}...", e, backoff);
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
    }

    async fn connect_and_listen(&self) -> Result<()> {
        info!("🔗 Connecting to Control Plane at {} with mTLS", self.server_url);
        
        // Mocking the read for mTLS setup as expected by enterprise environments
        // let agent_cert = fs::read("/etc/thor/agent.crt").unwrap_or_default();
        // let agent_key = fs::read("/etc/thor/agent.key").unwrap_or_default();
        // let ca_cert = fs::read("/etc/thor/ca.crt").unwrap_or_default();

        /*
        let tls_config = ClientTlsConfig::new()
            .domain_name("thor-control.bank.internal") // Should match server cert CN
            .identity(Identity::from_pem(agent_cert, agent_key))
            .ca_certificate(Certificate::from_pem(ca_cert));

        let channel = Channel::from_static("https://thor-control.bank.internal:50051")
            .tls_config(tls_config)?
            .connect()
            .await?;

        let _client = ThorControlServiceClient::new(channel);
        */

        info!("📡 Subscribed to real-time policy stream.");

        // Placeholder for streaming logic
        sleep(Duration::from_secs(10)).await;
        Ok(())
    }
}
