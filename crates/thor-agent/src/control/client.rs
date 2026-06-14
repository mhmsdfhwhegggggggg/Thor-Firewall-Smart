//! Thor Agent Control Plane Client
//! Maintains persistent, resilient connection to the central server.

use anyhow::{Result, Context};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tracing::{info, warn, error};
use tonic::transport::{Channel, ClientTlsConfig, Identity, Certificate};
use std::fs;

use crate::detection::sigma::{GuardedDynamicRule, RuleMode, RuleSource};
use std::time::Instant;
use std::sync::atomic::AtomicUsize;

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
        info!("🔗 Connecting to Control Plane at {} with STRICT mTLS", self.server_url);
        
        let agent_cert_path = std::env::var("THOR_AGENT_CERT").unwrap_or_else(|_| "/etc/thor/agent.crt".into());
        let agent_key_path = std::env::var("THOR_AGENT_KEY").unwrap_or_else(|_| "/etc/thor/agent.key".into());
        let ca_cert_path = std::env::var("THOR_CA_CERT").unwrap_or_else(|_| "/etc/thor/ca.crt".into());

        let agent_cert = fs::read(&agent_cert_path).with_context(|| format!("Missing agent cert at {}", agent_cert_path))?;
        let agent_key = fs::read(&agent_key_path).with_context(|| format!("Missing agent key at {}", agent_key_path))?;
        let ca_cert = fs::read(&ca_cert_path).with_context(|| format!("Missing CA cert at {}", ca_cert_path))?;

        let tls_config = ClientTlsConfig::new()
            .domain_name("thor-control.bank.internal") // Ensure SNI matches Server Certificate CN
            .identity(Identity::from_pem(agent_cert, agent_key))
            .ca_certificate(Certificate::from_pem(ca_cert));

        let channel = Channel::from_shared(self.server_url.clone())?
            .tls_config(tls_config)?
            .connect()
            .await?;

        // Implementation of ThorControlServiceClient streaming will be added here
        // let mut client = ThorControlServiceClient::new(channel);

        info!("📡 Subscribed to real-time policy stream.");

        // Placeholder for streaming logic loop
        loop {
            sleep(Duration::from_secs(10)).await;
        }
    }
}
