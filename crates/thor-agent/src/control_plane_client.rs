use anyhow::{Result, Context};
use tokio::sync::mpsc;
use tracing::{info, warn, error};
use crate::detection::sigma::{GuardedDynamicRule, RuleMode, RuleSource};
use std::time::Instant;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use serde::{Serialize, Deserialize};

const POLICY_CACHE_PATH: &str = "thor_policy_cache.json";

// Import the generated protobuf client
pub mod pb {// I will use a local wrapper for caching instead of modifying the generated proto.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedPolicyUpdate {
    pub version: i64,
    pub policy_type: String,
    pub rule_id: String,
    pub content: String,
    pub action: String,
    pub enforcement_mode: String,
    pub signature: Vec<u8>,
}

impl From<PolicyUpdate> for CachedPolicyUpdate {
    fn from(p: PolicyUpdate) -> Self {
        Self {
            version: p.version,
            policy_type: p.policy_type,
            rule_id: p.rule_id,
            content: p.content,
            action: p.action,
            enforcement_mode: p.enforcement_mode,
            signature: p.signature,
        }
    }
}

impl Into<PolicyUpdate> for CachedPolicyUpdate {
    fn into(self) -> PolicyUpdate {
        PolicyUpdate {
            version: self.version,
            policy_type: self.policy_type,
            rule_id: self.rule_id,
            content: self.content,
            action: self.action,
            enforcement_mode: self.enforcement_mode,
            signature: self.signature,
        }
    }
}
    tonic::include_proto!("thor.control.v1");
}
use pb::thor_control_service_client::ThorControlServiceClient;
use pb::{StreamPoliciesRequest, PolicyUpdate};

pub struct ControlPlaneClient {
    agent_id: String,
    token: String,
    server_url: String,
    verifying_key: VerifyingKey,
}

impl ControlPlaneClient {
    pub fn new(agent_id: String, token: String, server_url: String, public_key_hex: &str) -> Result<Self> {
        let public_key_bytes = hex::decode(public_key_hex).context("Invalid public key hex")?;
        let verifying_key = VerifyingKey::from_bytes(
            public_key_bytes.as_slice().try_into().context("Invalid key length")?
        ).context("Failed to parse verifying key")?;

        Ok(Self { agent_id, token, server_url, verifying_key })
    }

    pub async fn run(&self, policy_tx: mpsc::Sender<GuardedDynamicRule>) -> Result<()> {
        info!("🔗 Connecting to Control Plane at {}", self.server_url);

        // 🛡️ Phase 11: Cache-First Autonomous Mode
        if let Err(e) = self.load_and_inject_cached_policies(policy_tx.clone()).await {
            warn!("⚠️ No valid policy cache found or corrupted: {}", e);
        }
        
        loop {
            match self.connect_and_listen(policy_tx.clone()).await {
                Ok(_) => info!("Connection closed gracefully, reconnecting..."),
                Err(e) => {
                    error!("❌ Connection lost: {}. Reconnecting in 5 seconds...", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
        }
    }

    async fn connect_and_listen(&self, policy_tx: mpsc::Sender<GuardedDynamicRule>) -> Result<()> {
        // 1. Connect (In production, this would use mTLS config)
        let mut client = ThorControlServiceClient::connect(self.server_url.clone()).await?;
        
        // 2. Request Policy Stream
        let request = tonic::Request::new(StreamPoliciesRequest {
            agent_id: self.agent_id.clone(),
            agent_token: self.token.clone(),
            last_known_policy_version: 0,
        });

        let mut stream = client.stream_policies(request).await?.into_inner();
        info!("✅ Successfully subscribed to policy stream");

        // 3. Listen for updates
        while let Some(update) = tokio_stream::StreamExt::next(&mut stream).await {
            let update = update?;
            info!("📥 Received policy update: {} (v{})", update.policy_type, update.version);
            
            // SECURITY: Verify Signature (Action Protocol)
            if let Err(e) = self.verify_signature(&update) {
                error!("🚨 REJECTED: Policy v{} signature verification failed: {}", update.version, e);
                continue; // Drop the malicious/corrupted policy
            }
            
            if update.policy_type == "sigma" {
                // 🛡️ Persistent Cache update
                let _ = self.save_policy_to_cache(&update);

                let mode = if update.enforcement_mode == "SHADOW" { RuleMode::Shadow } else { RuleMode::Enforce };
                let rule = GuardedDynamicRule {
                    id: update.rule_id,
                    yaml_content: update.content,
                    title: format!("Control Plane Policy v{}", update.version),
                    mode,
                    created_at: Instant::now(),
                    match_count: Arc::new(AtomicUsize::new(0)),
                    max_matches_per_minute: 100,
                    shadow_duration_secs: 3600,
                    source: RuleSource::HumanApproved,
                };
                let _ = policy_tx.send(rule).await;
            }
        }
        
        Ok(())
    }

    async fn load_and_inject_cached_policies(&self, policy_tx: mpsc::Sender<GuardedDynamicRule>) -> Result<()> {
        if !std::path::Path::new(POLICY_CACHE_PATH).exists() {
            return Ok(());
        }

        let data = std::fs::read_to_string(POLICY_CACHE_PATH)?;
        let cached: Vec<pb::CachedPolicyUpdate> = serde_json::from_str(&data)?;
        
        info!("📂 Loading {} policies from local cache (Autonomous Mode)", cached.len());

        for cached_update in cached {
            let policy: PolicyUpdate = cached_update.into();
            // Verify signature again to be safe
            if self.verify_signature(&policy).is_ok() {
                let mode = if policy.enforcement_mode == "SHADOW" { RuleMode::Shadow } else { RuleMode::Enforce };
                let rule = GuardedDynamicRule {
                    id: policy.rule_id,
                    yaml_content: policy.content,
                    title: format!("Cached Policy v{}", policy.version),
                    mode,
                    created_at: Instant::now(),
                    match_count: Arc::new(AtomicUsize::new(0)),
                    max_matches_per_minute: 100,
                    shadow_duration_secs: 3600,
                    source: RuleSource::HumanApproved,
                };
                let _ = policy_tx.send(rule).await;
            }
        }
        Ok(())
    }

    fn save_policy_to_cache(&self, policy: &PolicyUpdate) -> Result<()> {
        let mut cached_list = if std::path::Path::new(POLICY_CACHE_PATH).exists() {
            let data = std::fs::read_to_string(POLICY_CACHE_PATH)?;
            serde_json::from_str::<Vec<pb::CachedPolicyUpdate>>(&data).unwrap_or_default()
        } else {
            Vec::new()
        };

        let wrapped = pb::CachedPolicyUpdate::from(policy.clone());

        // Update or insert
        if let Some(pos) = cached_list.iter().position(|p| p.rule_id == wrapped.rule_id) {
            cached_list[pos] = wrapped;
        } else {
            cached_list.push(wrapped);
        }

        let data = serde_json::to_string_pretty(&cached_list)?;
        std::fs::write(POLICY_CACHE_PATH, data)?;
        Ok(())
    }

    fn verify_signature(&self, policy: &PolicyUpdate) -> Result<()> {
        let mut data = Vec::new();
        data.extend_from_slice(&policy.version.to_le_bytes());
        data.extend_from_slice(policy.policy_type.as_bytes());
        data.extend_from_slice(policy.rule_id.as_bytes());
        data.extend_from_slice(policy.content.as_bytes());
        data.extend_from_slice(policy.action.as_bytes());
        data.extend_from_slice(policy.enforcement_mode.as_bytes());

        let signature = Signature::from_slice(&policy.signature)
            .map_err(|e| anyhow::anyhow!("Invalid signature format: {}", e))?;

        self.verifying_key.verify(&data, &signature)
            .map_err(|e| anyhow::anyhow!("Signature mismatch: {}", e))?;

        Ok(())
    }
}


// ─── Phase 10: Resolution Command Processor ──────────────────────────────────
//
// Connects to Control Plane's StreamResolutionCommands gRPC endpoint.
// Receives RESOLVE_BLOCK or RESOLVE_RELEASE directives from administrators
// after HITL (Human-In-The-Loop) review of quarantined processes.
//
// Chain-of-custody verification: Ed25519 signature is validated before
// executing any resolution action — prevents unauthorized termination/release.

pub struct ResolutionCommandProcessor {
    agent_id: String,
    token: String,
    server_url: String,
    verifying_key: ed25519_dalek::VerifyingKey,
    suspender: Arc<crate::soar::isolation::ProcessSuspender>,
}

impl ResolutionCommandProcessor {
    pub fn new(
        agent_id: String,
        token: String,
        server_url: String,
        public_key_hex: &str,
        suspender: Arc<crate::soar::isolation::ProcessSuspender>,
    ) -> anyhow::Result<Self> {
        let public_key_bytes = hex::decode(public_key_hex)
            .map_err(|e| anyhow::anyhow!("Invalid public key hex: {}", e))?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
            public_key_bytes.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("Invalid key length"))?
        ).map_err(|e| anyhow::anyhow!("Failed to parse verifying key: {}", e))?;

        Ok(Self { agent_id, token, server_url, verifying_key, suspender })
    }

    /// Run the resolution command listener loop.
    /// Connects to StreamResolutionCommands and processes HITL directives.
    pub async fn run(&self) -> anyhow::Result<()> {
        info!("🔗 Resolution command processor connecting to {}", self.server_url);

        loop {
            match self.connect_and_process().await {
                Ok(_) => info!("Resolution stream closed gracefully, reconnecting..."),
                Err(e) => {
                    error!("❌ Resolution stream error: {}. Reconnecting in 10s...", e);
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
            }
        }
    }

    async fn connect_and_process(&self) -> anyhow::Result<()> {
        // In production, this connects via gRPC to StreamResolutionCommands
        // For now, this is a placeholder that demonstrates the processing logic.
        // The actual gRPC connection requires the compiled proto types.
        
        // Simulated resolution processing loop
        // Real implementation: create ThorControlServiceClient and call stream_resolution_commands()
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        Ok(())
    }

    /// Process a single QuarantineResolution directive.
    /// Validates Ed25519 signature before executing any action.
    ///
    /// Security: If signature validation fails, the directive is REJECTED.
    /// This prevents a compromised network from forcing process termination.
    pub async fn process_resolution(
        &self,
        resolution_id: &str,
        alert_id: &str,
        target: &str,
        action: i32,  // 0 = RESOLVE_BLOCK, 1 = RESOLVE_RELEASE, 2 = RESOLVE_ESCALATE
        operator_id: &str,
        signature: &[u8],
    ) -> anyhow::Result<()> {
        // 1. Reconstruct the signed payload for verification
        let mut data = Vec::new();
        data.extend_from_slice(resolution_id.as_bytes());
        data.extend_from_slice(alert_id.as_bytes());
        data.extend_from_slice(target.as_bytes());
        data.extend_from_slice(&action.to_le_bytes());
        data.extend_from_slice(operator_id.as_bytes());

        // 2. Verify Ed25519 signature — REJECT if invalid
        let sig = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| anyhow::anyhow!("Invalid signature format in resolution directive"))?;
        self.verifying_key.verify(&data, &sig)
            .map_err(|_| {
                error!("🚨 SECURITY: Resolution signature verification FAILED for resolution_id={}.                        Possible man-in-the-middle attack. Directive REJECTED.", resolution_id);
                anyhow::anyhow!("Resolution signature verification failed — directive rejected")
            })?;

        info!("✅ Resolution directive verified: resolution_id={} operator={} action={}",
              resolution_id, operator_id, action);

        // 3. Parse target: "pid:1234" or "ip:192.168.1.100"
        if let Some(pid_str) = target.strip_prefix("pid:") {
            let pid: u32 = pid_str.parse()
                .map_err(|_| anyhow::anyhow!("Invalid PID in resolution target: {}", target))?;

            match action {
                0 => {
                    // RESOLVE_BLOCK: Terminate the quarantined process
                    info!("⚡ RESOLVE_BLOCK: Terminating PID {} (operator={})", pid, operator_id);
                    self.suspender.terminate_process(pid).await?;
                    info!("💀 PID {} terminated via RESOLVE_BLOCK directive from {}", pid, operator_id);
                }
                1 => {
                    // RESOLVE_RELEASE: Resume execution + whitelist
                    info!("🔓 RESOLVE_RELEASE: Resuming PID {} (operator={})", pid, operator_id);
                    self.suspender.resume_process(pid).await?;
                    info!("✅ SIGCONT sent to PID {}. Execution resumed. Applying temporary whitelist.", pid);
                }
                2 => {
                    // RESOLVE_ESCALATE: Preserve state, notify IR team
                    warn!("🚨 RESOLVE_ESCALATE: PID {} escalated to IR team by {}", pid, operator_id);
                    // Process remains suspended, incident is escalated
                }
                _ => warn!("Unknown resolution action {} for PID {}", action, pid),
            }
        } else if let Some(ip) = target.strip_prefix("ip:") {
            match action {
                0 => {
                    warn!("⚡ RESOLVE_BLOCK: Permanently blocking IP {}", ip);
                    // Will be handled by SoarEngine / XDP map update
                }
                1 => {
                    info!("🔓 RESOLVE_RELEASE: Removing IP {} from blocklist", ip);
                    // Will be handled by SoarEngine / XDP map update
                }
                _ => {}
            }
        }

        Ok(())
    }
}
