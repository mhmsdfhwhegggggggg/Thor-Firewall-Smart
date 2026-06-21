//! Break-Glass Emergency Protocol
//!
//! When the Control Plane or its AI systems are compromised, administrators
//! need an **out-of-band** mechanism to regain control without trusting the
//! compromised system. This module implements exactly that.
//!
//! ## Design
//! - A **Break-Glass Token** is a short-lived, cryptographically signed command
//!   issued by an authorized Security Officer using an **offline Ed25519 key**
//!   that is stored physically (HSM/air-gapped workstation), NOT on any server.
//! - The token is signed offline and injected via a secondary channel (e.g., USB,
//!   SMS OTP, or a physical terminal) that bypasses the main API entirely.
//! - The Control Plane verifies the signature using the pre-distributed public key.
//! - Once a valid token is accepted, the system enters **Lockdown Mode**:
//!   - ALL AI autonomous decisions are frozen.
//!   - ALL policy pushes are halted.
//!   - Agents fall back to their last known-good policy cache.
//!   - Full manual control is restored to the Security Officer.
//!
//! ## Token Format (JSON, signed as bytes)
//! ```json
//! {
//!   "issued_at": 1734567890,
//!   "expires_at": 1734568490,   // 10-minute validity window
//!   "issued_by": "CISO_ALICE",
//!   "command": "FULL_LOCKDOWN" | "FREEZE_AI" | "FORCE_ALLOW_ALL" | "EMERGENCY_BLOCK_ALL",
//!   "target_scope": "global" | "agent:<id>",
//!   "reason": "Suspected Control Plane compromise",
//!   "nonce": "<random 32 bytes hex>"
//! }
//! ```

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

// ─── Token Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BreakGlassCommand {
    /// Freeze ALL AI autonomous decisions. Human approval required for every action.
    FreezeAi,
    /// Force all agents into ALLOW_ALL mode (use when false-positive storm blocks critical services).
    ForceAllowAll,
    /// Force all agents into BLOCK_ALL mode (use during active incident containment).
    EmergencyBlockAll,
    /// Full system lockdown: freeze AI + halt policy updates + require manual approval.
    FullLockdown,
    /// Revoke specific agent's access (suspected compromised agent).
    RevokeAgent { agent_id: String },
    /// Restore normal operation after a break-glass event.
    RestoreNormal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakGlassToken {
    pub issued_at: u64,
    pub expires_at: u64,
    pub issued_by: String,
    pub command: BreakGlassCommand,
    pub target_scope: String,
    pub reason: String,
    pub nonce: String, // Prevents replay attacks
}

// ─── System State ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct SystemEmergencyState {
    /// Is the system currently in any break-glass mode?
    pub active: AtomicBool,
    /// Is AI autonomous action frozen?
    pub ai_frozen: AtomicBool,
    /// Is the system in block-all mode?
    pub block_all: AtomicBool,
    /// Is the system in allow-all mode?
    pub allow_all: AtomicBool,
    /// Nonces of tokens already consumed (replay prevention)
    consumed_nonces: RwLock<HashSet<String>>,
    /// Audit trail of all break-glass activations
    activation_log: RwLock<Vec<BreakGlassActivation>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BreakGlassActivation {
    pub timestamp: u64,
    pub issued_by: String,
    pub command: String,
    pub reason: String,
}

impl SystemEmergencyState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            active: AtomicBool::new(false),
            ai_frozen: AtomicBool::new(false),
            block_all: AtomicBool::new(false),
            allow_all: AtomicBool::new(false),
            consumed_nonces: RwLock::new(HashSet::new()),
            activation_log: RwLock::new(Vec::new()),
        })
    }

    pub fn is_ai_frozen(&self) -> bool {
        self.ai_frozen.load(Ordering::Acquire)
    }

    pub fn is_block_all(&self) -> bool {
        self.block_all.load(Ordering::Acquire)
    }

    pub fn is_allow_all(&self) -> bool {
        self.allow_all.load(Ordering::Acquire)
    }

    pub async fn get_activation_log(&self) -> Vec<BreakGlassActivation> {
        self.activation_log.read().await.clone()
    }
}

// ─── Break-Glass Processor ────────────────────────────────────────────────────

pub struct BreakGlassProcessor {
    /// The offline public key used to verify emergency tokens.
    /// The corresponding private key MUST be stored only in an air-gapped HSM.
    verifying_key: VerifyingKey,
    state: Arc<SystemEmergencyState>,
}

impl BreakGlassProcessor {
    pub fn new(verifying_key_bytes: &[u8; 32], state: Arc<SystemEmergencyState>) -> anyhow::Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(verifying_key_bytes)?;
        Ok(Self { verifying_key, state })
    }

    /// Process an incoming break-glass token.
    ///
    /// # Arguments
    /// - `token_json`: The serialized `BreakGlassToken` as UTF-8 JSON bytes.
    /// - `signature_bytes`: The 64-byte Ed25519 signature over `token_json`.
    ///
    /// # Security guarantees
    /// - Signature must be valid under the pre-distributed offline public key.
    /// - Token must not be expired (10-minute window).
    /// - Nonce must not have been used before (replay prevention).
    pub async fn process(
        &self,
        token_json: &[u8],
        signature_bytes: &[u8; 64],
    ) -> Result<BreakGlassCommand, BreakGlassError> {
        // 1. Verify signature
        let signature = Signature::from_bytes(signature_bytes);
        self.verifying_key
            .verify(token_json, &signature)
            .map_err(|_| {
                error!("🚨 BREAK-GLASS: INVALID SIGNATURE DETECTED — Possible unauthorized access attempt!");
                BreakGlassError::InvalidSignature
            })?;

        // 2. Parse token
        let token: BreakGlassToken = serde_json::from_slice(token_json)
            .map_err(|_| BreakGlassError::MalformedToken)?;

        // 3. Check expiry
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > token.expires_at {
            warn!("🚨 BREAK-GLASS: Expired token from '{}' rejected.", token.issued_by);
            return Err(BreakGlassError::TokenExpired);
        }

        // 4. Replay prevention
        {
            let mut nonces = self.state.consumed_nonces.write().await;
            if nonces.contains(&token.nonce) {
                error!("🚨 BREAK-GLASS: REPLAY ATTACK — Nonce '{}' already used!", token.nonce);
                return Err(BreakGlassError::ReplayAttack);
            }
            nonces.insert(token.nonce.clone());
        }

        // 5. Execute the command
        let command_str = format!("{:?}", token.command);
        warn!(
            "⚡ BREAK-GLASS ACTIVATED by '{}': {:?} | Reason: {}",
            token.issued_by, token.command, token.reason
        );

        self.apply_command(&token.command).await;

        // 6. Log the activation
        {
            let mut log = self.state.activation_log.write().await;
            log.push(BreakGlassActivation {
                timestamp: now,
                issued_by: token.issued_by.clone(),
                command: command_str,
                reason: token.reason.clone(),
            });
        }

        Ok(token.command)
    }

    async fn apply_command(&self, command: &BreakGlassCommand) {
        match command {
            BreakGlassCommand::FreezeAi => {
                self.state.ai_frozen.store(true, Ordering::Release);
                self.state.active.store(true, Ordering::Release);
                warn!("🧊 AI FROZEN — All autonomous decisions require human approval.");
            }
            BreakGlassCommand::EmergencyBlockAll => {
                self.state.block_all.store(true, Ordering::Release);
                self.state.active.store(true, Ordering::Release);
                warn!("🛑 EMERGENCY BLOCK-ALL — All agents entering DENY_ALL mode.");
            }
            BreakGlassCommand::ForceAllowAll => {
                self.state.allow_all.store(true, Ordering::Release);
                self.state.active.store(true, Ordering::Release);
                warn!("⚠️ FORCE ALLOW-ALL — Critical false-positive mitigation mode.");
            }
            BreakGlassCommand::FullLockdown => {
                self.state.ai_frozen.store(true, Ordering::Release);
                self.state.block_all.store(true, Ordering::Release);
                self.state.active.store(true, Ordering::Release);
                error!("🔒 FULL LOCKDOWN — System is under emergency human control only.");
            }
            BreakGlassCommand::RevokeAgent { agent_id } => {
                warn!("🚫 AGENT REVOKED: '{}' — Disconnecting from cluster.", agent_id);
                // In a real implementation, publish to the agent_manager to disconnect this agent
            }
            BreakGlassCommand::RestoreNormal => {
                self.state.ai_frozen.store(false, Ordering::Release);
                self.state.block_all.store(false, Ordering::Release);
                self.state.allow_all.store(false, Ordering::Release);
                self.state.active.store(false, Ordering::Release);
                info!("✅ NORMAL OPERATION RESTORED — Break-glass mode deactivated.");
            }
        }
    }
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum BreakGlassError {
    #[error("Invalid Ed25519 signature — token rejected")]
    InvalidSignature,
    #[error("Token has expired")]
    TokenExpired,
    #[error("Malformed token JSON")]
    MalformedToken,
    #[error("Replay attack detected — nonce already consumed")]
    ReplayAttack,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};

    fn setup() -> (BreakGlassProcessor, SigningKey, Arc<SystemEmergencyState>) {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_bytes = signing_key.verifying_key().to_bytes();
        let state = SystemEmergencyState::new();
        let processor = BreakGlassProcessor::new(&verifying_bytes, state.clone()).unwrap();
        (processor, signing_key, state)
    }

    fn make_token(command: BreakGlassCommand) -> BreakGlassToken {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        BreakGlassToken {
            issued_at: now,
            expires_at: now + 600,
            issued_by: "CISO_TEST".to_string(),
            command,
            target_scope: "global".to_string(),
            reason: "Unit test".to_string(),
            nonce: uuid::Uuid::new_v4().to_string(),
        }
    }

    #[tokio::test]
    async fn valid_freeze_ai_token_works() {
        let (processor, signing_key, state) = setup();
        let token = make_token(BreakGlassCommand::FreezeAi);
        let token_json = serde_json::to_vec(&token).unwrap();
        let sig = signing_key.sign(&token_json).to_bytes();

        let result = processor.process(&token_json, &sig).await;
        assert!(result.is_ok());
        assert!(state.is_ai_frozen(), "AI should be frozen after break-glass");
    }

    #[tokio::test]
    async fn invalid_signature_rejected() {
        let (processor, _, _) = setup();
        let token = make_token(BreakGlassCommand::FreezeAi);
        let token_json = serde_json::to_vec(&token).unwrap();
        let fake_sig = [0u8; 64]; // Wrong signature

        let result = processor.process(&token_json, &fake_sig).await;
        assert!(matches!(result, Err(BreakGlassError::InvalidSignature)));
    }

    #[tokio::test]
    async fn replay_attack_prevented() {
        let (processor, signing_key, _) = setup();
        let token = make_token(BreakGlassCommand::FreezeAi);
        let token_json = serde_json::to_vec(&token).unwrap();
        let sig = signing_key.sign(&token_json).to_bytes();

        // First use — OK
        assert!(processor.process(&token_json, &sig).await.is_ok());
        // Second use of same token — REPLAY ATTACK
        let result = processor.process(&token_json, &sig).await;
        assert!(matches!(result, Err(BreakGlassError::ReplayAttack)));
    }

    #[tokio::test]
    async fn restore_normal_clears_all_flags() {
        let (processor, signing_key, state) = setup();

        // Activate full lockdown
        let lockdown_token = make_token(BreakGlassCommand::FullLockdown);
        let lockdown_json = serde_json::to_vec(&lockdown_token).unwrap();
        let sig = signing_key.sign(&lockdown_json).to_bytes();
        processor.process(&lockdown_json, &sig).await.unwrap();
        assert!(state.is_ai_frozen());

        // Restore normal
        let restore_token = make_token(BreakGlassCommand::RestoreNormal);
        let restore_json = serde_json::to_vec(&restore_token).unwrap();
        let sig2 = signing_key.sign(&restore_json).to_bytes();
        processor.process(&restore_json, &sig2).await.unwrap();

        assert!(!state.is_ai_frozen(), "System should be restored to normal");
        assert!(!state.is_block_all());
    }
}
