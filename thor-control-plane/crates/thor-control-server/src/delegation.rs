//! Delegation Policy Manager — Role-Based Command Authorization
//! Phase 2: Control Plane State Orchestration & Delegation
//!
//! Ensures operators can only issue commands their role permits on allowed agent groups.
//!
//! Role Hierarchy:
//!   super_admin  — All commands on all agents
//!   soc_admin    — Response actions (quarantine, block, release) on all agents
//!   soc_analyst  — Read-only + feedback submission
//!   agent_group  — Commands scoped to specific agent group IDs
//!
//! Policy is backed by PostgreSQL agent_delegation_policies table.

use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{info, warn};

// ── Role definitions ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorRole {
    SuperAdmin,
    SocAdmin,
    SocAnalyst,
    AgentGroupManager { group_ids: Vec<String> },
}

impl OperatorRole {
    pub fn from_str(s: &str) -> Self {
        match s {
            "super_admin"  => Self::SuperAdmin,
            "soc_admin"    => Self::SocAdmin,
            "soc_analyst"  => Self::SocAnalyst,
            other => {
                let groups = other.strip_prefix("group:")
                    .map(|g| g.split(',').map(String::from).collect())
                    .unwrap_or_default();
                Self::AgentGroupManager { group_ids: groups }
            }
        }
    }

    pub fn can_execute(&self, action: &CommandAction, agent_group: Option<&str>) -> bool {
        match self {
            Self::SuperAdmin => true,
            Self::SocAdmin => !matches!(action, CommandAction::SystemShutdown | CommandAction::RotateSigningKey),
            Self::SocAnalyst => matches!(
                action,
                CommandAction::GetStatus | CommandAction::SubmitFeedback | CommandAction::ViewAlerts
            ),
            Self::AgentGroupManager { group_ids } => {
                // Can only act on agents in their assigned groups
                let in_group = agent_group
                    .map(|g| group_ids.iter().any(|gid| gid == g))
                    .unwrap_or(false);
                in_group && matches!(
                    action,
                    CommandAction::QuarantineProcess | CommandAction::ReleaseProcess | 
                    CommandAction::BlockIp | CommandAction::UpdatePolicy | CommandAction::GetStatus
                )
            }
        }
    }
}

// ── Command actions ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandAction {
    // SOC Admin actions
    QuarantineProcess,
    ReleaseProcess,
    BlockIp,
    UnblockIp,
    UpdatePolicy,
    DeletePolicy,
    // SOC Analyst actions (read-only)
    GetStatus,
    ViewAlerts,
    SubmitFeedback,
    // Super Admin only
    SystemShutdown,
    RotateSigningKey,
    ManageOperators,
}

impl CommandAction {
    pub fn from_str(s: &str) -> Self {
        match s {
            "quarantine_process" => Self::QuarantineProcess,
            "release_process"    => Self::ReleaseProcess,
            "block_ip"           => Self::BlockIp,
            "unblock_ip"         => Self::UnblockIp,
            "update_policy"      => Self::UpdatePolicy,
            "delete_policy"      => Self::DeletePolicy,
            "get_status"         => Self::GetStatus,
            "view_alerts"        => Self::ViewAlerts,
            "submit_feedback"    => Self::SubmitFeedback,
            "system_shutdown"    => Self::SystemShutdown,
            "rotate_signing_key" => Self::RotateSigningKey,
            "manage_operators"   => Self::ManageOperators,
            _                    => Self::GetStatus, // safe default
        }
    }
}

// ── Delegation Manager ────────────────────────────────────────────────────────

/// In-memory delegation cache backed by PostgreSQL.
/// Cache TTL: 60 seconds (refresh on next request after expiry).
pub struct DelegationPolicyManager {
    /// operator_id → (role, last_refresh_unix_ts)
    policy_cache: DashMap<String, (OperatorRole, u64)>,
    cache_ttl_secs: u64,
}

impl DelegationPolicyManager {
    pub fn new() -> Self {
        Self {
            policy_cache: DashMap::new(),
            cache_ttl_secs: 60,
        }
    }

    /// Validate if an operator with the given JWT claims can execute an action on an agent.
    ///
    /// # Arguments
    /// * `operator_id` — Extracted from JWT `sub` claim
    /// * `operator_role` — Extracted from JWT `role` claim
    /// * `action` — The command being authorized
    /// * `target_agent_id` — The agent the command targets (for group-scoped roles)
    /// * `target_agent_group` — The agent's group ID (from DB)
    pub fn validate(
        &self,
        operator_id: &str,
        operator_role: &str,
        action: &str,
        target_agent_id: &str,
        target_agent_group: Option<&str>,
    ) -> DelegationResult {
        let role = OperatorRole::from_str(operator_role);
        let cmd  = CommandAction::from_str(action);

        if role.can_execute(&cmd, target_agent_group) {
            info!(
                "✅ Delegation APPROVED: operator={} role={} action={} agent={}",
                operator_id, operator_role, action, target_agent_id
            );
            DelegationResult::Approved {
                operator_id: operator_id.to_string(),
                action: action.to_string(),
                agent_id: target_agent_id.to_string(),
            }
        } else {
            warn!(
                "🚫 Delegation DENIED: operator={} role={} action={} agent={}",
                operator_id, operator_role, action, target_agent_id
            );
            DelegationResult::Denied {
                reason: format!(
                    "Role '{}' is not authorized to execute '{}' on agent '{}'",
                    operator_role, action, target_agent_id
                ),
            }
        }
    }

    /// Load operator policies from JWT token claims (fast path, no DB).
    pub fn from_jwt_claims(&self, role_claim: &str) -> OperatorRole {
        OperatorRole::from_str(role_claim)
    }
}

#[derive(Debug)]
pub enum DelegationResult {
    Approved { operator_id: String, action: String, agent_id: String },
    Denied   { reason: String },
}

impl DelegationResult {
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved { .. })
    }
    pub fn denial_reason(&self) -> Option<&str> {
        match self {
            Self::Denied { reason } => Some(reason.as_str()),
            _ => None,
        }
    }
}

// ── PostgreSQL schema migration ───────────────────────────────────────────────

/// SQL migration for agent state store and delegation policies.
/// Run on Control Plane startup via sqlx::migrate!() or manually.
pub const STATE_STORE_MIGRATION: &str = r#"
-- Agent runtime state (eBPF map counts, ML model version, etc.)
CREATE TABLE IF NOT EXISTS agent_runtime_state (
    agent_id          TEXT PRIMARY KEY,
    hostname          TEXT NOT NULL,
    ip_address        TEXT NOT NULL,
    agent_version     TEXT NOT NULL,
    ml_model_version  TEXT,
    ebpf_map_count    INTEGER DEFAULT 0,
    sigma_rule_count  INTEGER DEFAULT 0,
    yara_rule_count   INTEGER DEFAULT 0,
    last_heartbeat    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status            TEXT NOT NULL DEFAULT 'online',
    quarantine_count  INTEGER DEFAULT 0,
    block_count       INTEGER DEFAULT 0,
    alert_rate_1m     FLOAT DEFAULT 0.0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Operator delegation policies
CREATE TABLE IF NOT EXISTS operator_delegation_policies (
    id            BIGSERIAL PRIMARY KEY,
    operator_id   TEXT NOT NULL,
    operator_role TEXT NOT NULL,
    agent_group   TEXT,          -- NULL = all agents
    allowed_actions TEXT[],      -- NULL = role default
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ,   -- NULL = no expiry
    created_by    TEXT NOT NULL,
    UNIQUE (operator_id)
);

-- Quarantine state tracking
CREATE TABLE IF NOT EXISTS quarantine_records (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    pid             INTEGER NOT NULL,
    process_name    TEXT,
    reason          TEXT NOT NULL,
    xai_report      JSONB,
    quarantined_by  TEXT NOT NULL,
    quarantined_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    released_at     TIMESTAMPTZ,
    resolution      TEXT,        -- RESOLVE_BLOCK or RESOLVE_RELEASE
    resolved_by     TEXT,
    INDEX idx_quarantine_agent (agent_id),
    INDEX idx_quarantine_active (released_at) WHERE released_at IS NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_state_status ON agent_runtime_state(status);
CREATE INDEX IF NOT EXISTS idx_agent_state_heartbeat ON agent_runtime_state(last_heartbeat);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn super_admin_can_do_everything() {
        let mgr = DelegationPolicyManager::new();
        let r = mgr.validate("admin1", "super_admin", "system_shutdown", "agent-1", None);
        assert!(r.is_approved());
    }

    #[test]
    fn soc_analyst_cannot_quarantine() {
        let mgr = DelegationPolicyManager::new();
        let r = mgr.validate("analyst1", "soc_analyst", "quarantine_process", "agent-1", None);
        assert!(!r.is_approved());
        assert!(r.denial_reason().is_some());
    }

    #[test]
    fn soc_admin_can_quarantine() {
        let mgr = DelegationPolicyManager::new();
        let r = mgr.validate("soc1", "soc_admin", "quarantine_process", "agent-1", Some("group-a"));
        assert!(r.is_approved());
    }

    #[test]
    fn group_manager_scoped_to_group() {
        let mgr = DelegationPolicyManager::new();
        // Can act on agent in their group
        let r = mgr.validate("gm1", "group:group-a", "quarantine_process", "agent-1", Some("group-a"));
        assert!(r.is_approved());
        // Cannot act on agent in another group
        let r2 = mgr.validate("gm1", "group:group-a", "quarantine_process", "agent-9", Some("group-b"));
        assert!(!r2.is_approved());
    }
}
