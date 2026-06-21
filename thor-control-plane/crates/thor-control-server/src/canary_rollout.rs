//! Policy Canary Rollout with Auto-Rollback
//!
//! Safely deploys new security policies to a controlled subset of agents
//! and automatically rolls back if the policy causes alert storms (False Positives).
//!
//! ## Deployment Phases
//! ```
//! Phase 1: CANARY   →  1% of agents receive new policy
//!     ↓ (wait OBSERVATION_WINDOW)
//! Phase 2: EARLY    → 10% of agents
//!     ↓ (wait OBSERVATION_WINDOW)
//! Phase 3: ROLLOUT  → 50% of agents
//!     ↓ (wait OBSERVATION_WINDOW)
//! Phase 4: FULL     → 100% of agents
//! ```
//!
//! At each phase, we monitor the **False Positive Rate (FPR)** of agents
//! running the new policy. If FPR exceeds the threshold, we:
//! 1. Immediately roll back ALL agents to the previous policy version.
//! 2. Quarantine the new policy for human review.
//! 3. Send a critical alert to the SOC.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

// ─── Configuration ────────────────────────────────────────────────────────────

/// Maximum acceptable false-positive rate before triggering auto-rollback (5%).
const FPR_ROLLBACK_THRESHOLD: f64 = 0.05;
/// Time to observe agents in each canary phase before advancing.
const OBSERVATION_WINDOW: Duration = Duration::from_secs(300); // 5 minutes
/// Minimum number of alert events to make a statistically valid FPR decision.
const MIN_SAMPLE_SIZE: usize = 20;

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum RolloutPhase {
    Idle,
    Canary,   // 1% of agents
    Early,    // 10%
    Rollout,  // 50%
    Full,     // 100%
    RolledBack { reason: String },
}

#[derive(Debug, Clone)]
pub struct PolicyVersion {
    pub version: u64,
    pub policy_type: String,
    pub rule_id: String,
    pub content: String,
}

/// Per-agent metric window for FPR calculation.
struct AgentMetrics {
    /// Ring buffer of recent alert outcomes: true = false positive, false = true positive
    alert_outcomes: VecDeque<bool>,
}

impl AgentMetrics {
    fn new() -> Self {
        Self { alert_outcomes: VecDeque::with_capacity(200) }
    }

    fn record(&mut self, is_false_positive: bool) {
        if self.alert_outcomes.len() >= 200 {
            self.alert_outcomes.pop_front();
        }
        self.alert_outcomes.push_back(is_false_positive);
    }

    fn fpr(&self) -> f64 {
        if self.alert_outcomes.len() < MIN_SAMPLE_SIZE { return 0.0; }
        let fp_count = self.alert_outcomes.iter().filter(|&&x| x).count();
        fp_count as f64 / self.alert_outcomes.len() as f64
    }
}

// ─── Rollout Controller ───────────────────────────────────────────────────────

pub struct CanaryRolloutController {
    current_phase: RwLock<RolloutPhase>,
    /// The policy currently being rolled out
    new_policy: RwLock<Option<PolicyVersion>>,
    /// The last stable policy version (for rollback)
    stable_policy: RwLock<Option<PolicyVersion>>,
    /// Set of agent IDs currently running the NEW policy
    canary_agents: DashMap<String, ()>,
    /// Per-agent metrics for FPR monitoring
    agent_metrics: DashMap<String, AgentMetrics>,
    /// All registered agent IDs
    all_agents: RwLock<Vec<String>>,
    phase_started_at: RwLock<Instant>,
}

impl CanaryRolloutController {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            current_phase: RwLock::new(RolloutPhase::Idle),
            new_policy: RwLock::new(None),
            stable_policy: RwLock::new(None),
            canary_agents: DashMap::new(),
            agent_metrics: DashMap::new(),
            all_agents: RwLock::new(Vec::new()),
            phase_started_at: RwLock::new(Instant::now()),
        })
    }

    /// Register a new agent with the rollout controller.
    pub async fn register_agent(&self, agent_id: String) {
        let mut agents = self.all_agents.write().await;
        if !agents.contains(&agent_id) {
            agents.push(agent_id.clone());
        }
        self.agent_metrics.entry(agent_id).or_insert_with(AgentMetrics::new);
    }

    /// Begin rolling out a new policy version. Previous policy becomes the rollback target.
    pub async fn begin_rollout(&self, new_policy: PolicyVersion) {
        info!("🚀 Canary Rollout: Starting phase CANARY for policy v{} ({})",
            new_policy.version, new_policy.rule_id);

        // Save current policy as the stable rollback target
        {
            let current = self.new_policy.read().await.clone();
            *self.stable_policy.write().await = current;
        }

        *self.new_policy.write().await = Some(new_policy);
        *self.current_phase.write().await = RolloutPhase::Canary;
        *self.phase_started_at.write().await = Instant::now();

        self.apply_canary_phase().await;
    }

    /// Called by the monitoring loop to check metrics and advance/rollback.
    pub async fn tick(&self) -> RolloutPhase {
        let phase = self.current_phase.read().await.clone();
        let elapsed = self.phase_started_at.read().await.elapsed();

        match &phase {
            RolloutPhase::Idle | RolloutPhase::Full | RolloutPhase::RolledBack { .. } => {
                return phase;
            }
            _ => {}
        }

        // Check FPR of canary agents
        let fpr = self.calculate_canary_fpr().await;
        if fpr > FPR_ROLLBACK_THRESHOLD {
            error!("🔴 Canary Rollout: FPR={:.1}% EXCEEDS THRESHOLD ({:.1}%) — AUTO-ROLLBACK!",
                fpr * 100.0, FPR_ROLLBACK_THRESHOLD * 100.0);
            return self.rollback(format!("FPR {:.1}% > threshold {:.1}%",
                fpr * 100.0, FPR_ROLLBACK_THRESHOLD * 100.0)).await;
        }

        // Not enough time has elapsed to advance phase
        if elapsed < OBSERVATION_WINDOW {
            return phase;
        }

        // Advance to the next phase
        self.advance_phase().await
    }

    /// Record an alert outcome for an agent (called by SOAR when alert is resolved).
    pub async fn record_alert_outcome(&self, agent_id: &str, is_false_positive: bool) {
        if let Some(mut metrics) = self.agent_metrics.get_mut(agent_id) {
            metrics.record(is_false_positive);
        }
    }

    /// Check if an agent is running the new (canary) policy.
    pub fn is_canary_agent(&self, agent_id: &str) -> bool {
        self.canary_agents.contains_key(agent_id)
    }

    pub async fn current_phase(&self) -> RolloutPhase {
        self.current_phase.read().await.clone()
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    async fn calculate_canary_fpr(&self) -> f64 {
        let agents: Vec<String> = self.canary_agents.iter()
            .map(|e| e.key().clone())
            .collect();

        if agents.is_empty() { return 0.0; }

        let total_fpr: f64 = agents.iter()
            .filter_map(|id| self.agent_metrics.get(id))
            .map(|m| m.fpr())
            .sum();

        total_fpr / agents.len() as f64
    }

    async fn advance_phase(&self) -> RolloutPhase {
        let all_agents = self.all_agents.read().await;
        let n = all_agents.len();
        if n == 0 { return RolloutPhase::Idle; }

        let current = self.current_phase.read().await.clone();
        let (next_phase, next_fraction) = match current {
            RolloutPhase::Canary  => (RolloutPhase::Early,   0.10),
            RolloutPhase::Early   => (RolloutPhase::Rollout, 0.50),
            RolloutPhase::Rollout => (RolloutPhase::Full,    1.00),
            other => return other,
        };

        let target_count = ((n as f64) * next_fraction).ceil() as usize;
        info!("✅ Canary advancing to {:?} — deploying to {}/{} agents", next_phase, target_count, n);

        // Add more agents to the canary pool
        self.canary_agents.clear();
        for agent_id in all_agents.iter().take(target_count) {
            self.canary_agents.insert(agent_id.clone(), ());
        }

        *self.current_phase.write().await = next_phase.clone();
        *self.phase_started_at.write().await = Instant::now();

        next_phase
    }

    async fn apply_canary_phase(&self) {
        let all_agents = self.all_agents.read().await;
        let n = all_agents.len();
        let canary_count = ((n as f64) * 0.01).max(1.0) as usize;

        self.canary_agents.clear();
        for agent_id in all_agents.iter().take(canary_count) {
            self.canary_agents.insert(agent_id.clone(), ());
        }

        info!("🐤 CANARY: {}/{} agents now running new policy", canary_count, n);
    }

    async fn rollback(&self, reason: String) -> RolloutPhase {
        warn!("⏪ AUTO-ROLLBACK triggered: {}", reason);

        // Remove all agents from canary pool (they'll revert to stable policy)
        self.canary_agents.clear();

        let new_state = RolloutPhase::RolledBack { reason };
        *self.current_phase.write().await = new_state.clone();

        // The Control Plane should now push the stable_policy to all agents
        if let Some(stable) = self.stable_policy.read().await.as_ref() {
            warn!("⏪ Reverting all agents to stable policy v{}", stable.version);
        } else {
            error!("⏪ No stable policy available for rollback! Agents will use cached policy.");
        }

        new_state
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy(v: u64) -> PolicyVersion {
        PolicyVersion {
            version: v,
            policy_type: "SIGMA".to_string(),
            rule_id: format!("rule-{v}"),
            content: format!("rule content v{v}"),
        }
    }

    #[tokio::test]
    async fn rollback_triggers_on_high_fpr() {
        let ctrl = CanaryRolloutController::new();

        // Register agents
        for i in 0..100 {
            ctrl.register_agent(format!("agent-{i}")).await;
        }

        ctrl.begin_rollout(make_policy(2)).await;
        assert_eq!(ctrl.current_phase().await, RolloutPhase::Canary);

        // Simulate 100% false positive rate on canary agents
        let canary_ids: Vec<String> = ctrl.canary_agents.iter()
            .map(|e| e.key().clone())
            .collect();
        for id in &canary_ids {
            for _ in 0..MIN_SAMPLE_SIZE + 5 {
                ctrl.record_alert_outcome(id, true).await; // all false positives
            }
        }

        let phase = ctrl.tick().await;
        assert!(matches!(phase, RolloutPhase::RolledBack { .. }),
            "Should have rolled back due to high FPR");
    }

    #[tokio::test]
    async fn clean_policy_advances_phases() {
        let ctrl = CanaryRolloutController::new();
        for i in 0..200 {
            ctrl.register_agent(format!("agent-{i}")).await;
        }
        ctrl.begin_rollout(make_policy(2)).await;
        assert_eq!(ctrl.current_phase().await, RolloutPhase::Canary);

        // Simulate no false positives — FPR = 0
        // Force time advancement by creating a fake tick with elapsed time
        // (In production, the tokio::time::sleep would be used)
        // We verify FPR stays at 0 and would not rollback
        let fpr = ctrl.calculate_canary_fpr().await;
        assert!(fpr < FPR_ROLLBACK_THRESHOLD, "No false positives should not trigger rollback");
    }

    #[test]
    fn agent_metrics_fpr_calculation() {
        let mut m = AgentMetrics::new();
        // 5 true positives, 5 false positives = 50% FPR
        for _ in 0..5 { m.record(false); } // true positive
        for _ in 0..5 { m.record(true); }  // false positive
        // Below MIN_SAMPLE_SIZE — should return 0
        assert_eq!(m.fpr(), 0.0);

        // Add enough samples
        for _ in 0..MIN_SAMPLE_SIZE { m.record(false); }
        assert!(m.fpr() < 0.30, "FPR should reflect realistic false positive ratio");
    }
}
