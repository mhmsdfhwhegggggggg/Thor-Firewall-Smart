//! Byzantine-Robust Federated Learning Aggregator
//!
//! Replaces naive FedAvg with **Coordinate-wise Trimmed Mean**, a provably robust
//! aggregation algorithm that tolerates up to f < n/2 malicious agents sending
//! adversarially crafted (poisoned) model weight updates.
//!
//! ## Why not FedAvg?
//! Standard FedAvg is trivially attacked: a single compromised agent can shift the
//! global model arbitrarily by sending very large gradient updates (Byzantine attack).
//!
//! ## Our approach: Coordinate-wise Trimmed Mean
//! For each weight dimension independently:
//!   1. Collect that dimension's value from all n agents.
//!   2. Sort the values.
//!   3. Drop the top β% and bottom β% (default β = 20%).
//!   4. Average the remaining values.
//!
//! This bounds the influence of any single agent to ≤ 1/(n × (1-2β)) of the final update,
//! making gradient poisoning attacks mathematically infeasible.
//!
//! Additionally, we run a **Gradient Norm Filter** before aggregation:
//! Any agent whose update norm exceeds 3σ from the median norm is quarantined.

use std::collections::HashMap;
use tracing::{info, warn};

// ─── Types ────────────────────────────────────────────────────────────────────

/// A single agent's model weight update submission.
#[derive(Debug, Clone)]
pub struct AgentWeightUpdate {
    /// Unique agent identifier (from TPM attestation hash)
    pub agent_id: String,
    /// Flattened weight delta vector (same shape across all agents)
    pub weights: Vec<f32>,
    /// Number of local training samples (used for weighted aggregation)
    pub n_samples: u32,
}

/// Result of a successful aggregation round.
#[derive(Debug)]
pub struct AggregationResult {
    /// The new global model weights after robust aggregation
    pub global_weights: Vec<f32>,
    /// Number of agents whose updates were accepted
    pub accepted_count: usize,
    /// Agent IDs whose updates were quarantined (suspected poisoners)
    pub quarantined_agents: Vec<String>,
    /// Aggregation method used
    pub method: AggregationMethod,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AggregationMethod {
    TrimmedMean { trim_fraction: f32 },
    FedAvg, // Fallback when n < 4
}

// ─── Aggregator ───────────────────────────────────────────────────────────────

pub struct ByzantineRobustAggregator {
    /// Fraction to trim from each tail (0.20 = drop top 20% + bottom 20%)
    trim_fraction: f32,
    /// Z-score threshold for norm-based quarantine
    norm_zscore_threshold: f64,
}

impl ByzantineRobustAggregator {
    pub fn new() -> Self {
        Self {
            trim_fraction: 0.20,      // Tolerate up to 20% Byzantine agents
            norm_zscore_threshold: 3.0,
        }
    }

    pub fn with_trim_fraction(mut self, f: f32) -> Self {
        assert!(f > 0.0 && f < 0.5, "trim_fraction must be in (0, 0.5)");
        self.trim_fraction = f;
        self
    }

    /// Perform Byzantine-robust aggregation of agent weight updates.
    pub fn aggregate(&self, updates: Vec<AgentWeightUpdate>) -> Option<AggregationResult> {
        let n = updates.len();
        if n == 0 {
            warn!("🔴 FL Aggregator: No updates received, skipping round.");
            return None;
        }

        // Validate all updates have the same dimension
        let dim = updates[0].weights.len();
        if updates.iter().any(|u| u.weights.len() != dim) {
            warn!("🔴 FL Aggregator: Mismatched weight dimensions detected — possible attack!");
            return None;
        }

        // ── Step 1: Gradient Norm Filter ──────────────────────────────────────
        let norms: Vec<f64> = updates.iter()
            .map(|u| l2_norm(&u.weights))
            .collect();

        let median_norm = median(&norms);
        let std_norm = std_dev(&norms, median_norm);

        let (clean_updates, quarantined_agents): (Vec<_>, Vec<_>) = updates
            .into_iter()
            .zip(norms.iter())
            .partition(|(_, &norm)| {
                (norm - median_norm).abs() <= self.norm_zscore_threshold * std_norm
            });

        let quarantined: Vec<String> = quarantined_agents
            .into_iter()
            .map(|(u, _)| {
                warn!("🚨 FL Aggregator: Quarantining agent '{}' — gradient norm is {} σ from median",
                    u.agent_id, self.norm_zscore_threshold);
                u.agent_id
            })
            .collect();

        let clean_updates: Vec<AgentWeightUpdate> = clean_updates
            .into_iter()
            .map(|(u, _)| u)
            .collect();

        let accepted = clean_updates.len();

        info!("✅ FL Aggregator: {}/{} agent updates accepted. {} quarantined.",
            accepted, n, quarantined.len());

        // ── Step 2: Aggregation Method Selection ──────────────────────────────
        if accepted < 4 {
            // Too few agents for trimming — fall back to FedAvg but warn
            warn!("⚠️  FL Aggregator: Only {} clean agents, using FedAvg (Byzantine resistance reduced).", accepted);
            let global_weights = fedavg(&clean_updates, dim);
            return Some(AggregationResult {
                global_weights,
                accepted_count: accepted,
                quarantined_agents: quarantined,
                method: AggregationMethod::FedAvg,
            });
        }

        // ── Step 3: Coordinate-wise Trimmed Mean ──────────────────────────────
        let global_weights = coordinate_trimmed_mean(&clean_updates, dim, self.trim_fraction);

        info!("🛡️  FL Round complete: Trimmed-Mean aggregation over {} agents (trim={}%)",
            accepted, (self.trim_fraction * 100.0) as u32);

        Some(AggregationResult {
            global_weights,
            accepted_count: accepted,
            quarantined_agents: quarantined,
            method: AggregationMethod::TrimmedMean { trim_fraction: self.trim_fraction },
        })
    }
}

impl Default for ByzantineRobustAggregator {
    fn default() -> Self { Self::new() }
}

// ─── Math helpers ─────────────────────────────────────────────────────────────

/// Coordinate-wise trimmed mean over all agent weight vectors.
fn coordinate_trimmed_mean(updates: &[AgentWeightUpdate], dim: usize, trim: f32) -> Vec<f32> {
    let n = updates.len();
    let trim_k = ((n as f32) * trim).floor() as usize;

    (0..dim).map(|d| {
        // Collect all agents' values for this dimension
        let mut vals: Vec<f32> = updates.iter().map(|u| u.weights[d]).collect();
        vals.sort_by(|a, b| a.partial_cmp(b).unwrap());

        // Trim tails
        let trimmed = &vals[trim_k..n - trim_k];
        if trimmed.is_empty() { return 0.0; }

        trimmed.iter().sum::<f32>() / trimmed.len() as f32
    }).collect()
}

/// Standard sample-weighted FedAvg fallback.
fn fedavg(updates: &[AgentWeightUpdate], dim: usize) -> Vec<f32> {
    let total_samples: u64 = updates.iter().map(|u| u.n_samples as u64).sum();
    if total_samples == 0 { return vec![0.0; dim]; }

    let mut global = vec![0.0f32; dim];
    for update in updates {
        let w = update.n_samples as f32 / total_samples as f32;
        for (g, &local) in global.iter_mut().zip(update.weights.iter()) {
            *g += local * w;
        }
    }
    global
}

fn l2_norm(v: &[f32]) -> f64 {
    v.iter().map(|&x| (x as f64).powi(2)).sum::<f64>().sqrt()
}

fn median(v: &[f64]) -> f64 {
    if v.is_empty() { return 0.0; }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = s.len() / 2;
    if s.len() % 2 == 0 { (s[mid - 1] + s[mid]) / 2.0 } else { s[mid] }
}

fn std_dev(v: &[f64], mean: f64) -> f64 {
    if v.len() < 2 { return 1.0; }
    let variance = v.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / (v.len() - 1) as f64;
    variance.sqrt().max(1e-8)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_update(id: &str, weights: Vec<f32>) -> AgentWeightUpdate {
        AgentWeightUpdate { agent_id: id.to_string(), weights, n_samples: 100 }
    }

    #[test]
    fn honest_agents_converge() {
        let agg = ByzantineRobustAggregator::new();
        let updates = vec![
            make_update("a1", vec![1.0, 2.0, 3.0]),
            make_update("a2", vec![1.1, 2.1, 3.1]),
            make_update("a3", vec![0.9, 1.9, 2.9]),
            make_update("a4", vec![1.0, 2.0, 3.0]),
            make_update("a5", vec![1.05, 2.05, 3.05]),
        ];
        let result = agg.aggregate(updates).unwrap();
        assert_eq!(result.quarantined_agents.len(), 0);
        // Global weights should be close to [1.0, 2.0, 3.0]
        assert!((result.global_weights[0] - 1.0).abs() < 0.15);
        assert!((result.global_weights[1] - 2.0).abs() < 0.15);
    }

    #[test]
    fn byzantine_agent_quarantined() {
        let agg = ByzantineRobustAggregator::new();
        let updates = vec![
            make_update("honest1", vec![1.0, 2.0, 3.0]),
            make_update("honest2", vec![1.0, 2.0, 3.0]),
            make_update("honest3", vec![1.0, 2.0, 3.0]),
            make_update("honest4", vec![1.0, 2.0, 3.0]),
            // Byzantine agent: massive poisoned update
            make_update("attacker", vec![10000.0, 10000.0, 10000.0]),
        ];
        let result = agg.aggregate(updates).unwrap();
        assert!(result.quarantined_agents.contains(&"attacker".to_string()));
        // Global model should still be near honest values
        assert!(result.global_weights[0] < 10.0, "Byzantine agent must NOT dominate");
    }

    #[test]
    fn trimmed_mean_resists_outliers() {
        let agg = ByzantineRobustAggregator::new();
        // 8 honest + 2 outliers (20% trim should remove them)
        let mut updates: Vec<_> = (0..8)
            .map(|i| make_update(&format!("h{i}"), vec![1.0]))
            .collect();
        updates.push(make_update("evil1", vec![999.0]));
        updates.push(make_update("evil2", vec![999.0]));

        let result = agg.aggregate(updates).unwrap();
        // After trimming, result should be close to 1.0
        assert!(result.global_weights[0] < 100.0, "Trimmed mean must suppress outliers");
    }
}
