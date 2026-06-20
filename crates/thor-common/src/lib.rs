//! Thor Common — shared types, unified event schema, and Zero-Trust utilities
//!
//! All crates in the Thor workspace import from here.  Nothing in this crate
//! should have side-effects at crate-init time.
//!
//! ## Aegis XDR Phase 2 additions (Conditional Sovereign AI):
//! - `ConditionalAutonomyPolicy`  — SOC-defined thresholds per agent type
//! - `XAIExplanation`             — Explainable AI result attached to every event
//! - `AuditLogEntry`              — Tamper-evident SHA-256 chained audit record
//! - `FederatedGradientDelta`     — FL weight updates (no raw data leaves agent)
//! - `DecisionOutcome`            — Outcome of autonomous or human-escalated action
//! - `ConfidenceScore`            — ML confidence with provenance metadata

pub mod crypto;
pub mod event_channel;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ─── Threat Level ─────────────────────────────────────────────────────────────

/// Unified threat severity level used across detection, alerts, and SOAR
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatLevel {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatLevel {
    /// Derive threat level from an ML anomaly score (0.0–1.0)
    pub fn from_score(score: f32) -> Self {
        if score >= 0.95      { ThreatLevel::Critical }
        else if score >= 0.85 { ThreatLevel::High }
        else if score >= 0.70 { ThreatLevel::Medium }
        else if score >= 0.50 { ThreatLevel::Low }
        else                  { ThreatLevel::Unknown }
    }

    /// Numeric severity (0=unknown, 4=critical)
    pub fn severity(&self) -> u8 {
        match self {
            ThreatLevel::Unknown  => 0,
            ThreatLevel::Low      => 1,
            ThreatLevel::Medium   => 2,
            ThreatLevel::High     => 3,
            ThreatLevel::Critical => 4,
        }
    }

    pub fn is_critical_or_high(&self) -> bool {
        matches!(self, ThreatLevel::Critical | ThreatLevel::High)
    }

    pub fn from_str_level(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => ThreatLevel::Critical,
            "high"     => ThreatLevel::High,
            "medium"   => ThreatLevel::Medium,
            "low"      => ThreatLevel::Low,
            _          => ThreatLevel::Unknown,
        }
    }
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ThreatLevel::Critical => "CRITICAL",
            ThreatLevel::High     => "HIGH",
            ThreatLevel::Medium   => "MEDIUM",
            ThreatLevel::Low      => "LOW",
            ThreatLevel::Unknown  => "UNKNOWN",
        };
        write!(f, "{}", s)
    }
}

// ─── MITRE ATT&CK ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MitreTactic {
    Reconnaissance, ResourceDevelopment, InitialAccess, Execution,
    Persistence, PrivilegeEscalation, DefenseEvasion, CredentialAccess,
    Discovery, LateralMovement, Collection, CommandAndControl,
    Exfiltration, Impact,
}

impl MitreTactic {
    pub fn tactic_id(&self) -> &'static str {
        match self {
            MitreTactic::Reconnaissance      => "TA0043",
            MitreTactic::ResourceDevelopment => "TA0042",
            MitreTactic::InitialAccess       => "TA0001",
            MitreTactic::Execution           => "TA0002",
            MitreTactic::Persistence         => "TA0003",
            MitreTactic::PrivilegeEscalation => "TA0004",
            MitreTactic::DefenseEvasion      => "TA0005",
            MitreTactic::CredentialAccess    => "TA0006",
            MitreTactic::Discovery           => "TA0007",
            MitreTactic::LateralMovement     => "TA0008",
            MitreTactic::Collection          => "TA0009",
            MitreTactic::CommandAndControl   => "TA0011",
            MitreTactic::Exfiltration        => "TA0010",
            MitreTactic::Impact              => "TA0040",
        }
    }
}

// ─── Aegis XDR: Conditional Autonomy ─────────────────────────────────────────

/// Agent type identifier for policy scoping.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentType {
    /// L3/L4 XDP/eBPF Network Agent
    Network,
    /// L7 WAF Web Agent
    Web,
    /// EDR Server Agent
    Server,
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentType::Network => write!(f, "network"),
            AgentType::Web     => write!(f, "web"),
            AgentType::Server  => write!(f, "server"),
        }
    }
}

/// SOC-defined autonomy policy for one agent type.
///
/// An agent will execute a response autonomously ONLY if its ML
/// `confidence_score >= auto_action_threshold`.  Events below that
/// threshold are escalated to the SOC decision inbox for human review.
///
/// This is the heart of the **Conditional Sovereign AI** model in Aegis XDR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAutonomyPolicy {
    /// Agent type this policy applies to.
    pub agent_type: AgentType,
    /// Minimum ML confidence for autonomous action (0.0–1.0). Default: 0.90.
    pub auto_action_threshold: f32,
    /// When true, agents act autonomously even if SOC is offline.
    pub offline_autonomous: bool,
    /// Max autonomous actions per minute (rate gate, 0 = unlimited).
    pub max_auto_actions_per_min: u32,
    /// Actions permitted without SOC approval.
    pub allowed_auto_actions: Vec<String>,
    /// Policy version hash (SOC must re-sign after modification).
    pub policy_version: String,
    /// UTC timestamp of last SOC review/approval.
    pub last_reviewed_at: DateTime<Utc>,
    /// SOC analyst who last approved this policy.
    pub approved_by: String,
}

impl AgentAutonomyPolicy {
    /// Returns true if confidence is sufficient AND action is on the allowlist.
    pub fn allows_auto_action(&self, confidence: f32, action: &str) -> bool {
        confidence >= self.auto_action_threshold
            && self.allowed_auto_actions.iter().any(|a| a == action)
    }

    /// Conservative default — 90% confidence required, SOC must be online.
    pub fn default_for(agent_type: AgentType) -> Self {
        let allowed = match &agent_type {
            AgentType::Network => vec!["XDP_DROP".into(), "RATE_LIMIT".into(), "REDIRECT_HONEYPOT".into()],
            AgentType::Web     => vec!["WAF_BLOCK".into(), "CHALLENGE".into()],
            AgentType::Server  => vec!["PROCESS_ALERT".into(), "FILE_QUARANTINE".into()],
        };
        Self {
            agent_type,
            auto_action_threshold: 0.90,
            offline_autonomous: false,
            max_auto_actions_per_min: 100,
            allowed_auto_actions: allowed,
            policy_version: "v1.0.0".into(),
            last_reviewed_at: Utc::now(),
            approved_by: "system-default".into(),
        }
    }
}

/// Outcome of an agent decision — autonomous or human-escalated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecisionOutcome {
    /// Agent acted autonomously (confidence >= threshold).
    Autonomous { action: String, confidence: f32, model_id: String },
    /// Escalated to SOC inbox — awaiting human decision.
    PendingHumanReview { escalated_at: DateTime<Utc>, reason: String },
    /// SOC analyst approved and action was executed.
    HumanApproved { analyst: String, action: String, approved_at: DateTime<Utc> },
    /// SOC analyst rejected the proposed action.
    HumanRejected  { analyst: String, reason: String, rejected_at: DateTime<Utc> },
    /// Event below alert threshold — only logged.
    Logged,
}

// ─── ML Confidence Score with Provenance ─────────────────────────────────────

/// ML inference result with full model provenance for audit and XAI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceScore {
    /// Raw ML score (0.0–1.0) from the primary model.
    pub score: f32,
    /// ONNX model identifier.
    pub model_id: String,
    /// Model version string (e.g. "thor_master_brain_v3_2026").
    pub model_version: String,
    /// Inference latency in microseconds (<30µs target).
    pub inference_latency_us: u64,
    /// Secondary ensemble scores (model_id → score).
    pub ensemble_scores: Option<HashMap<String, f32>>,
    /// Final fused score after ensemble voting.
    pub fused_score: Option<f32>,
}

impl ConfidenceScore {
    /// Returns fused score if available, otherwise raw score.
    pub fn effective(&self) -> f32 {
        self.fused_score.unwrap_or(self.score)
    }
}

// ─── Explainable AI (XAI) ─────────────────────────────────────────────────────

/// XAI explanation attached to every ML-driven event.
///
/// Fulfils the **Accountability & Human Oversight** pillar of Aegis XDR:
/// every automated decision must be understandable by a SOC analyst.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XAIExplanation {
    /// One-line human-readable summary for the SOC dashboard.
    pub summary: String,
    /// Top contributing features (feature_name → importance_weight).
    pub top_features: Vec<FeatureImportance>,
    /// Detection signals that fired (Sigma rule IDs, IOC feed entries, etc.)
    pub triggered_signals: Vec<String>,
    /// Counterfactual: what would need to change for this NOT to be a threat.
    pub counterfactual: Option<String>,
    /// Explanation method used (SHAP, LIME, gradient-based, rule-only).
    pub explanation_method: String,
}

/// A single feature and its SHAP-style importance weight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureImportance {
    pub feature_name: String,
    /// Higher = more important for the decision.
    pub importance:   f32,
    /// Human-readable feature value (e.g., "TCP port 4444").
    pub value:        String,
}

impl XAIExplanation {
    /// Build a minimal rule-only explanation (no ML model involved).
    pub fn from_rules(triggered: Vec<String>) -> Self {
        let summary = if triggered.is_empty() {
            "Anomaly detected by heuristic analysis.".into()
        } else {
            format!("Detection rules triggered: {}", triggered.join(", "))
        };
        Self {
            summary,
            top_features: vec![],
            triggered_signals: triggered,
            counterfactual: None,
            explanation_method: "rule-based".into(),
        }
    }
}

// ─── Tamper-Evident Audit Log ─────────────────────────────────────────────────

/// One entry in the tamper-evident audit chain.
///
/// `entry_hash = SHA-256(prev_hash || canonical_json(this_entry_minus_hash))`
/// Any modification to any field breaks the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub sequence:    u64,
    /// SHA-256 of previous entry (genesis entry uses "0" * 64).
    pub prev_hash:   String,
    pub timestamp:   DateTime<Utc>,
    pub agent_id:    String,
    pub category:    AuditCategory,
    /// Links back to the triggering UnifiedThorEvent.
    pub event_id:    String,
    pub decision:    DecisionOutcome,
    pub explanation: Option<XAIExplanation>,
    /// SHA-256(prev_hash || canonical_json) — verify with `verify()`.
    pub entry_hash:  String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditCategory {
    AutomaticAction, HumanDecision, PolicyChange,
    ModelUpdate, AgentRegistration, SecurityAlert, FederatedUpdate,
}

#[derive(Serialize)]
struct AuditHashInput<'a> {
    sequence: u64, prev_hash: &'a str,
    timestamp: String, agent_id: &'a str, event_id: &'a str,
}

impl AuditLogEntry {
    pub fn compute_hash(&mut self) {
        use sha2::{Sha256, Digest};
        let json = serde_json::to_string(&AuditHashInput {
            sequence: self.sequence, prev_hash: &self.prev_hash,
            timestamp: self.timestamp.to_rfc3339(),
            agent_id: &self.agent_id, event_id: &self.event_id,
        }).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(self.prev_hash.as_bytes());
        h.update(json.as_bytes());
        self.entry_hash = format!("{:x}", h.finalize());
    }

    pub fn verify(&self) -> bool {
        use sha2::{Sha256, Digest};
        let json = serde_json::to_string(&AuditHashInput {
            sequence: self.sequence, prev_hash: &self.prev_hash,
            timestamp: self.timestamp.to_rfc3339(),
            agent_id: &self.agent_id, event_id: &self.event_id,
        }).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(self.prev_hash.as_bytes());
        h.update(json.as_bytes());
        format!("{:x}", h.finalize()) == self.entry_hash
    }
}

// ─── Federated Learning ───────────────────────────────────────────────────────

/// Gradient delta from one agent — only weight updates, NEVER raw data.
///
/// Agents train locally, then send only the differential update.
/// The SOC FL coordinator aggregates deltas using FedAvg.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedGradientDelta {
    pub round_id:          String,
    pub agent_id:          String,
    pub model_id:          String,
    /// Number of local samples used for this update.
    pub local_samples:     u64,
    /// Per-layer weight deltas (layer_name → float32 vector).
    pub layer_deltas:      HashMap<String, Vec<f32>>,
    /// Jensen-Shannon Divergence between old and new distributions.
    /// If JSD > 0.15, the SOC FL coordinator flags a retrain review.
    pub jsd_metric:        f32,
    pub contributed_at:    DateTime<Utc>,
    /// HMAC-SHA256 signature prevents gradient poisoning attacks.
    pub payload_signature: String,
}

/// Status of a federated learning round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FLRoundStatus {
    Collecting  { agents_received: u32, agents_expected: u32 },
    Aggregating,
    Distributing { new_model_version: String },
    Completed   { new_model_version: String, jsd_improvement: f32 },
    Failed      { reason: String },
}

// ─── Unified Event Schema (Aegis XDR Phase 2) ─────────────────────────────────

/// Canonical event emitted by all Thor agents to the Control-Plane.
///
/// Phase 2 additions over Phase 1:
/// - `confidence`       — ML confidence with model provenance
/// - `xai`              — XAI explanation (mandatory for ML-driven events)
/// - `decision_outcome` — Result of the conditional autonomy decision
/// - `audit_seq`        — Link to tamper-evident audit chain
/// - `fl_round_id`      — Federated learning round contribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedThorEvent {
    pub event_id:    String,
    pub timestamp:   DateTime<Utc>,
    pub agent_id:    String,
    pub platform:    AgentPlatform,
    pub threat_level: ThreatLevel,
    pub rule_name:   Option<String>,
    pub mitre_tactic: Option<MitreTactic>,
    pub details:     EventDetails,
    pub soar_action_taken: Option<String>,
    pub description: String,
    // ── Aegis XDR Phase 2 ────────────────────────────────────────────
    pub confidence:       Option<ConfidenceScore>,
    pub xai:              Option<XAIExplanation>,
    pub decision_outcome: Option<DecisionOutcome>,
    pub audit_seq:        Option<u64>,
    pub fl_round_id:      Option<String>,
}

impl UnifiedThorEvent {
    pub fn new(agent_id: impl Into<String>, platform: AgentPlatform, details: EventDetails) -> Self {
        let threat = match &details {
            EventDetails::Network(n) => n.threat_level.clone(),
            EventDetails::Web(w)     => ThreatLevel::from_score(w.anomaly_score),
            EventDetails::Server(s)  => ThreatLevel::from_str_level(&s.severity),
        };
        let description = match &details {
            EventDetails::Network(n) => format!("Network: {}:{} -> {} [{}]", n.src_ip, n.src_port, n.dst_ip, threat),
            EventDetails::Web(w)     => format!("WAF: {} {} score={:.2}", w.method, w.uri, w.anomaly_score),
            EventDetails::Server(s)  => format!("EDR: {} PID={} [{}]", s.process_name, s.pid, s.alert_cause),
        };
        Self {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            agent_id: agent_id.into(),
            platform, threat_level: threat, rule_name: None,
            mitre_tactic: None, details, soar_action_taken: None, description,
            confidence: None, xai: None, decision_outcome: None,
            audit_seq: None, fl_round_id: None,
        }
    }

    /// Attach ML inference result and XAI explanation.
    pub fn with_ml(mut self, confidence: ConfidenceScore, xai: XAIExplanation) -> Self {
        self.threat_level = ThreatLevel::from_score(confidence.effective());
        self.confidence = Some(confidence);
        self.xai = Some(xai);
        self
    }

    /// Apply conditional autonomy: auto-act or escalate to SOC.
    pub fn apply_autonomy(mut self, policy: &AgentAutonomyPolicy, proposed_action: &str) -> Self {
        let score = self.confidence.as_ref().map(|c| c.effective()).unwrap_or(0.0);
        if policy.allows_auto_action(score, proposed_action) {
            self.soar_action_taken = Some(proposed_action.to_string());
            self.decision_outcome = Some(DecisionOutcome::Autonomous {
                action: proposed_action.to_string(),
                confidence: score,
                model_id: self.confidence.as_ref().map(|c| c.model_id.clone()).unwrap_or_default(),
            });
        } else {
            self.decision_outcome = Some(DecisionOutcome::PendingHumanReview {
                escalated_at: Utc::now(),
                reason: format!(
                    "Confidence {:.2} < threshold {:.2} or action '{}' not on allowlist",
                    score, policy.auto_action_threshold, proposed_action
                ),
            });
        }
        self
    }

    /// Returns true if this event is awaiting SOC human review.
    pub fn needs_human_review(&self) -> bool {
        matches!(&self.decision_outcome, Some(DecisionOutcome::PendingHumanReview { .. }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentPlatform { Linux, Windows, Container, Edge, Unknown }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "agent_type", rename_all = "snake_case")]
pub enum EventDetails {
    Network(NetworkEventDetails),
    Web(WebEventDetails),
    Server(ServerEventDetails),
}

// ─── Network Agent Details ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEventDetails {
    pub src_ip:       String,
    pub dst_ip:       String,
    pub src_port:     u16,
    pub dst_port:     u16,
    pub protocol:     String,
    pub tcp_flags:    Option<u8>,
    pub packet_count: u64,
    pub byte_count:   u64,
    pub action:       NetworkAction,
    pub threat_level: ThreatLevel,
    pub ioc_matched:  Option<String>,
    /// DGA entropy score (0.0–1.0) for DNS C2 beacon detection.
    pub dga_entropy:  Option<f32>,
    /// Packets-per-second rate (used for DDoS detection).
    pub pps_rate:     Option<f64>,
    /// JA4 TLS fingerprint for fingerprinting C2 channels.
    pub ja4_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkAction { Allowed, Dropped, Redirected, RateLimited, PendingReview }

// ─── Web Agent Details ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebEventDetails {
    pub src_ip:        String,
    pub method:        String,
    pub uri:           String,
    pub host:          Option<String>,
    pub user_agent:    Option<String>,
    pub status_code:   Option<u16>,
    pub category:      WebThreatCategory,
    pub anomaly_score: f32,
    pub signatures:    Vec<String>,
    pub payload_hash:  Option<String>,
    pub action:        WebAction,
    /// JA4H HTTP fingerprint for bot/scanner classification.
    pub ja4h:          Option<String>,
    pub content_type:  Option<String>,
    pub body_bytes:    Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebThreatCategory {
    SqlInjection, CrossSiteScripting, PathTraversal, CommandInjection,
    ProtocolViolation, RateLimit, BotActivity, Log4Shell, WebShell,
    Ssrf, XXE, Deserialization, Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebAction { Allowed, Blocked, Challenged, Logged, PendingReview }

// ─── Server Agent Details ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEventDetails {
    pub pid:          u32,
    pub ppid:         Option<u32>,
    pub process_name: String,
    pub cmd_line:     String,
    pub user:         String,
    pub severity:     String,
    pub alert_cause:  String,
    pub action:       ServerAction,
    pub file_path:    Option<String>,
    pub file_hash:    Option<String>,
    /// True when in-memory image differs from on-disk (process hollowing).
    pub memory_anomaly: Option<bool>,
    /// UEBA behavioural anomaly score from IsolationForest model.
    pub ueba_score:   Option<f32>,
    /// Windows ETW event ID (Windows agents only).
    pub etw_event_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerAction { Detected, ProcessKilled, FileQuarantined, NetworkIsolated, Logged, PendingReview }

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Critical > ThreatLevel::High);
        assert!(ThreatLevel::High > ThreatLevel::Low);
        assert_eq!(ThreatLevel::from_score(0.96), ThreatLevel::Critical);
        assert_eq!(ThreatLevel::from_score(0.30), ThreatLevel::Unknown);
    }

    #[test]
    fn test_conditional_autonomy_allows() {
        let p = AgentAutonomyPolicy::default_for(AgentType::Network);
        assert!(p.allows_auto_action(0.95, "XDP_DROP"));
        assert!(!p.allows_auto_action(0.85, "XDP_DROP"));      // below 0.90
        assert!(!p.allows_auto_action(0.95, "PROCESS_KILL"));  // not on allowlist
    }

    #[test]
    fn test_event_apply_autonomy_auto() {
        let policy = AgentAutonomyPolicy::default_for(AgentType::Network);
        let details = EventDetails::Network(NetworkEventDetails {
            src_ip: "1.2.3.4".into(), dst_ip: "5.6.7.8".into(),
            src_port: 1234, dst_port: 80, protocol: "TCP".into(),
            tcp_flags: None, packet_count: 1, byte_count: 64,
            action: NetworkAction::Allowed, threat_level: ThreatLevel::Critical,
            ioc_matched: None, dga_entropy: None, pps_rate: None, ja4_fingerprint: None,
        });
        let event = UnifiedThorEvent::new("net-01", AgentPlatform::Linux, details)
            .with_ml(
                ConfidenceScore {
                    score: 0.95, model_id: "thor_master_brain_v3".into(),
                    model_version: "2026".into(), inference_latency_us: 25,
                    ensemble_scores: None, fused_score: None,
                },
                XAIExplanation::from_rules(vec!["FEODO_C2_IOC".into()]),
            )
            .apply_autonomy(&policy, "XDP_DROP");

        assert!(!event.needs_human_review());
        assert!(matches!(event.decision_outcome, Some(DecisionOutcome::Autonomous { .. })));
    }

    #[test]
    fn test_event_apply_autonomy_escalate() {
        let policy = AgentAutonomyPolicy::default_for(AgentType::Network);
        let details = EventDetails::Network(NetworkEventDetails {
            src_ip: "1.2.3.4".into(), dst_ip: "5.6.7.8".into(),
            src_port: 1234, dst_port: 80, protocol: "TCP".into(),
            tcp_flags: None, packet_count: 1, byte_count: 64,
            action: NetworkAction::Allowed, threat_level: ThreatLevel::Medium,
            ioc_matched: None, dga_entropy: None, pps_rate: None, ja4_fingerprint: None,
        });
        let event = UnifiedThorEvent::new("net-01", AgentPlatform::Linux, details)
            .with_ml(
                ConfidenceScore {
                    score: 0.72, model_id: "thor_master_brain_v3".into(),
                    model_version: "2026".into(), inference_latency_us: 22,
                    ensemble_scores: None, fused_score: None,
                },
                XAIExplanation::from_rules(vec![]),
            )
            .apply_autonomy(&policy, "XDP_DROP");

        assert!(event.needs_human_review()); // 0.72 < 0.90 → escalate
    }

    #[test]
    fn test_audit_log_hash_chain() {
        let mut entry = AuditLogEntry {
            sequence: 1, prev_hash: "0".repeat(64),
            timestamp: Utc::now(), agent_id: "net-01".into(),
            category: AuditCategory::AutomaticAction,
            event_id: Uuid::new_v4().to_string(),
            decision: DecisionOutcome::Logged,
            explanation: None, entry_hash: String::new(),
        };
        entry.compute_hash();
        assert_eq!(entry.entry_hash.len(), 64); // SHA-256 hex
        assert!(entry.verify());
    }

    #[test]
    fn test_mitre_tactic_ids() {
        assert_eq!(MitreTactic::CommandAndControl.tactic_id(), "TA0011");
        assert_eq!(MitreTactic::Exfiltration.tactic_id(), "TA0010");
    }
}
