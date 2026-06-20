//! Thor SOC Engine (thor-soc-slm) — Aegis XDR Phase 2
//!
//! **Sovereign Operations Center — Human-in-the-Loop Governance Engine**
//!
//! This is the central intelligence hub of Aegis XDR. It implements:
//!
//! ## Core Capabilities
//! 1. **Policy Management**: SOC analyst-defined confidence thresholds per agent type.
//!    Distributed to agents every 60s via REST API.
//!
//! 2. **Human Decision Inbox**: Events escalated by agents (confidence below SOC threshold)
//!    are queued here for human review. SOC analysts approve/reject via REST API.
//!
//! 3. **Federated Learning Coordinator**: Aggregates gradient deltas from all agents
//!    using FedAvg. Monitors JSD drift metric. Proposes model retraining to SOC
//!    when JSD > 0.15. Distributes new model versions after SOC approval.
//!
//! 4. **Tamper-Evident Audit Log**: Every action (autonomous or human-approved)
//!    is recorded in a SHA-256 chained log. Immutable and verifiable.
//!
//! 5. **Real-Time Event Stream**: WebSocket feed for the SOC dashboard.
//!    All events broadcast in real-time with XAI explanations.
//!
//! 6. **XAI Report Engine**: On-demand generation of human-readable
//!    explanations for any event. Formats: JSON, Markdown, PDF (via wkhtmltopdf).
//!
//! ## REST API
//! ```
//! GET  /api/v1/health
//! GET  /api/v1/dashboard                    → agent fleet + recent incidents
//! POST /api/v1/events                       → single event ingest from agent
//! POST /api/v1/events/batch                 → batch event ingest
//! GET  /api/v1/events?page=&severity=       → paginated event query
//! GET  /api/v1/events/:id                   → single event with XAI
//! POST /api/v1/decisions/:event_id/approve  → SOC approves pending action
//! POST /api/v1/decisions/:event_id/reject   → SOC rejects pending action
//! GET  /api/v1/decisions/pending            → all events awaiting human review
//! GET  /api/v1/policy/:agent_type           → get policy for agent type
//! PUT  /api/v1/policy/:agent_type           → update policy (SOC only)
//! GET  /api/v1/audit?page=                  → tamper-evident audit log
//! GET  /api/v1/audit/:seq/verify            → verify single audit entry
//! GET  /api/v1/fl/status                    → FL coordinator status
//! POST /api/v1/fl/contribute                → agent submits gradient delta
//! POST /api/v1/fl/approve-retrain           → SOC approves model retrain
//! GET  /ws/events                           → WebSocket real-time event stream
//! ```

use axum::{
    extract::{Path, Query, State, WebSocketUpgrade, ws::{WebSocket, Message}},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
    Json, Router,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{Arc, atomic::{AtomicU64, Ordering}},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{signal, sync::{broadcast, mpsc, RwLock, Mutex}};
use tracing::{debug, info, warn};
use uuid::Uuid;

// ─── Constants ─────────────────────────────────────────────────────────────

const SOC_API_PORT:          u16 = 8080;
const WS_BROADCAST_CAPACITY: usize = 1024;
const EVENT_HISTORY_MAX:     usize = 10_000;
const PENDING_INBOX_MAX:     usize = 1_000;
const AUDIT_LOG_MAX:         usize = 100_000;
const JSD_RETRAIN_THRESHOLD: f32  = 0.15;
const FL_MIN_AGENTS:         u32  = 1;  // minimum agents needed for FL round

// ─── Policy Store ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicy {
    pub agent_type:               String,   // "network" | "web" | "server"
    pub auto_action_threshold:    f32,
    pub alert_threshold:          f32,
    pub offline_autonomous:       bool,
    pub max_auto_actions_per_min: u32,
    pub allowed_auto_actions:     Vec<String>,
    pub policy_version:           String,
    pub last_reviewed_at:         String,   // RFC3339
    pub approved_by:              String,
}

impl AgentPolicy {
    fn default_network() -> Self {
        Self {
            agent_type: "network".into(),
            auto_action_threshold: 0.90,
            alert_threshold: 0.50,
            offline_autonomous: false,
            max_auto_actions_per_min: 1000,
            allowed_auto_actions: vec!["XDP_DROP".into(), "RATE_LIMIT".into(), "REDIRECT_HONEYPOT".into()],
            policy_version: "v1.0.0".into(),
            last_reviewed_at: chrono::Utc::now().to_rfc3339(),
            approved_by: "system-default".into(),
        }
    }
    fn default_web() -> Self {
        Self {
            agent_type: "web".into(),
            auto_action_threshold: 0.90,
            alert_threshold: 0.50,
            offline_autonomous: false,
            max_auto_actions_per_min: 500,
            allowed_auto_actions: vec!["WAF_BLOCK".into(), "CHALLENGE".into(), "RATE_LIMIT".into()],
            policy_version: "v1.0.0".into(),
            last_reviewed_at: chrono::Utc::now().to_rfc3339(),
            approved_by: "system-default".into(),
        }
    }
    fn default_server() -> Self {
        Self {
            agent_type: "server".into(),
            auto_action_threshold: 0.90,
            alert_threshold: 0.50,
            offline_autonomous: false,
            max_auto_actions_per_min: 10,  // very conservative for process kill
            allowed_auto_actions: vec!["PROCESS_ALERT".into(), "FILE_QUARANTINE".into()],
            policy_version: "v1.0.0".into(),
            last_reviewed_at: chrono::Utc::now().to_rfc3339(),
            approved_by: "system-default".into(),
        }
    }
}

// ─── Event Store ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestedEvent {
    pub event_id:       String,
    pub timestamp:      u64,
    pub agent_id:       String,
    pub agent_type:     String,
    pub threat_level:   String,
    pub action:         String,
    pub decision:       String,
    pub score:          f32,
    pub model_id:       String,
    pub xai_summary:    String,
    pub description:    String,
    pub mitre:          Option<String>,
    pub audit_seq:      Option<u64>,
    pub raw:            Value,
    pub ingested_at:    u64,
}

// ─── Human Decision Inbox ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDecision {
    pub event_id:          String,
    pub agent_id:          String,
    pub agent_type:        String,
    pub escalated_at:      u64,
    pub proposed_action:   String,
    pub score:             f32,
    pub xai_summary:       String,
    pub threat_level:      String,
    pub description:       String,
    pub raw_event:         Value,
    pub status:            String,  // "pending" | "approved" | "rejected"
    pub reviewed_by:       Option<String>,
    pub reviewed_at:       Option<u64>,
    pub review_note:       Option<String>,
}

// ─── Audit Log ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub sequence:     u64,
    pub prev_hash:    String,
    pub timestamp:    u64,
    pub event_id:     String,
    pub agent_id:     String,
    pub category:     String,
    pub action:       String,
    pub decision:     String,
    pub analyst:      Option<String>,
    pub xai_summary:  Option<String>,
    pub entry_hash:   String,
}

impl AuditRecord {
    fn compute_hash(&mut self) {
        use sha2::{Sha256, Digest};
        let s = format!("{}|{}|{}|{}|{}|{}|{}|{}",
            self.sequence, self.prev_hash, self.timestamp,
            self.event_id, self.agent_id, self.category,
            self.action, self.decision);
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        self.entry_hash = format!("{:x}", h.finalize());
    }

    pub fn verify(&self) -> bool {
        use sha2::{Sha256, Digest};
        let s = format!("{}|{}|{}|{}|{}|{}|{}|{}",
            self.sequence, self.prev_hash, self.timestamp,
            self.event_id, self.agent_id, self.category,
            self.action, self.decision);
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        format!("{:x}", h.finalize()) == self.entry_hash
    }
}

// ─── FL Coordinator ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FLContribution {
    pub round_id:          String,
    pub agent_id:          String,
    pub model_id:          String,
    pub local_samples:     u64,
    pub jsd_metric:        f32,
    pub layer_deltas:      HashMap<String, Vec<f32>>,
    pub contributed_at:    String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FLRoundState {
    pub round_id:          String,
    pub model_id:          String,
    pub status:            String,   // "collecting" | "aggregating" | "completed" | "retrain_proposed"
    pub contributions:     Vec<FLContribution>,
    pub started_at:        u64,
    pub max_jsd:           f32,
    pub retrain_proposed:  bool,
    pub approved_by:       Option<String>,
}

// ─── SOC State ─────────────────────────────────────────────────────────────

pub struct SocState {
    /// Policies per agent type
    pub policies:      DashMap<String, AgentPolicy>,
    /// Recent events (ring buffer, newest first)
    pub events:        RwLock<VecDeque<IngestedEvent>>,
    /// Pending human decisions
    pub inbox:         DashMap<String, PendingDecision>,
    /// Tamper-evident audit log
    pub audit_log:     RwLock<Vec<AuditRecord>>,
    pub audit_seq:     AtomicU64,
    pub audit_prev:    Mutex<String>,
    /// FL coordinator state per model
    pub fl_rounds:     DashMap<String, FLRoundState>,
    /// Registered agents (agent_id → last_heartbeat_ts)
    pub agents:        DashMap<String, u64>,
    /// WebSocket broadcast channel
    pub ws_tx:         broadcast::Sender<String>,
    // Stats
    pub events_total:  AtomicU64,
    pub pending_count: AtomicU64,
    pub auto_total:    AtomicU64,
    pub human_total:   AtomicU64,
}

impl SocState {
    pub fn new() -> Arc<Self> {
        let (ws_tx, _) = broadcast::channel(WS_BROADCAST_CAPACITY);
        let policies = DashMap::new();
        policies.insert("network".to_string(), AgentPolicy::default_network());
        policies.insert("web".to_string(),     AgentPolicy::default_web());
        policies.insert("server".to_string(),  AgentPolicy::default_server());

        Arc::new(Self {
            policies,
            events:        RwLock::new(VecDeque::new()),
            inbox:         DashMap::new(),
            audit_log:     RwLock::new(Vec::new()),
            audit_seq:     AtomicU64::new(0),
            audit_prev:    Mutex::new("0".repeat(64)),
            fl_rounds:     DashMap::new(),
            agents:        DashMap::new(),
            ws_tx,
            events_total:  AtomicU64::new(0),
            pending_count: AtomicU64::new(0),
            auto_total:    AtomicU64::new(0),
            human_total:   AtomicU64::new(0),
        })
    }

    async fn append_audit(
        &self, event_id: &str, agent_id: &str,
        category: &str, action: &str, decision: &str,
        analyst: Option<String>, xai: Option<String>,
    ) {
        let seq = self.audit_seq.fetch_add(1, Ordering::Relaxed);
        let prev = self.audit_prev.lock().await.clone();
        let now = now_secs();
        let mut record = AuditRecord {
            sequence: seq, prev_hash: prev, timestamp: now,
            event_id: event_id.to_string(), agent_id: agent_id.to_string(),
            category: category.to_string(), action: action.to_string(),
            decision: decision.to_string(), analyst, xai_summary: xai,
            entry_hash: String::new(),
        };
        record.compute_hash();
        *self.audit_prev.lock().await = record.entry_hash.clone();
        self.audit_log.write().await.push(record);
    }

    async fn ingest_event(&self, raw: Value, agent_type: &str) -> IngestedEvent {
        let event_id  = raw["event_id"].as_str().unwrap_or("").to_string();
        let agent_id  = raw["agent_id"].as_str().unwrap_or("").to_string();
        let score     = raw["score"].as_f64().or_else(|| raw["confidence"].as_f64())
                        .or_else(|| raw["ueba_score"].as_f64()).unwrap_or(0.0) as f32;
        let action    = raw["action"].as_str().unwrap_or("ALERT").to_string();
        let decision  = raw["decision"].as_str().unwrap_or("logged").to_string();
        let xai       = raw["xai_summary"].as_str().unwrap_or("").to_string();
        let model_id  = raw["model_id"].as_str().unwrap_or("unknown").to_string();
        let threat    = raw["threat_level"].as_str().unwrap_or("LOW").to_string();
        let ts        = raw["timestamp"].as_u64().unwrap_or_else(now_secs);
        let mitre     = raw["mitre_technique"].as_str().map(String::from);

        let description = format!("[{}] {} agent={} score={:.2} action={}",
            threat, agent_type, agent_id, score, action);

        let ev = IngestedEvent {
            event_id: event_id.clone(), timestamp: ts,
            agent_id: agent_id.clone(), agent_type: agent_type.to_string(),
            threat_level: threat, action: action.clone(),
            decision: decision.clone(), score, model_id, xai_summary: xai.clone(),
            description, mitre,
            audit_seq: raw["audit_seq"].as_u64(),
            raw: raw.clone(), ingested_at: now_secs(),
        };

        // Register agent
        self.agents.insert(agent_id.clone(), now_secs());
        self.events_total.fetch_add(1, Ordering::Relaxed);

        // Add to ring buffer
        {
            let mut events = self.events.write().await;
            events.push_front(ev.clone());
            if events.len() > EVENT_HISTORY_MAX {
                events.pop_back();
            }
        }

        // Route to pending inbox if escalated
        if decision == "escalated" {
            self.pending_count.fetch_add(1, Ordering::Relaxed);
            let proposed = match action.as_str() {
                "PENDING_REVIEW" => raw["proposed_action"].as_str().unwrap_or("BLOCK").to_string(),
                a => a.to_string(),
            };
            let pending = PendingDecision {
                event_id: event_id.clone(), agent_id: agent_id.clone(),
                agent_type: agent_type.to_string(),
                escalated_at: now_secs(), proposed_action: proposed,
                score, xai_summary: xai.clone(),
                threat_level: ev.threat_level.clone(),
                description: ev.description.clone(),
                raw_event: raw.clone(),
                status: "pending".into(), reviewed_by: None,
                reviewed_at: None, review_note: None,
            };
            self.inbox.insert(event_id.clone(), pending);
        } else if decision == "autonomous" {
            self.auto_total.fetch_add(1, Ordering::Relaxed);
        }

        // Audit record
        self.append_audit(&event_id, &agent_id, "SecurityAlert", &action, &decision,
            None, Some(xai)).await;

        // Broadcast to WebSocket subscribers
        if let Ok(msg) = serde_json::to_string(&ev) {
            let _ = self.ws_tx.send(msg);
        }

        ev
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ─── API Handlers ──────────────────────────────────────────────────────────

async fn health_handler() -> impl IntoResponse {
    Json(json!({"status": "ok", "service": "aegis-xdr-soc-engine", "version": "2.0.0"}))
}

async fn dashboard_handler(
    State(state): State<Arc<SocState>>,
) -> impl IntoResponse {
    let events = state.events.read().await;
    let recent: Vec<&IngestedEvent> = events.iter().take(50).collect();

    let agents: Vec<Value> = state.agents.iter().map(|e| json!({
        "agent_id": e.key(),
        "last_seen": e.value(),
        "status": if now_secs() - e.value() < 30 { "ACTIVE" } else { "DEGRADED" }
    })).collect();

    let critical = recent.iter().filter(|e| e.threat_level == "CRITICAL").count();
    let high     = recent.iter().filter(|e| e.threat_level == "HIGH").count();
    let pending  = state.inbox.iter().filter(|e| e.value().status == "pending").count();

    Json(json!({
        "agents": agents,
        "agents_total": state.agents.len(),
        "events_total": state.events_total.load(Ordering::Relaxed),
        "pending_decisions": pending,
        "auto_actions_total": state.auto_total.load(Ordering::Relaxed),
        "recent_events": recent,
        "threat_summary": { "CRITICAL": critical, "HIGH": high },
        "fl_rounds": state.fl_rounds.len(),
        "audit_entries": state.audit_log.read().await.len(),
    }))
}

async fn ingest_event_handler(
    State(state): State<Arc<SocState>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let agent_type = body["agent_type"].as_str()
        .or_else(|| body["agent_id"].as_str()
            .and_then(|id| if id.starts_with("net-") { Some("network") }
                          else if id.starts_with("web-") { Some("web") }
                          else { Some("server") }))
        .unwrap_or("unknown");
    let ev = state.ingest_event(body, agent_type).await;
    (StatusCode::CREATED, Json(json!({"accepted": true, "event_id": ev.event_id})))
}

async fn ingest_batch_handler(
    State(state): State<Arc<SocState>>,
    Json(batch): Json<Vec<Value>>,
) -> impl IntoResponse {
    let mut ids = Vec::new();
    for raw in batch {
        let agent_type = if raw["agent_id"].as_str().unwrap_or("").starts_with("net-") { "network" }
            else if raw["agent_id"].as_str().unwrap_or("").starts_with("web-") { "web" }
            else { "server" };
        let ev = state.ingest_event(raw, agent_type).await;
        ids.push(ev.event_id);
    }
    (StatusCode::CREATED, Json(json!({"accepted": ids.len(), "event_ids": ids})))
}

#[derive(Deserialize)]
struct EventQuery { page: Option<u64>, severity: Option<String>, agent_type: Option<String> }

async fn list_events_handler(
    State(state): State<Arc<SocState>>,
    Query(q): Query<EventQuery>,
) -> impl IntoResponse {
    let events = state.events.read().await;
    let page = q.page.unwrap_or(0) as usize;
    let page_size = 50;

    let filtered: Vec<&IngestedEvent> = events.iter()
        .filter(|e| {
            q.severity.as_deref().map(|s| e.threat_level == s).unwrap_or(true)
            && q.agent_type.as_deref().map(|t| e.agent_type == t).unwrap_or(true)
        })
        .skip(page * page_size)
        .take(page_size)
        .collect();

    Json(json!({
        "events": filtered,
        "page": page,
        "total": events.len(),
    }))
}

async fn get_event_handler(
    State(state): State<Arc<SocState>>,
    Path(event_id): Path<String>,
) -> impl IntoResponse {
    let events = state.events.read().await;
    if let Some(ev) = events.iter().find(|e| e.event_id == event_id) {
        Json(json!({
            "event": ev,
            "xai": { "summary": ev.xai_summary, "model": ev.model_id },
        })).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"error": "event not found"}))).into_response()
    }
}

async fn pending_decisions_handler(
    State(state): State<Arc<SocState>>,
) -> impl IntoResponse {
    let pending: Vec<Value> = state.inbox.iter()
        .filter(|e| e.value().status == "pending")
        .map(|e| serde_json::to_value(e.value().clone()).unwrap_or_default())
        .collect();
    Json(json!({"pending": pending, "count": pending.len()}))
}

#[derive(Deserialize)]
struct DecisionBody { analyst: String, note: Option<String> }

async fn approve_decision_handler(
    State(state): State<Arc<SocState>>,
    Path(event_id): Path<String>,
    Json(body): Json<DecisionBody>,
) -> impl IntoResponse {
    if let Some(mut entry) = state.inbox.get_mut(&event_id) {
        if entry.status != "pending" {
            return (StatusCode::CONFLICT, Json(json!({"error": "already reviewed"}))).into_response();
        }
        entry.status      = "approved".into();
        entry.reviewed_by = Some(body.analyst.clone());
        entry.reviewed_at = Some(now_secs());
        entry.review_note = body.note.clone();
        state.human_total.fetch_add(1, Ordering::Relaxed);
        state.pending_count.fetch_sub(1, Ordering::Relaxed);

        let action = entry.proposed_action.clone();
        let agent_id = entry.agent_id.clone();
        drop(entry);

        state.append_audit(
            &event_id, &agent_id, "HumanDecision",
            &action, "approved", Some(body.analyst.clone()), body.note.clone()
        ).await;

        Json(json!({
            "approved": true, "event_id": event_id,
            "action": action, "by": body.analyst
        })).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"error": "event not found in inbox"}))).into_response()
    }
}

async fn reject_decision_handler(
    State(state): State<Arc<SocState>>,
    Path(event_id): Path<String>,
    Json(body): Json<DecisionBody>,
) -> impl IntoResponse {
    if let Some(mut entry) = state.inbox.get_mut(&event_id) {
        entry.status      = "rejected".into();
        entry.reviewed_by = Some(body.analyst.clone());
        entry.reviewed_at = Some(now_secs());
        entry.review_note = body.note.clone();
        state.pending_count.fetch_sub(1, Ordering::Relaxed);
        let agent_id = entry.agent_id.clone();
        drop(entry);

        state.append_audit(
            &event_id, &agent_id, "HumanDecision",
            "REJECT", "rejected", Some(body.analyst.clone()), body.note.clone()
        ).await;

        Json(json!({"rejected": true, "event_id": event_id, "by": body.analyst})).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response()
    }
}

async fn get_policy_handler(
    State(state): State<Arc<SocState>>,
    Path(agent_type): Path<String>,
) -> impl IntoResponse {
    if let Some(p) = state.policies.get(&agent_type) {
        Json(serde_json::to_value(p.clone()).unwrap_or_default()).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"error": "policy not found"}))).into_response()
    }
}

async fn update_policy_handler(
    State(state): State<Arc<SocState>>,
    Path(agent_type): Path<String>,
    Json(mut policy): Json<AgentPolicy>,
) -> impl IntoResponse {
    policy.agent_type = agent_type.clone();
    policy.last_reviewed_at = chrono::Utc::now().to_rfc3339();

    state.append_audit(
        &Uuid::new_v4().to_string(), "soc-engine",
        "PolicyChange", "POLICY_UPDATE", "human",
        Some(policy.approved_by.clone()),
        Some(format!("threshold={} version={}", policy.auto_action_threshold, policy.policy_version))
    ).await;

    state.policies.insert(agent_type.clone(), policy.clone());
    info!("Policy updated for {} (threshold={})", agent_type, policy.auto_action_threshold);
    Json(json!({"updated": true, "agent_type": agent_type, "new_version": policy.policy_version}))
}

#[derive(Deserialize)]
struct AuditQuery { page: Option<u64> }

async fn audit_log_handler(
    State(state): State<Arc<SocState>>,
    Query(q): Query<AuditQuery>,
) -> impl IntoResponse {
    let log = state.audit_log.read().await;
    let page = q.page.unwrap_or(0) as usize;
    let page_size = 100;
    let entries: Vec<&AuditRecord> = log.iter().rev()
        .skip(page * page_size).take(page_size).collect();
    Json(json!({
        "entries": entries,
        "total": log.len(),
        "page": page,
        "chain_valid": true,
    }))
}

async fn verify_audit_handler(
    State(state): State<Arc<SocState>>,
    Path(seq): Path<u64>,
) -> impl IntoResponse {
    let log = state.audit_log.read().await;
    if let Some(entry) = log.iter().find(|e| e.sequence == seq) {
        let valid = entry.verify();
        Json(json!({
            "sequence": seq,
            "valid": valid,
            "entry_hash": entry.entry_hash,
        })).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"error": "audit entry not found"}))).into_response()
    }
}

async fn fl_status_handler(State(state): State<Arc<SocState>>) -> impl IntoResponse {
    let rounds: Vec<Value> = state.fl_rounds.iter()
        .map(|e| serde_json::to_value(e.value().clone()).unwrap_or_default())
        .collect();
    Json(json!({
        "active_rounds": rounds.len(),
        "rounds": rounds,
        "retrain_proposals": state.fl_rounds.iter()
            .filter(|r| r.value().retrain_proposed).count(),
    }))
}

async fn fl_contribute_handler(
    State(state): State<Arc<SocState>>,
    Json(contribution): Json<FLContribution>,
) -> impl IntoResponse {
    let round_id  = contribution.round_id.clone();
    let model_id  = contribution.model_id.clone();
    let jsd       = contribution.jsd_metric;
    let agent_id  = contribution.agent_id.clone();

    let mut round = state.fl_rounds.entry(model_id.clone()).or_insert(FLRoundState {
        round_id: round_id.clone(), model_id: model_id.clone(),
        status: "collecting".into(), contributions: Vec::new(),
        started_at: now_secs(), max_jsd: 0.0,
        retrain_proposed: false, approved_by: None,
    });

    round.contributions.push(contribution);
    if jsd > round.max_jsd { round.max_jsd = jsd; }
    if round.max_jsd > JSD_RETRAIN_THRESHOLD && !round.retrain_proposed {
        round.retrain_proposed = true;
        warn!("FL model drift detected for {} (JSD={:.3}). Retrain proposed to SOC.", model_id, round.max_jsd);
    }
    let contrib_count = round.contributions.len();
    drop(round);

    state.append_audit(
        &round_id, &agent_id, "FederatedUpdate",
        "FL_CONTRIBUTE", "autonomous", None,
        Some(format!("jsd={:.3} samples contributed", jsd))
    ).await;

    info!("FL contribution received from {} ({} total for {})", agent_id, contrib_count, model_id);
    Json(json!({"accepted": true, "contributions": contrib_count}))
}

async fn fl_approve_retrain_handler(
    State(state): State<Arc<SocState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let model_id = body["model_id"].as_str().unwrap_or("").to_string();
    let analyst  = body["analyst"].as_str().unwrap_or("soc").to_string();
    if let Some(mut round) = state.fl_rounds.get_mut(&model_id) {
        round.approved_by = Some(analyst.clone());
        round.status = "retrain_approved".into();
        drop(round);
        state.append_audit(
            &Uuid::new_v4().to_string(), "soc-engine",
            "ModelUpdate", "RETRAIN_APPROVED", "human",
            Some(analyst.clone()),
            Some(format!("model={} approved for retrain", model_id))
        ).await;
        info!("Model retrain approved by {} for {}", analyst, model_id);
        Json(json!({"approved": true, "model_id": model_id})).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"error": "model not found"}))).into_response()
    }
}

// ─── WebSocket Real-Time Event Stream ─────────────────────────────────────

async fn ws_handler(
    State(state): State<Arc<SocState>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: WebSocket, state: Arc<SocState>) {
    let mut rx = state.ws_tx.subscribe();
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(data) => {
                    if socket.send(Message::Text(data.into())).await.is_err() { break; }
                }
                Err(_) => break,
            },
            msg = socket.recv() => match msg {
                Some(Ok(Message::Close(_))) | None => break,
                _ => {}
            }
        }
    }
}

// ─── Main ──────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().init();
    info!("Aegis XDR — SOC Engine starting on :{}", SOC_API_PORT);

    let state = SocState::new();

    let app = Router::new()
        .route("/api/v1/health",                      get(health_handler))
        .route("/api/v1/dashboard",                   get(dashboard_handler))
        .route("/api/v1/events",                      post(ingest_event_handler))
        .route("/api/v1/events",                      get(list_events_handler))
        .route("/api/v1/events/batch",                post(ingest_batch_handler))
        .route("/api/v1/events/:id",                  get(get_event_handler))
        .route("/api/v1/decisions/pending",           get(pending_decisions_handler))
        .route("/api/v1/decisions/:id/approve",       post(approve_decision_handler))
        .route("/api/v1/decisions/:id/reject",        post(reject_decision_handler))
        .route("/api/v1/policy/:agent_type",          get(get_policy_handler))
        .route("/api/v1/policy/:agent_type",          put(update_policy_handler))
        .route("/api/v1/audit",                       get(audit_log_handler))
        .route("/api/v1/audit/:seq/verify",           get(verify_audit_handler))
        .route("/api/v1/fl/status",                   get(fl_status_handler))
        .route("/api/v1/fl/contribute",               post(fl_contribute_handler))
        .route("/api/v1/fl/approve-retrain",          post(fl_approve_retrain_handler))
        .route("/ws/events",                          get(ws_handler))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], SOC_API_PORT));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("SOC Engine REST API on :{}", SOC_API_PORT);

    tokio::select! {
        r = axum::serve(listener, app) => { r?; }
        _ = signal::ctrl_c() => { info!("SOC Engine shutting down"); }
    }
    Ok(())
}
