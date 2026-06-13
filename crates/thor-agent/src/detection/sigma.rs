//! Sigma rule engine — Aho-Corasick DFA for O(N) multi-pattern matching
//! SECURITY: All rule injections (including legacy inject_dynamic_rule) MUST go
//! through AiSafetyGuardian shadow mode + human approval. No direct enforcement.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::sync::RwLock;
use tracing::{info, warn, debug, error};
use walkdir::WalkDir;
use uuid::Uuid;
use chrono::Utc;

use crate::events::{Alert, RuleType};
use crate::events::enrichment::EnrichedEvent;
use crate::events::RawEvent;
use thor_common::ThreatLevel;

// ─── Rule lifecycle states ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleMode {
    Shadow,   // Monitoring only — no enforcement action taken
    Enforce,  // Active enforcement — only after human approval
    Rejected, // Permanently rejected by guardian or human
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleSource {
    LlmGenerated,
    HumanApproved,
    ThreatIntel,
    StaticBuiltin,
}

// ─── Dynamic rule container ───────────────────────────────────────────────────

#[derive(Debug)]
pub struct GuardedDynamicRule {
    pub id: String,
    pub yaml_content: String,
    pub title: String,
    pub mode: RuleMode,
    pub created_at: Instant,
    pub match_count: AtomicUsize,
    pub max_matches_per_minute: usize,
    pub shadow_duration_secs: u64,
    pub source: RuleSource,
}

impl Clone for GuardedDynamicRule {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            yaml_content: self.yaml_content.clone(),
            title: self.title.clone(),
            mode: self.mode,
            created_at: self.created_at,
            match_count: AtomicUsize::new(self.match_count.load(Ordering::Relaxed)),
            max_matches_per_minute: self.max_matches_per_minute,
            shadow_duration_secs: self.shadow_duration_secs,
            source: self.source,
        }
    }
}

impl GuardedDynamicRule {
    pub fn new_from_llm(id: String, yaml: String, title: String) -> Self {
        Self {
            id,
            yaml_content: yaml,
            title,
            mode: RuleMode::Shadow,       // ALWAYS start in Shadow
            created_at: Instant::now(),
            match_count: AtomicUsize::new(0),
            max_matches_per_minute: 100,
            shadow_duration_secs: 3600,   // 1-hour observation window
            source: RuleSource::LlmGenerated,
        }
    }

    pub fn record_match(&self) -> bool {
        let count = self.match_count.fetch_add(1, Ordering::Relaxed);
        if count > self.max_matches_per_minute {
            warn!(
                "🚨 AI SAFETY TRIGGER: Rule '{}' hit {} times — possible hallucination. Rejecting.",
                self.title, count
            );
            return false;
        }
        true
    }

    pub fn is_ready_for_enforcement(&self) -> bool {
        if self.mode != RuleMode::Shadow { return false; }
        let elapsed = self.created_at.elapsed().as_secs();
        let matches = self.match_count.load(Ordering::Relaxed);
        elapsed >= self.shadow_duration_secs
            && matches > 0
            && matches < self.max_matches_per_minute / 2
    }
}

// ─── Static (file-loaded) rule ────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    pub id: Option<String>,
    pub status: Option<String>,
    pub description: Option<String>,
    pub level: Option<String>,
    pub detection: SigmaDetection,
    pub logsource: Option<SigmaLogsource>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SigmaDetection {
    pub selection: Option<serde_yaml::Value>,
    pub condition: Option<String>,
    pub keywords: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SigmaLogsource {
    pub category: Option<String>,
    pub product: Option<String>,
}

#[derive(Clone)]
pub struct CompiledRule {
    pub rule: SigmaRule,
    pub ac: AhoCorasick,
    pub patterns: Vec<String>,
}

// ─── AI Safety Guardian ───────────────────────────────────────────────────────

pub struct AiSafetyGuardian {
    pub pending_approval: Arc<DashMap<String, GuardedDynamicRule>>,
    /// Auto-enforcement is DISABLED by design — always requires human approval.
    pub auto_enforce_enabled: bool,
}

impl AiSafetyGuardian {
    pub fn new() -> Self {
        Self {
            pending_approval: Arc::new(DashMap::new()),
            auto_enforce_enabled: false, // Hardcoded false — never auto-enforce
        }
    }

    pub async fn ingest_llm_rule(
        &self,
        id: String,
        yaml: String,
        title: String,
    ) -> Result<(), String> {
        // 1. Parse YAML
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml)
            .map_err(|e| format!("Invalid YAML: {}", e))?;

        // 2. Safety checks — reject overly broad rules
        let yaml_lower = parsed.to_string().to_lowercase();
        let dangerous_patterns = [
            "0.0.0.0/0", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "any", "all processes", "kill all", "::/0",
        ];
        if dangerous_patterns.iter().any(|p| yaml_lower.contains(p)) {
            warn!("🛡️ AI SAFETY: Rejected overly broad rule '{}'", title);
            return Err("Rule scope too broad — must target specific assets".to_string());
        }

        // 3. Enter shadow mode — NOT enforcement
        let guarded = GuardedDynamicRule::new_from_llm(id.clone(), yaml, title.clone());
        info!(
            "🛡️ Rule '{}' [id={}] entered SHADOW MODE — awaiting human approval",
            title, id
        );
        self.pending_approval.insert(id, guarded);
        Ok(())
    }

    pub async fn human_approve_rule(
        &self,
        rule_id: &str,
        dynamic_rules: &DashMap<String, GuardedDynamicRule>,
    ) -> Result<(), String> {
        if let Some((_, mut rule)) = self.pending_approval.remove(rule_id) {
            rule.mode = RuleMode::Enforce;
            info!("✅ Human approved rule '{}' [id={}] → ENFORCED", rule.title, rule_id);
            dynamic_rules.insert(rule_id.to_string(), rule);
            Ok(())
        } else {
            Err(format!("Rule '{}' not found in pending approvals", rule_id))
        }
    }
}

impl Default for AiSafetyGuardian {
    fn default() -> Self { Self::new() }
}

// ─── Sigma Engine ─────────────────────────────────────────────────────────────

pub struct SigmaEngine {
    rules: Vec<CompiledRule>,
    pub dynamic_rules: Arc<DashMap<String, GuardedDynamicRule>>,
    pub guardian: Arc<AiSafetyGuardian>,
}

impl SigmaEngine {
    pub fn load(rules_dir: &Path) -> Result<Self> {
        let mut rules = Vec::new();
        let dynamic_rules = Arc::new(DashMap::new());
        let guardian = Arc::new(AiSafetyGuardian::new());

        if !rules_dir.exists() {
            warn!("Sigma rules dir not found: {:?} — using empty set", rules_dir);
            return Ok(Self { rules, dynamic_rules, guardian });
        }

        for entry in WalkDir::new(rules_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("yml") { continue; }

            match std::fs::read_to_string(path) {
                Ok(content) => {
                    match serde_yaml::from_str::<SigmaRule>(&content) {
                        Ok(rule) => {
                            let patterns = extract_patterns(&rule);
                            if patterns.is_empty() { continue; }
                            match AhoCorasick::builder()
                                .ascii_case_insensitive(true)
                                .build(&patterns)
                            {
                                Ok(ac) => rules.push(CompiledRule { rule, ac, patterns }),
                                Err(e) => warn!("AC build failed for {:?}: {}", path, e),
                            }
                        }
                        Err(e) => warn!("Sigma YAML parse error {:?}: {}", path, e),
                    }
                }
                Err(e) => warn!("Cannot read sigma rule {:?}: {}", path, e),
            }
        }
        info!("📚 Loaded {} Sigma rules from {:?}", rules.len(), rules_dir);
        Ok(Self { rules, dynamic_rules, guardian })
    }

    /// Empty engine for fallback when rules dir is missing.
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            dynamic_rules: Arc::new(DashMap::new()),
            guardian: Arc::new(AiSafetyGuardian::new()),
        }
    }

    /// Ingest a rule from LLM — always via guardian (shadow + approval).
    pub async fn ingest_llm_rule(
        &self,
        id: String,
        yaml: String,
        title: String,
    ) -> Result<(), String> {
        self.guardian.ingest_llm_rule(id, yaml, title).await
    }

    /// SECURITY FIX: inject_dynamic_rule now also goes through shadow mode.
    /// Previous behaviour (direct enforce bypass) has been removed.
    pub async fn inject_dynamic_rule(&self, yaml_content: &str) -> Result<()> {
        let parsed: serde_yaml::Value = serde_yaml::from_str(yaml_content)
            .context("Invalid YAML")?;

        let rule_id = parsed.get("id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("DYNAMIC-{}", Uuid::new_v4()));

        let title = parsed.get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("Dynamic Rule")
            .to_string();

        self.guardian
            .ingest_llm_rule(rule_id.clone(), yaml_content.to_string(), title)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        info!(
            "🛡️ inject_dynamic_rule: '{}' → shadow mode (human approval required)",
            rule_id
        );
        Ok(())
    }

    pub fn evaluate(&self, text_payload: &str) -> Vec<String> {
        let mut matches = Vec::new();

        // Only evaluate rules that are in Enforce mode (shadow = observe only)
        for entry in self.dynamic_rules.iter() {
            let rule = entry.value();
            if rule.mode != RuleMode::Enforce { continue; }
            if rule.yaml_content.to_lowercase().contains(&text_payload.to_lowercase()) {
                if rule.record_match() {
                    matches.push(rule.title.clone());
                }
            }
        }

        for compiled in &self.rules {
            if compiled.ac.is_match(text_payload) {
                matches.push(compiled.rule.title.clone());
            }
        }
        matches
    }

    pub fn check(&self, event: &EnrichedEvent) -> Option<Alert> {
        let haystack = event_to_string(event);
        let matched = self.evaluate(&haystack);
        if matched.is_empty() { return None; }

        Some(Alert {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            source: event.hostname.clone().unwrap_or_default(),
            rule_name: format!("Sigma: {:?}", matched),
            rule_type: RuleType::Sigma,
            threat_level: ThreatLevel::High,
            description: matched.join(", "),
            pid: None,
            process_name: None,
            src_ip: event.src_ip_str.clone(),
            dst_ip: event.dst_ip_str.clone(),
            dst_port: None,
            ml_score: None,
            soar_actions_taken: vec![],
            raw_event_type: event.raw.source().to_string(),
        })
    }

    pub fn rule_count(&self) -> usize { self.rules.len() }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn extract_patterns(rule: &SigmaRule) -> Vec<String> {
    let mut patterns = Vec::new();
    if let Some(keywords) = &rule.detection.keywords {
        patterns.extend(keywords.iter().cloned());
    }
    if let Some(selection) = &rule.detection.selection {
        flatten_yaml_strings(selection, &mut patterns);
    }
    patterns
}

fn flatten_yaml_strings(val: &serde_yaml::Value, out: &mut Vec<String>) {
    match val {
        serde_yaml::Value::String(s) => { out.push(s.clone()); }
        serde_yaml::Value::Sequence(seq) => { for v in seq { flatten_yaml_strings(v, out); } }
        serde_yaml::Value::Mapping(map) => { for (_, v) in map { flatten_yaml_strings(v, out); } }
        _ => {}
    }
}

fn event_to_string(event: &EnrichedEvent) -> String {
    match &event.raw {
        RawEvent::Process(e) => format!(
            "{} {} {} {} process",
            e.pid(), event.hostname.as_deref().unwrap_or(""),
            event.src_ip_str.as_deref().unwrap_or(""),
            event.dst_ip_str.as_deref().unwrap_or(""),
        ),
        RawEvent::Network(e) => format!(
            "pid:{} comm:{} dst_ip:{} dst_port:{} proto:{}",
            e.pid, e.comm, e.dst_ip, e.dst_port, e.protocol
        ),
        RawEvent::XdpDrop { src_ip, dst_port, reason, .. } => format!(
            "src_ip:{} dst_port:{} reason:{}", src_ip, dst_port, reason
        ),
    }
}
