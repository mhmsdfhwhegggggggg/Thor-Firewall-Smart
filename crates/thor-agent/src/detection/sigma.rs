//! Sigma rule engine — Aho-Corasick DFA for O(N) multi-pattern matching
//! Loads YAML rules from rules/sigma/*.yml

use aho_corasick::AhoCorasick;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{info, warn, debug};
use walkdir::WalkDir;
use uuid::Uuid;
use chrono::Utc;

use crate::events::{Alert, RuleType};
use crate::events::enrichment::EnrichedEvent;
use crate::events::RawEvent;
use thor_common::ThreatLevel;

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

pub struct SigmaEngine {
    rules: Vec<CompiledRule>,
}

impl SigmaEngine {
    pub fn load(rules_dir: &Path) -> Result<Self> {
        let mut rules = Vec::new();
        if !rules_dir.exists() {
            warn!("Sigma rules dir not found: {:?} — using empty set", rules_dir);
            return Ok(Self { rules });
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
                                Ok(ac) => {
                                    debug!("Loaded Sigma rule: {} ({} patterns)", rule.title, patterns.len());
                                    rules.push(CompiledRule { rule, ac, patterns });
                                }
                                Err(e) => warn!("AC build failed for {:?}: {}", path, e),
                            }
                        }
                        Err(e) => warn!("Sigma YAML parse error in {:?}: {}", path, e),
                    }
                }
                Err(e) => warn!("Cannot read sigma rule {:?}: {}", path, e),
            }
        }
        info!("📚 Loaded {} Sigma rules from {:?}", rules.len(), rules_dir);
        Ok(Self { rules })
    }

    pub fn check(&self, event: &EnrichedEvent) -> Option<Alert> {
        let haystack = event_to_string(event);
        for compiled in &self.rules {
            if compiled.ac.is_match(&haystack) {
                let level = compiled.rule.level.as_deref().unwrap_or("medium");
                let threat = match level {
                    "critical" => ThreatLevel::Critical,
                    "high" => ThreatLevel::High,
                    "medium" => ThreatLevel::Medium,
                    _ => ThreatLevel::Low,
                };
                return Some(Alert {
                    id: Uuid::new_v4().to_string(),
                    timestamp: Utc::now(),
                    source: event.hostname.clone().unwrap_or_default(),
                    rule_name: format!("Sigma:{}", compiled.rule.title),
                    rule_type: RuleType::Sigma,
                    threat_level: threat,
                    description: compiled.rule.description.clone()
                        .unwrap_or_else(|| compiled.rule.title.clone()),
                    pid: None,
                    process_name: None,
                    src_ip: event.src_ip_str.clone(),
                    dst_ip: event.dst_ip_str.clone(),
                    dst_port: None,
                    ml_score: None,
                    soar_actions_taken: vec![],
                    raw_event_type: event.raw.source().to_string(),
                });
            }
        }
        None
    }

    pub fn rule_count(&self) -> usize { self.rules.len() }
}

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
        RawEvent::Process(e) => {
            format!("{} {} {} {} {}",
                e.pid(), event.hostname.as_deref().unwrap_or(""),
                event.src_ip_str.as_deref().unwrap_or(""),
                event.dst_ip_str.as_deref().unwrap_or(""), "process")
        }
        RawEvent::Network(e) => {
            format!("pid:{} comm:{} dst_ip:{} dst_port:{} proto:{}",
                e.pid, e.comm, e.dst_ip, e.dst_port, e.protocol)
        }
        RawEvent::XdpDrop { src_ip, dst_port, reason, .. } => {
            format!("src_ip:{} dst_port:{} reason:{}", src_ip, dst_port, reason)
        }
    }
}
