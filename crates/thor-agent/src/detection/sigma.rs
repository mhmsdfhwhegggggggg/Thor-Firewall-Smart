//! Sigma Engine — wraps SigmaCompiler + evaluates rules against enriched events
//! Full condition parsing: AND/OR/NOT/1of/allof

use anyhow::{Context, Result};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use chrono::Utc;
use dashmap::DashMap;
use uuid::Uuid;
use tracing::{info, warn};

use crate::events::{Alert, RuleType};
use crate::events::enrichment::EnrichedEvent;

use super::sigma_compiler::{CompiledSigmaRule, SigmaCompiler};

// ─── Guarded dynamic rule (shadow mode) ──────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RuleMode { Shadow, Enforce, Rejected }

pub struct SigmaEngine {
    rules:         Vec<CompiledSigmaRule>,
    rule_count:    usize,
    /// per-rule match counter (for rate limiting shadow rules)
    match_counts:  DashMap<String, (AtomicUsize, Instant)>,
}

impl SigmaEngine {
    pub fn load(dir: &Path) -> Result<Self> {
        let rules = SigmaCompiler::load_directory(dir);
        let n = rules.len();
        info!("📚 SigmaEngine: {} rules loaded from {:?}", n, dir);
        Ok(Self {
            rule_count:   n,
            rules,
            match_counts: DashMap::new(),
        })
    }

    pub fn rule_count(&self) -> usize { self.rule_count }

    /// Evaluate all rules against event, return first matching alert
    pub fn check(&self, event: &EnrichedEvent) -> Option<Alert> {
        for rule in &self.rules {
            if rule.evaluate(event) {
                return Some(self.make_alert(rule, event));
            }
        }
        None
    }

    /// Evaluate all rules, return ALL matches (for high-fidelity mode)
    pub fn check_all(&self, event: &EnrichedEvent) -> Vec<Alert> {
        self.rules.iter()
            .filter(|r| r.evaluate(event))
            .map(|r| self.make_alert(r, event))
            .collect()
    }

    fn make_alert(&self, rule: &CompiledSigmaRule, event: &EnrichedEvent) -> Alert {
        // Update match counter
        let entry = self.match_counts
            .entry(rule.id.clone())
            .or_insert_with(|| (AtomicUsize::new(0), Instant::now()));
        entry.0.fetch_add(1, Ordering::Relaxed);

        Alert {
            id:           Uuid::new_v4().to_string(),
            timestamp:    Utc::now(),
            source:       event.hostname.clone().unwrap_or_else(|| "unknown".to_string()),
            rule_name:    format!("Sigma:{}", rule.title),
            rule_type:    RuleType::Sigma,
            threat_level: rule.level.clone(),
            description:  format!(
                "[Sigma] {} | tags: {}",
                rule.description,
                rule.tags.join(", ")
            ),
            pid:          None,
            process_name: None,
            src_ip:       event.src_ip_str.clone(),
            dst_ip:       event.dst_ip_str.clone(),
            dst_port:     None,
            ml_score:     None,
            soar_actions_taken: vec![],
            raw_event_type: event.raw.source().to_string(),
        }
    }

    /// Add a dynamic rule (LLM-generated or TI-injected)
    pub fn add_rule(&mut self, yaml_content: &str) -> Result<String> {
        let rule = SigmaCompiler::compile_file(yaml_content)?;
        let id = rule.id.clone();
        self.rules.push(rule);
        self.rule_count += 1;
        Ok(id)
    }
}
