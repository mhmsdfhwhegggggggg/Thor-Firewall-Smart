//! YARA engine — file/memory scanning using libyara (spawn_blocking to avoid tokio starvation)
//!
//! # Fix: Arc<yara::Rules>
//! The rules are compiled ONCE during load() and shared via Arc.
//! Previously, scan() created a new empty Compiler::new() with zero rules → 0 matches.
//! Now: YaraEngine stores compiled_rules: Arc<yara::Rules> and reuses them in every scan().

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};
use walkdir::WalkDir;
use uuid::Uuid;
use chrono::Utc;

use crate::events::{Alert, RuleType};
use crate::events::enrichment::EnrichedEvent;
use crate::events::RawEvent;
use thor_common::ThreatLevel;

/// YARA engine wrapping compiled rules — production-grade implementation.
/// Rules are compiled ONCE at startup and shared via Arc for zero-copy cloning.
#[derive(Clone)]
pub struct YaraEngine {
    /// Compiled YARA rules — shared across all threads via Arc.
    /// CRITICAL FIX: Previously this was missing and scan() created a new
    /// empty Compiler::new() → zero matches. Now compiled once in load().
    compiled_rules: Option<Arc<yara::Rules>>,
    rule_count: usize,
}

impl YaraEngine {
    pub fn load(rules_dir: &Path) -> Result<Self> {
        if !rules_dir.exists() {
            warn!("YARA rules dir not found: {:?} — using empty set", rules_dir);
            return Ok(Self { compiled_rules: None, rule_count: 0 });
        }

        let mut count = 0usize;
        let mut compiler = yara::Compiler::new()?;

        for entry in WalkDir::new(rules_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            let ext = path.extension().and_then(|s| s.to_str());
            if ext != Some("yar") && ext != Some("yara") { continue; }

            match std::fs::read_to_string(path) {
                Ok(content) => {
                    match compiler.add_rules_str(&content) {
                        Ok(_)  => { count += 1; info!("Loaded YARA rule: {:?}", path); }
                        Err(e) => warn!("YARA compile error in {:?}: {}", path, e),
                    }
                }
                Err(e) => warn!("Cannot read YARA rule {:?}: {}", path, e),
            }
        }

        // Compile ALL rules in one shot → one Arc<Rules> shared across threads.
        // This is the critical fix: rules are compiled ONCE and reused in every scan().
        let compiled_rules = if count > 0 {
            match compiler.compile_rules() {
                Ok(rules) => {
                    info!("🔐 Compiled {} YARA rules from {:?} — rules are hot!", count, rules_dir);
                    Some(Arc::new(rules))
                }
                Err(e) => {
                    warn!("YARA final compilation failed: {} — scanning disabled", e);
                    None
                }
            }
        } else {
            warn!("No YARA rules found in {:?} — scanning disabled", rules_dir);
            None
        };

        Ok(Self { compiled_rules, rule_count: count })
    }

    /// Synchronous scan — must be called from spawn_blocking.
    /// Uses the pre-compiled Arc<Rules> — never creates a new Compiler.
    pub fn scan(&self, event: &EnrichedEvent) -> Vec<Alert> {
        let rules = match &self.compiled_rules {
            Some(r) => Arc::clone(r),
            None    => return vec![],  // no rules loaded — skip
        };

        // Extract scannable data from process events (filename)
        let filename = match &event.raw {
            RawEvent::Process(e) => e.filename().clone(),
            _ => return vec![],
        };

        if filename.is_empty() || filename == "<unknown>" { return vec![]; }

        // Use the pre-compiled rules — O(1) Arc clone, zero compilation overhead
        let matches = match rules.scan_file(&filename, 10) {
            Ok(m)  => m,
            Err(e) => {
                // File might not exist at scan time (process exited) — not an error
                tracing::debug!("YARA scan skipped for {:?}: {}", filename, e);
                return vec![];
            }
        };

        matches.into_iter().map(|m| {
            // Extract MITRE ATT&CK metadata from rule tags if present
            let mitre_tag = m.tags
                .iter()
                .find(|t| t.starts_with("T1") || t.starts_with("attack."))
                .cloned()
                .unwrap_or_default();

            Alert {
                id:          Uuid::new_v4().to_string(),
                timestamp:   Utc::now(),
                source:      event.hostname.clone().unwrap_or_default(),
                rule_name:   format!("YARA:{}", m.identifier),
                rule_type:   RuleType::Yara,
                threat_level: ThreatLevel::High,
                description: format!(
                    "YARA match '{}' in file: {}{}",
                    m.identifier,
                    filename,
                    if mitre_tag.is_empty() { String::new() }
                    else { format!(" [MITRE: {}]", mitre_tag) }
                ),
                pid:              None,
                process_name:     None,
                src_ip:           None,
                dst_ip:           None,
                dst_port:         None,
                ml_score:         None,
                soar_actions_taken: vec![],
                raw_event_type:   "process".to_string(),
            }
        }).collect()
    }

    /// Scan a raw byte buffer (in-memory, e.g. process memory dump).
    /// Uses the same pre-compiled rules.
    pub fn scan_bytes(&self, data: &[u8], label: &str) -> Vec<Alert> {
        let rules = match &self.compiled_rules {
            Some(r) => Arc::clone(r),
            None    => return vec![],
        };

        let matches = match rules.scan_mem(data, 10) {
            Ok(m)  => m,
            Err(e) => {
                tracing::debug!("YARA mem-scan failed for {}: {}", label, e);
                return vec![];
            }
        };

        matches.into_iter().map(|m| Alert {
            id:          Uuid::new_v4().to_string(),
            timestamp:   Utc::now(),
            source:      label.to_string(),
            rule_name:   format!("YARA:MEM:{}", m.identifier),
            rule_type:   RuleType::Yara,
            threat_level: ThreatLevel::Critical,
            description: format!(
                "YARA in-memory match '{}' in: {} — possible fileless malware",
                m.identifier, label
            ),
            pid:              None,
            process_name:     Some(label.to_string()),
            src_ip:           None,
            dst_ip:           None,
            dst_port:         None,
            ml_score:         None,
            soar_actions_taken: vec![],
            raw_event_type:   "memory".to_string(),
        }).collect()
    }

    pub fn rule_count(&self) -> usize { self.rule_count }
    pub fn is_loaded(&self) -> bool { self.compiled_rules.is_some() }
}
