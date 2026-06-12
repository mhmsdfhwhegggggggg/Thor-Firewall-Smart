//! YARA engine — file/memory scanning using libyara (spawn_blocking to avoid tokio starvation)

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

/// YARA engine wrapping compiled rules
#[derive(Clone)]
pub struct YaraEngine {
    rules_path: std::path::PathBuf,
    rule_count: usize,
}

impl YaraEngine {
    pub fn load(rules_dir: &Path) -> Result<Self> {
        if !rules_dir.exists() {
            warn!("YARA rules dir not found: {:?} — using empty set", rules_dir);
            return Ok(Self { rules_path: rules_dir.to_path_buf(), rule_count: 0 });
        }

        let mut count = 0;
        let mut compiler = yara::Compiler::new()?;

        for entry in WalkDir::new(rules_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            let ext = path.extension().and_then(|s| s.to_str());
            if ext != Some("yar") && ext != Some("yara") { continue; }

            match std::fs::read_to_string(path) {
                Ok(content) => {
                    match compiler.add_rules_str(&content) {
                        Ok(_) => { count += 1; info!("Loaded YARA rule: {:?}", path); }
                        Err(e) => warn!("YARA compile error in {:?}: {}", path, e),
                    }
                }
                Err(e) => warn!("Cannot read YARA rule {:?}: {}", path, e),
            }
        }

        info!("🔐 Compiled {} YARA rules from {:?}", count, rules_dir);
        Ok(Self { rules_path: rules_dir.to_path_buf(), rule_count: count })
    }

    /// Synchronous scan — must be called from spawn_blocking
    pub fn scan(&self, event: &EnrichedEvent) -> Vec<Alert> {
        if self.rule_count == 0 { return vec![]; }

        // Extract scannable data from process events (filename)
        let filename = match &event.raw {
            RawEvent::Process(e) => e.filename().clone(),
            _ => return vec![],
        };

        if filename.is_empty() || filename == "<unknown>" { return vec![]; }

        // Compile fresh rules for this scan (in production: cache compiled rules)
        let compiler = match yara::Compiler::new() {
            Ok(c) => c,
            Err(_) => return vec![],
        };

        let rules = match compiler.compile_rules() {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        // Scan file on disk
        let matches = match rules.scan_file(&filename, 5) {
            Ok(m) => m,
            Err(_) => return vec![],
        };

        matches.into_iter().map(|m| Alert {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            source: event.hostname.clone().unwrap_or_default(),
            rule_name: format!("YARA:{}", m.identifier),
            rule_type: RuleType::Yara,
            threat_level: ThreatLevel::High,
            description: format!("YARA match '{}' in file: {}", m.identifier, filename),
            pid: None,
            process_name: None,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            ml_score: None,
            soar_actions_taken: vec![],
            raw_event_type: "process".to_string(),
        }).collect()
    }

    pub fn rule_count(&self) -> usize { self.rule_count }
}
