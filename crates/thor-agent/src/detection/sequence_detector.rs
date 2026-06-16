//! Sequence Detector — multi-stage temporal attack chain detection engine.
//!
//! Tracks pending event sequences across configurable time windows.
//! Enables detection of multi-phase attacks like Process Hollowing,
//! credential dumping chains, and lateral movement sequences that
//! span multiple discrete events and cannot be detected by single-event rules.
//!
//! # Architecture
//! Each [`SequenceRule`] defines an ordered list of stages. The engine
//! maintains per-source-entity state machines keyed by `(rule_id, entity_key)`.
//! When all stages fire within the time window, an alert is emitted.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use uuid::Uuid;
use chrono::Utc;
use tracing::{debug, info, warn};

use crate::events::{Alert, RuleType};
use crate::events::enrichment::EnrichedEvent;
use thor_common::ThreatLevel;

// ─── Stage definition ────────────────────────────────────────────────────────

/// A single stage predicate in a sequence rule.
#[derive(Debug, Clone)]
pub struct SequenceStage {
    /// Human-readable stage name, e.g. "step1_priv_escalation"
    pub name: String,
    /// Field to extract as entity key (groups events by host/user/pid)
    pub entity_field: EntityField,
    /// Predicate that must match for this stage to fire
    pub predicate: StagePredicate,
}

/// Which field to use as the correlation key across stages.
#[derive(Debug, Clone, PartialEq)]
pub enum EntityField {
    Hostname,
    Pid,
    UserId,
    SrcIp,
}

/// Predicate evaluated against an [`EnrichedEvent`].
#[derive(Debug, Clone)]
pub enum StagePredicate {
    /// Command line contains any of these strings
    CommandContains(Vec<String>),
    /// Process name equals one of these values
    ProcessNameIn(Vec<String>),
    /// Event type equals this string
    EventTypeEquals(String),
    /// Compound AND of multiple predicates
    And(Vec<StagePredicate>),
    /// Compound OR of multiple predicates
    Or(Vec<StagePredicate>),
}

impl StagePredicate {
    /// Evaluate this predicate against an enriched event.
    pub fn matches(&self, event: &EnrichedEvent) -> bool {
        match self {
            StagePredicate::CommandContains(patterns) => {
                let cmd = event.command_line.as_deref().unwrap_or("");
                patterns.iter().any(|p| cmd.contains(p.as_str()))
            }
            StagePredicate::ProcessNameIn(names) => {
                let pname = event.process_name.as_deref().unwrap_or("");
                names.iter().any(|n| pname == n.as_str())
            }
            StagePredicate::EventTypeEquals(t) => {
                event.event_type.as_deref() == Some(t.as_str())
            }
            StagePredicate::And(preds) => preds.iter().all(|p| p.matches(event)),
            StagePredicate::Or(preds) => preds.iter().any(|p| p.matches(event)),
        }
    }
}

// ─── Sequence Rule ────────────────────────────────────────────────────────────

/// A multi-stage temporal sequence rule.
#[derive(Debug, Clone)]
pub struct SequenceRule {
    /// Unique rule identifier
    pub id: String,
    /// Human-readable title
    pub title: String,
    /// Full description
    pub description: String,
    /// Severity level
    pub threat_level: ThreatLevel,
    /// Ordered list of stages — must fire in order
    pub stages: Vec<SequenceStage>,
    /// Maximum duration between first and last stage firing
    pub window: Duration,
    /// MITRE ATT&CK tags
    pub tags: Vec<String>,
}

// ─── Pending sequence state ───────────────────────────────────────────────────

/// Tracks progress of a sequence for a specific entity.
#[derive(Debug)]
struct PendingSequence {
    /// Index of the next expected stage (0 = waiting for stage[0])
    next_stage: usize,
    /// Timestamp when stage[0] first fired (window starts here)
    window_start: Instant,
    /// Snapshots of events that triggered each completed stage
    stage_events: Vec<String>,
}

impl PendingSequence {
    fn new(first_event_desc: String) -> Self {
        Self {
            next_stage: 1,
            window_start: Instant::now(),
            stage_events: vec![first_event_desc],
        }
    }

    /// Returns true if this pending sequence has exceeded its time window.
    fn is_expired(&self, window: Duration) -> bool {
        self.window_start.elapsed() > window
    }
}

// ─── Engine ───────────────────────────────────────────────────────────────────

/// Composite key: `(rule_id, entity_key)` — one state machine per pair.
type SeqKey = (String, String);

/// The sequence detection engine.
pub struct SequenceDetector {
    rules: Vec<SequenceRule>,
    /// Active pending sequences, keyed by `(rule_id, entity_key)`
    pending: DashMap<SeqKey, PendingSequence>,
    /// Total completed (matched) sequences since startup
    completed_count: Arc<std::sync::atomic::AtomicU64>,
}

impl SequenceDetector {
    /// Create a new engine with the given rules.
    pub fn new(rules: Vec<SequenceRule>) -> Self {
        let completed_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
        Self {
            rules,
            pending: DashMap::new(),
            completed_count,
        }
    }

    /// Create a pre-configured engine with built-in detection rules.
    pub fn with_builtin_rules() -> Self {
        Self::new(builtin_rules())
    }

    /// Process an event through all sequence rules.
    /// Returns any alerts generated by completed sequences.
    pub fn process(&self, event: &EnrichedEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();

        // Periodically evict expired sequences (probabilistic, every ~1000 calls)
        if rand_u8() == 0 {
            self.evict_expired();
        }

        for rule in &self.rules {
            if let Some(alert) = self.process_rule(rule, event) {
                alerts.push(alert);
            }
        }

        alerts
    }

    /// Process a single rule against an event.
    fn process_rule(&self, rule: &SequenceRule, event: &EnrichedEvent) -> Option<Alert> {
        let entity_key = self.extract_entity_key(rule, event);
        let seq_key = (rule.id.clone(), entity_key.clone());

        // Check if this event matches a stage for this rule
        let next_stage_idx = {
            if let Some(pending) = self.pending.get(&seq_key) {
                if pending.is_expired(rule.window) {
                    // Expired — will be evicted, restart from stage 0
                    drop(pending);
                    self.pending.remove(&seq_key);
                    0 // check if this event matches stage[0]
                } else {
                    pending.next_stage
                }
            } else {
                0 // No pending state — check stage[0]
            }
        };

        // Can this event advance the sequence?
        if next_stage_idx >= rule.stages.len() {
            return None;
        }

        let stage = &rule.stages[next_stage_idx];
        if !stage.predicate.matches(event) {
            // Also check if stage[0] matches (restart)
            if next_stage_idx > 0 && rule.stages[0].predicate.matches(event) {
                let desc = self.event_description(event);
                self.pending.insert(seq_key, PendingSequence::new(desc));
            }
            return None;
        }

        let event_desc = self.event_description(event);

        if next_stage_idx == 0 {
            // Stage 0 just fired — create new pending entry
            self.pending.insert(seq_key, PendingSequence::new(event_desc));
            debug!("🔗 Sequence '{}' stage[0] fired for entity '{}'", rule.title, entity_key);
            None
        } else if next_stage_idx == rule.stages.len() - 1 {
            // Final stage fired — sequence complete!
            let stage_events = if let Some(mut pending) = self.pending.get_mut(&seq_key) {
                pending.stage_events.push(event_desc);
                pending.stage_events.clone()
            } else {
                vec![event_desc]
            };
            self.pending.remove(&seq_key);
            self.completed_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            info!(
                "🚨 Sequence MATCH: '{}' completed for entity '{}' ({} stages)",
                rule.title, entity_key, rule.stages.len()
            );

            Some(self.make_alert(rule, event, stage_events))
        } else {
            // Intermediate stage fired — advance the state machine
            if let Some(mut pending) = self.pending.get_mut(&seq_key) {
                pending.next_stage += 1;
                pending.stage_events.push(event_desc);
                debug!(
                    "🔗 Sequence '{}' advanced to stage[{}]/[{}] for entity '{}'",
                    rule.title, pending.next_stage, rule.stages.len(), entity_key
                );
            }
            None
        }
    }

    /// Extract the entity correlation key from an event using the rule's entity field spec.
    fn extract_entity_key(&self, rule: &SequenceRule, event: &EnrichedEvent) -> String {
        // Use the first stage's entity field as the rule-level key
        if let Some(stage) = rule.stages.first() {
            match stage.entity_field {
                EntityField::Hostname => event.hostname.clone().unwrap_or_else(|| "unknown".into()),
                EntityField::Pid => event.pid.map(|p| p.to_string()).unwrap_or_else(|| "0".into()),
                EntityField::UserId => event.user_id.clone().unwrap_or_else(|| "unknown".into()),
                EntityField::SrcIp => event.src_ip_str.clone().unwrap_or_else(|| "0.0.0.0".into()),
            }
        } else {
            "global".into()
        }
    }

    /// Build a human-readable description of the event.
    fn event_description(&self, event: &EnrichedEvent) -> String {
        format!(
            "[{}] cmd={} proc={} host={}",
            event.event_type.as_deref().unwrap_or("?"),
            event.command_line.as_deref().unwrap_or("?"),
            event.process_name.as_deref().unwrap_or("?"),
            event.hostname.as_deref().unwrap_or("?"),
        )
    }

    /// Build an Alert from a completed sequence.
    fn make_alert(&self, rule: &SequenceRule, event: &EnrichedEvent, stage_events: Vec<String>) -> Alert {
        Alert {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            source: event.hostname.clone().unwrap_or_else(|| "unknown".into()),
            rule_name: format!("Sequence:{}", rule.title),
            rule_type: RuleType::Behavioral,
            threat_level: rule.threat_level.clone(),
            description: format!(
                "[SequenceDetector] {} | stages={} | chain: {}",
                rule.description,
                rule.stages.len(),
                stage_events.join(" → ")
            ),
            pid: event.pid,
            process_name: event.process_name.clone(),
            src_ip: event.src_ip_str.clone(),
            dst_ip: event.dst_ip_str.clone(),
            dst_port: None,
            ml_score: None,
            soar_actions_taken: vec![],
            raw_event_type: event.raw.source().to_string(),
        }
    }

    /// Remove all expired pending sequences.
    fn evict_expired(&self) {
        let mut to_remove: Vec<SeqKey> = Vec::new();
        for entry in self.pending.iter() {
            // We can't know the rule window without the rule — use 10 min as max
            if entry.value().window_start.elapsed() > Duration::from_secs(600) {
                to_remove.push(entry.key().clone());
            }
        }
        let evicted = to_remove.len();
        for key in to_remove {
            self.pending.remove(&key);
        }
        if evicted > 0 {
            debug!("🧹 SequenceDetector: evicted {} expired entries", evicted);
        }
    }

    /// Return the number of completed sequences since startup.
    pub fn completed_count(&self) -> u64 {
        self.completed_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Return the number of currently pending (in-progress) sequences.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Return the number of rules loaded.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// Simple LCG-based pseudo-random u8 for probabilistic eviction.
fn rand_u8() -> u8 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEED: AtomicU64 = AtomicU64::new(0xdeadbeef_cafebabe);
    let s = SEED.fetch_add(0x9e3779b97f4a7c15, Ordering::Relaxed);
    (s >> 56) as u8
}

// ─── Built-in rules ───────────────────────────────────────────────────────────

/// Returns the set of built-in sequence detection rules.
fn builtin_rules() -> Vec<SequenceRule> {
    vec![
        SequenceRule {
            id: "thor-seq-001-process-hollowing".into(),
            title: "Process Hollowing Chain".into(),
            description: "Detects the 4-stage Process Hollowing injection technique".into(),
            threat_level: ThreatLevel::Critical,
            window: Duration::from_secs(30),
            tags: vec!["attack.t1055.012".into(), "attack.defense_evasion".into()],
            stages: vec![
                SequenceStage {
                    name: "suspend_target".into(),
                    entity_field: EntityField::Hostname,
                    predicate: StagePredicate::Or(vec![
                        StagePredicate::CommandContains(vec!["CREATE_SUSPENDED".into()]),
                        StagePredicate::CommandContains(vec!["NtCreateProcess".into()]),
                    ]),
                },
                SequenceStage {
                    name: "unmap_memory".into(),
                    entity_field: EntityField::Hostname,
                    predicate: StagePredicate::CommandContains(vec![
                        "NtUnmapViewOfSection".into(),
                        "ZwUnmapViewOfSection".into(),
                    ]),
                },
                SequenceStage {
                    name: "write_payload".into(),
                    entity_field: EntityField::Hostname,
                    predicate: StagePredicate::Or(vec![
                        StagePredicate::CommandContains(vec!["WriteProcessMemory".into()]),
                        StagePredicate::CommandContains(vec!["NtWriteVirtualMemory".into()]),
                    ]),
                },
                SequenceStage {
                    name: "resume_thread".into(),
                    entity_field: EntityField::Hostname,
                    predicate: StagePredicate::CommandContains(vec![
                        "SetThreadContext".into(),
                        "ResumeThread".into(),
                    ]),
                },
            ],
        },
        SequenceRule {
            id: "thor-seq-002-credential-dumping".into(),
            title: "Credential Dumping Attack Chain".into(),
            description: "Detects the 4-stage credential harvesting sequence".into(),
            threat_level: ThreatLevel::Critical,
            window: Duration::from_secs(300),
            tags: vec!["attack.t1003".into(), "attack.credential_access".into()],
            stages: vec![
                SequenceStage {
                    name: "privilege_escalation".into(),
                    entity_field: EntityField::UserId,
                    predicate: StagePredicate::CommandContains(vec![
                        "sudo su".into(),
                        "sudo -i".into(),
                        "pkexec".into(),
                        "SeDebugPrivilege".into(),
                    ]),
                },
                SequenceStage {
                    name: "credential_access".into(),
                    entity_field: EntityField::UserId,
                    predicate: StagePredicate::Or(vec![
                        StagePredicate::CommandContains(vec!["sekurlsa".into(), "lsadump".into()]),
                        StagePredicate::CommandContains(vec!["procdump -ma lsass".into()]),
                        StagePredicate::CommandContains(vec!["/etc/shadow".into()]),
                    ]),
                },
                SequenceStage {
                    name: "dump_creation".into(),
                    entity_field: EntityField::UserId,
                    predicate: StagePredicate::CommandContains(vec![
                        ".dmp".into(),
                        "lsass.dmp".into(),
                        "minidump".into(),
                    ]),
                },
                SequenceStage {
                    name: "exfiltration".into(),
                    entity_field: EntityField::UserId,
                    predicate: StagePredicate::Or(vec![
                        StagePredicate::CommandContains(vec!["curl -F".into()]),
                        StagePredicate::CommandContains(vec!["scp ".into()]),
                        StagePredicate::CommandContains(vec!["rsync ".into()]),
                    ]),
                },
            ],
        },
        SequenceRule {
            id: "thor-seq-003-lateral-movement".into(),
            title: "Lateral Movement Attack Chain".into(),
            description: "Detects discovery → auth → exec → persistence lateral movement sequence".into(),
            threat_level: ThreatLevel::Critical,
            window: Duration::from_secs(600),
            tags: vec!["attack.t1021".into(), "attack.lateral_movement".into()],
            stages: vec![
                SequenceStage {
                    name: "network_discovery".into(),
                    entity_field: EntityField::SrcIp,
                    predicate: StagePredicate::CommandContains(vec![
                        "nmap ".into(),
                        "masscan ".into(),
                        "arp-scan ".into(),
                        "netdiscover ".into(),
                    ]),
                },
                SequenceStage {
                    name: "auth_success".into(),
                    entity_field: EntityField::SrcIp,
                    predicate: StagePredicate::Or(vec![
                        StagePredicate::CommandContains(vec!["ssh ".into()]),
                        StagePredicate::CommandContains(vec!["smbclient".into()]),
                        StagePredicate::CommandContains(vec!["winrm".into()]),
                    ]),
                },
                SequenceStage {
                    name: "remote_execution".into(),
                    entity_field: EntityField::SrcIp,
                    predicate: StagePredicate::CommandContains(vec![
                        "psexec".into(),
                        "wmiexec".into(),
                        "Invoke-Command".into(),
                        "atexec".into(),
                    ]),
                },
                SequenceStage {
                    name: "persistence".into(),
                    entity_field: EntityField::SrcIp,
                    predicate: StagePredicate::Or(vec![
                        StagePredicate::CommandContains(vec!["crontab -e".into()]),
                        StagePredicate::CommandContains(vec!["systemctl enable".into()]),
                        StagePredicate::CommandContains(vec!["schtasks /create".into()]),
                    ]),
                },
            ],
        },
    ]
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::enrichment::EnrichedEvent;

    fn make_event(cmd: &str, hostname: &str) -> EnrichedEvent {
        EnrichedEvent {
            command_line: Some(cmd.to_string()),
            hostname: Some(hostname.to_string()),
            ..EnrichedEvent::default()
        }
    }

    #[test]
    fn test_stage_predicate_command_contains() {
        let pred = StagePredicate::CommandContains(vec!["sekurlsa".to_string()]);
        let ev = make_event("mimikatz sekurlsa::logonpasswords", "host1");
        assert!(pred.matches(&ev));
        let ev2 = make_event("ls -la", "host1");
        assert!(!pred.matches(&ev2));
    }

    #[test]
    fn test_stage_predicate_or() {
        let pred = StagePredicate::Or(vec![
            StagePredicate::CommandContains(vec!["sekurlsa".to_string()]),
            StagePredicate::CommandContains(vec!["lsadump".to_string()]),
        ]);
        let ev1 = make_event("sekurlsa::wdigest", "host1");
        let ev2 = make_event("lsadump::sam", "host1");
        let ev3 = make_event("ls -la", "host1");
        assert!(pred.matches(&ev1));
        assert!(pred.matches(&ev2));
        assert!(!pred.matches(&ev3));
    }

    #[test]
    fn test_sequence_no_match_wrong_order() {
        let detector = SequenceDetector::with_builtin_rules();
        // Fire stages out of order — should not trigger
        let ev_cred = make_event("sekurlsa::logonpasswords", "host-a");
        let ev_priv = make_event("sudo su root", "host-a");
        let alerts1 = detector.process(&ev_cred);
        let alerts2 = detector.process(&ev_priv);
        assert!(alerts1.is_empty());
        assert!(alerts2.is_empty());
    }

    #[test]
    fn test_sequence_incomplete_no_alert() {
        let detector = SequenceDetector::with_builtin_rules();
        // Only fire stage[0] and stage[1] of hollowing — not complete
        let ev0 = make_event("NtCreateProcess CREATE_SUSPENDED", "host-b");
        let ev1 = make_event("NtUnmapViewOfSection target=C:\\Windows\\System32\\svchost.exe", "host-b");
        let a0 = detector.process(&ev0);
        let a1 = detector.process(&ev1);
        assert!(a0.is_empty());
        assert!(a1.is_empty());
        assert!(detector.pending_count() > 0);
    }

    #[test]
    fn test_rule_count() {
        let detector = SequenceDetector::with_builtin_rules();
        assert_eq!(detector.rule_count(), 3, "Expected 3 built-in sequence rules");
    }

    #[test]
    fn test_process_hollowing_full_chain() {
        let detector = SequenceDetector::with_builtin_rules();
        let host = "victim-host";

        // Stage 0: suspend
        let alerts = detector.process(&make_event("NtCreateProcess CREATE_SUSPENDED svchost.exe", host));
        assert!(alerts.is_empty(), "Stage 0 should not alert");

        // Stage 1: unmap
        let alerts = detector.process(&make_event("NtUnmapViewOfSection called", host));
        assert!(alerts.is_empty(), "Stage 1 should not alert");

        // Stage 2: write payload
        let alerts = detector.process(&make_event("WriteProcessMemory 8192 bytes", host));
        assert!(alerts.is_empty(), "Stage 2 should not alert");

        // Stage 3: resume — COMPLETE
        let alerts = detector.process(&make_event("SetThreadContext then ResumeThread", host));
        assert_eq!(alerts.len(), 1, "Final stage should produce one alert");
        assert!(alerts[0].rule_name.contains("Process Hollowing"));
        assert_eq!(detector.completed_count(), 1);
    }
}
