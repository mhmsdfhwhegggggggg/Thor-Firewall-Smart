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
//!
//! # Cleanup
//! Call [`SequenceDetector::cleanup_expired`] periodically (e.g. every 30 s)
//! to reclaim memory from sequences whose time windows have elapsed.
//! The engine also performs probabilistic inline eviction every ~256 events.

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
    /// The rule-specific window duration (stored for accurate per-rule cleanup)
    rule_window: Duration,
    /// Snapshots of events that triggered each completed stage
    stage_events: Vec<String>,
}

impl PendingSequence {
    fn new(first_event_desc: String, rule_window: Duration) -> Self {
        Self {
            next_stage: 1,
            window_start: Instant::now(),
            rule_window,
            stage_events: vec![first_event_desc],
        }
    }

    /// Returns true if this pending sequence has exceeded its rule time window.
    fn is_expired(&self) -> bool {
        self.window_start.elapsed() > self.rule_window
    }
}

// ─── Engine ───────────────────────────────────────────────────────────────────

/// Composite key: `(rule_id, entity_key)` — one state machine per pair.
type SeqKey = (String, String);

/// The sequence detection engine.
pub struct SequenceDetector {
    rules: Vec<SequenceRule>,
    /// Active pending sequences, keyed by `(rule_id, entity_key)`.
    /// Each entry carries its own `rule_window` for accurate expiry checks.
    pending: DashMap<SeqKey, PendingSequence>,
    /// Total completed (matched) sequences since startup
    completed_count: Arc<std::sync::atomic::AtomicU64>,
    /// Total entries evicted by cleanup_expired() since startup
    evicted_count: Arc<std::sync::atomic::AtomicU64>,
}

impl SequenceDetector {
    /// Create a new engine with the given rules.
    pub fn new(rules: Vec<SequenceRule>) -> Self {
        let completed_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let evicted_count   = Arc::new(std::sync::atomic::AtomicU64::new(0));
        Self {
            rules,
            pending: DashMap::new(),
            completed_count,
            evicted_count,
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

        // Probabilistic inline eviction — roughly every 256 calls.
        // Full cleanup should be scheduled externally via cleanup_expired().
        if rand_u8() == 0 {
            self.inline_evict_expired();
        }

        for rule in &self.rules {
            if let Some(alert) = self.process_rule(rule, event) {
                alerts.push(alert);
            }
        }

        alerts
    }

    /// Scan all pending sequences and remove those whose rule-specific time
    /// window has elapsed.
    ///
    /// This should be called periodically from a background task (e.g. every
    /// 30 seconds) to bound memory growth.  Each pending sequence stores its
    /// own `rule_window`, so the check is always accurate — no more hardcoded
    /// 10-minute ceiling.
    ///
    /// Returns the number of entries evicted.
    pub fn cleanup_expired(&self) -> usize {
        let to_remove: Vec<SeqKey> = self
            .pending
            .iter()
            .filter(|entry| entry.value().is_expired())
            .map(|entry| entry.key().clone())
            .collect();

        let evicted = to_remove.len();
        for key in to_remove {
            self.pending.remove(&key);
        }

        if evicted > 0 {
            self.evicted_count
                .fetch_add(evicted as u64, std::sync::atomic::Ordering::Relaxed);
            warn!(
                "🧹 SequenceDetector: cleanup_expired evicted {} expired entries (total={})",
                evicted,
                self.evicted_count.load(std::sync::atomic::Ordering::Relaxed)
            );
        }

        evicted
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Process a single rule against an event.
    fn process_rule(&self, rule: &SequenceRule, event: &EnrichedEvent) -> Option<Alert> {
        let entity_key = self.extract_entity_key(rule, event);
        let seq_key = (rule.id.clone(), entity_key.clone());

        // Check if this event matches a stage for this rule
        let next_stage_idx = {
            if let Some(pending) = self.pending.get(&seq_key) {
                if pending.is_expired() {
                    // Expired — evict and restart from stage 0
                    drop(pending);
                    self.pending.remove(&seq_key);
                    0
                } else {
                    pending.next_stage
                }
            } else {
                0
            }
        };

        if next_stage_idx >= rule.stages.len() {
            return None;
        }

        let stage = &rule.stages[next_stage_idx];
        if !stage.predicate.matches(event) {
            // Also check if stage[0] matches (restart)
            if next_stage_idx > 0 && rule.stages[0].predicate.matches(event) {
                let desc = self.event_description(event);
                self.pending
                    .insert(seq_key, PendingSequence::new(desc, rule.window));
            }
            return None;
        }

        let event_desc = self.event_description(event);

        if next_stage_idx == 0 {
            // Stage 0 just fired — create new pending entry with this rule's window
            self.pending
                .insert(seq_key, PendingSequence::new(event_desc, rule.window));
            debug!(
                "🔗 Sequence '{}' stage[0] fired for entity '{}'",
                rule.title, entity_key
            );
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
            self.completed_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            info!(
                "🚨 Sequence MATCH: '{}' completed for entity '{}' ({} stages)",
                rule.title,
                entity_key,
                rule.stages.len()
            );

            Some(self.make_alert(rule, event, stage_events))
        } else {
            // Intermediate stage fired — advance the state machine
            if let Some(mut pending) = self.pending.get_mut(&seq_key) {
                pending.next_stage += 1;
                pending.stage_events.push(event_desc);
                debug!(
                    "🔗 Sequence '{}' advanced to stage[{}]/[{}] for entity '{}'",
                    rule.title,
                    pending.next_stage,
                    rule.stages.len(),
                    entity_key
                );
            }
            None
        }
    }

    /// Inline probabilistic eviction (fast path — no per-rule window accuracy).
    /// Entries must be > 10 min old to be evicted via this path.
    fn inline_evict_expired(&self) {
        const CEILING: Duration = Duration::from_secs(600);
        let to_remove: Vec<SeqKey> = self
            .pending
            .iter()
            .filter(|e| e.value().window_start.elapsed() > CEILING)
            .map(|e| e.key().clone())
            .collect();

        let evicted = to_remove.len();
        for key in to_remove {
            self.pending.remove(&key);
        }
        if evicted > 0 {
            debug!("🧹 SequenceDetector: inline evicted {} stale entries", evicted);
        }
    }

    /// Extract the entity correlation key from an event using the rule's entity field spec.
    fn extract_entity_key(&self, rule: &SequenceRule, event: &EnrichedEvent) -> String {
        if let Some(stage) = rule.stages.first() {
            match stage.entity_field {
                EntityField::Hostname => {
                    event.hostname.clone().unwrap_or_else(|| "unknown".into())
                }
                EntityField::Pid => {
                    event.pid.map(|p| p.to_string()).unwrap_or_else(|| "0".into())
                }
                EntityField::UserId => {
                    event.user_id.clone().unwrap_or_else(|| "unknown".into())
                }
                EntityField::SrcIp => {
                    event.src_ip_str.clone().unwrap_or_else(|| "0.0.0.0".into())
                }
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
    fn make_alert(
        &self,
        rule: &SequenceRule,
        event: &EnrichedEvent,
        stage_events: Vec<String>,
    ) -> Alert {
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

    // ── Metrics ───────────────────────────────────────────────────────────────

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

    /// Return total entries evicted by `cleanup_expired` since startup.
    pub fn evicted_count(&self) -> u64 {
        self.evicted_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Simple LCG-based pseudo-random u8 for probabilistic eviction (no deps).
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
                        StagePredicate::CommandContains(vec![
                            "sekurlsa".into(),
                            "lsadump".into(),
                        ]),
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
            description: "Detects discovery → auth → exec → persistence lateral movement sequence"
                .into(),
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
        let ev0 = make_event("NtCreateProcess CREATE_SUSPENDED", "host-b");
        let ev1 = make_event(
            "NtUnmapViewOfSection target=C:\\Windows\\System32\\svchost.exe",
            "host-b",
        );
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
    fn test_cleanup_expired_removes_stale_entries() {
        // Create a rule with a very short window (1 nanosecond)
        let rule = SequenceRule {
            id: "test-cleanup-rule".into(),
            title: "Cleanup Test".into(),
            description: "Rule for testing cleanup_expired".into(),
            threat_level: ThreatLevel::Low,
            window: Duration::from_nanos(1), // expires immediately
            tags: vec![],
            stages: vec![
                SequenceStage {
                    name: "stage0".into(),
                    entity_field: EntityField::Hostname,
                    predicate: StagePredicate::CommandContains(vec!["trigger_stage0".into()]),
                },
                SequenceStage {
                    name: "stage1".into(),
                    entity_field: EntityField::Hostname,
                    predicate: StagePredicate::CommandContains(vec!["trigger_stage1".into()]),
                },
            ],
        };

        let detector = SequenceDetector::new(vec![rule]);

        // Fire stage[0] to create a pending entry
        let ev = make_event("trigger_stage0", "cleanup-host");
        let _ = detector.process(&ev);
        assert_eq!(detector.pending_count(), 1, "Should have 1 pending entry");

        // Wait briefly so the 1ns window is definitely expired
        std::thread::sleep(Duration::from_millis(5));

        let evicted = detector.cleanup_expired();
        assert_eq!(evicted, 1, "cleanup_expired should have removed 1 expired entry");
        assert_eq!(detector.pending_count(), 0, "No pending entries should remain");
        assert_eq!(detector.evicted_count(), 1, "Eviction counter should be 1");
    }

    #[test]
    fn test_process_hollowing_full_chain() {
        let detector = SequenceDetector::with_builtin_rules();
        let host = "victim-host";

        let e0 = make_event("NtCreateProcess CREATE_SUSPENDED", host);
        let e1 = make_event("NtUnmapViewOfSection base=0x400000", host);
        let e2 = make_event("WriteProcessMemory pid=1234", host);
        let e3 = make_event("ResumeThread tid=5678", host);

        let a0 = detector.process(&e0);
        let a1 = detector.process(&e1);
        let a2 = detector.process(&e2);
        let a3 = detector.process(&e3);

        assert!(a0.is_empty());
        assert!(a1.is_empty());
        assert!(a2.is_empty());
        assert_eq!(a3.len(), 1, "Final stage should produce 1 alert");
        assert!(a3[0].rule_name.contains("Process Hollowing"));
    }
}
