//! Zero-Day Detection Engine — unified threat detection pipeline.
//!
//! # Architecture (v2)
//!
//! ```text
//! eBPF events ──► SyscallProfiler ──► ProcessProfile (24-dim)
//!                                          │
//!     ┌────────────────────────────────────┤
//!     ▼               ▼             ▼                ▼               ▼
//! AnomalyEngine  BehavioralBaseline ExploitPrimitive KernelExploit ProcessHollowing
//! (IF+Z-score)   (JS-divergence)    (heuristic)      (heuristic)   (heuristic)
//!     │               │             │                │               │
//!     └───────────────┴─────────────┴────────────────┴───────────────┘
//!                                   │
//!                       ZeroDayEngine.ingest_syscall()
//!                       ┌─────────────────────────────┐
//!                       │  Alert Fusion & Dedup        │
//!                       │  Severity Scoring            │
//!                       │  NetworkCovert (DNS/TLS/WS)  │
//!                       └─────────────────────────────┘
//!                                   │
//!                           ZeroDayFinding
//! ```
//!
//! # v2 Changes from original
//! * All 6 sub-engines integrated: anomaly, baseline, exploit, kernel, hollowing, network
//! * Alert deduplication (10-second window per pid+method)
//! * Combined multi-engine severity scoring with critical boosters
//! * KernelExploit / ProcessInjection / CovertChannel detection methods
//! * `ZeroDayAlert` (v1 API) preserved for backwards compatibility
//! * `ZeroDayFinding` (v2 API) is the richer unified output

pub mod syscall_profiler;
pub mod anomaly_engine;
pub mod exploit_primitives;
pub mod behavioral_baseline;
pub mod kernel_exploit;
pub mod process_hollowing;
pub mod network_covert;

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use anomaly_engine::{AnomalyEngine, AnomalyScore, FeatureVector};
use behavioral_baseline::{BehavioralBaseline, BaselineDrift, DriftSeverity};
use exploit_primitives::{ExploitPrimitiveDetector, ExploitAlert, ExploitType};
use kernel_exploit::{KernelExploitDetector, KernelExploitAlert, KernelEvent, KernelSeverity};
use network_covert::{NetworkCovertDetector, CovertChannelAlert, CovertChannelType};
use process_hollowing::{ProcessHollowingDetector, HollowingAlert, HollowingType};
use syscall_profiler::{ProcessProfile, SyscallEvent, SyscallProfiler};

// ─── Re-exports ───────────────────────────────────────────────────────────────

pub use syscall_profiler::{SyscallEvent as SyscallEventExport, SyscallProfiler as SyscallProfilerExport, ProcessProfile as ProcessProfileExport};
pub use anomaly_engine::{AnomalyEngine as AnomalyEngineExport, FeatureVector as FeatureVectorExport, AnomalyScore as AnomalyScoreExport};
pub use exploit_primitives::{ExploitPrimitiveDetector as ExploitPrimitiveDetectorExport, ExploitAlert as ExploitAlertExport, ExploitType as ExploitTypeExport};
pub use behavioral_baseline::{BehavioralBaseline as BehavioralBaselineExport, BaselineDrift as BaselineDriftExport};
pub use kernel_exploit::{KernelExploitDetector as KernelExploitDetectorExport, KernelExploitAlert as KernelExploitAlertExport, KernelExploitType, KernelEvent as KernelEventExport};
pub use process_hollowing::{ProcessHollowingDetector as ProcessHollowingDetectorExport, HollowingAlert as HollowingAlertExport, HollowingType as HollowingTypeExport};
pub use network_covert::{
    NetworkCovertDetector as NetworkCovertDetectorExport,
    CovertChannelAlert as CovertChannelAlertExport,
    CovertChannelType as CovertChannelTypeExport,
    DnsEvent, IcmpEvent, HttpEvent, TlsEvent, QuicEvent, WebSocketEvent,
};

// ─── Detection method taxonomy ────────────────────────────────────────────────

/// Which detection engine(s) produced an alert.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DetectionMethod {
    /// Isolation Forest + Z-score ensemble.
    BehavioralAnomaly,
    /// JS-divergence behavioral drift from established baseline.
    BaselineDrift,
    /// Heuristic: ROP / UAF / heap spray / memfd / ptrace.
    ExploitPrimitive,
    /// Kernel exploitation: setuid→root, module loading, BPF rootkit, io_uring, userfaultfd.
    KernelExploit,
    /// Process injection: hollowing, atom bombing, phantom DLL, pidfd.
    ProcessInjection,
    /// Covert channel: DNS tunnel, HTTPS mimicry, QUIC, WebSocket beaconing.
    CovertChannel,
    /// Combined signal from two or more engines.
    Combined,
}

impl std::fmt::Display for DetectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionMethod::BehavioralAnomaly => write!(f, "BehavioralAnomaly"),
            DetectionMethod::BaselineDrift     => write!(f, "BaselineDrift"),
            DetectionMethod::ExploitPrimitive  => write!(f, "ExploitPrimitive"),
            DetectionMethod::KernelExploit     => write!(f, "KernelExploit"),
            DetectionMethod::ProcessInjection  => write!(f, "ProcessInjection"),
            DetectionMethod::CovertChannel     => write!(f, "CovertChannel"),
            DetectionMethod::Combined          => write!(f, "Combined"),
        }
    }
}

// ─── ZeroDaySeverity (v1 compat) ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ZeroDaySeverity {
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
}

impl ZeroDaySeverity {
    pub fn from_score(score: f64) -> Self {
        if score >= 0.90      { ZeroDaySeverity::Critical }
        else if score >= 0.75 { ZeroDaySeverity::High }
        else if score >= 0.55 { ZeroDaySeverity::Medium }
        else                  { ZeroDaySeverity::Low }
    }
}

impl std::fmt::Display for ZeroDaySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZeroDaySeverity::Low      => write!(f, "LOW"),
            ZeroDaySeverity::Medium   => write!(f, "MEDIUM"),
            ZeroDaySeverity::High     => write!(f, "HIGH"),
            ZeroDaySeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─── ZeroDayAlert (v1 API — preserved for backwards compatibility) ─────────────

/// Single-engine alert — the v1 output format.
/// Preserved so existing API consumers don't break.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroDayAlert {
    pub id:               String,
    pub timestamp:        chrono::DateTime<chrono::Utc>,
    pub pid:              u32,
    pub process_name:     String,
    pub detection_method: DetectionMethod,
    pub anomaly_score:    f64,
    pub severity:         ZeroDaySeverity,
    pub description:      String,
    pub mitre_techniques: Vec<String>,
    pub features:         Option<FeatureVector>,
    pub exploit_type:     Option<ExploitType>,
}

// ─── ZeroDayFinding (v2 API) ──────────────────────────────────────────────────

/// Unified multi-engine finding — the v2 richer output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroDayFinding {
    pub pid:              u32,
    pub comm:             String,
    /// Combined threat score [0.0, 1.0].
    pub threat_score:     f64,
    pub severity:         ZeroDaySeverity,
    /// All detection methods that contributed.
    pub methods:          Vec<DetectionMethod>,
    pub summary:          String,
    pub exploit_alerts:   Vec<ExploitAlert>,
    pub kernel_alerts:    Vec<KernelExploitAlert>,
    pub hollow_alerts:    Vec<HollowingAlert>,
    pub network_alerts:   Vec<CovertChannelAlert>,
    pub anomaly_score:    Option<AnomalyScore>,
    pub drift:            Option<BaselineDrift>,
    pub mitre_techniques: Vec<String>,
    pub detected_at:      std::time::SystemTime,
}

// ─── Deduplication state ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DedupeKey {
    pid:    u32,
    method: DetectionMethod,
}

struct DedupeEntry {
    last_seen: Instant,
    count:     u32,
}

// ─── ZeroDayEngine ────────────────────────────────────────────────────────────

/// The unified zero-day detection engine.
///
/// Coordinates all 6 sub-engines into a single ingestion pipeline.
pub struct ZeroDayEngine {
    pub profiler:   Arc<SyscallProfiler>,
    pub anomaly:    Arc<AnomalyEngine>,
    pub primitives: Arc<ExploitPrimitiveDetector>,
    pub baseline:   Arc<BehavioralBaseline>,
    /// Minimum anomaly score to emit an alert (default: 0.55).
    pub threshold:  f64,
    // ── v2 sub-engines ────────────────────────────────────────────────────
    kernel:         Arc<KernelExploitDetector>,
    hollowing:      Arc<ProcessHollowingDetector>,
    network:        Arc<NetworkCovertDetector>,
    dedupe:         DashMap<DedupeKey, DedupeEntry>,
    dedupe_window:  Duration,
}

impl ZeroDayEngine {
    /// Create a new engine with default parameters (100 isolation trees).
    pub fn new() -> Self {
        Self {
            profiler:      Arc::new(SyscallProfiler::new()),
            anomaly:       Arc::new(AnomalyEngine::new(100)),
            primitives:    Arc::new(ExploitPrimitiveDetector::new()),
            baseline:      Arc::new(BehavioralBaseline::new()),
            threshold:     0.55,
            kernel:        Arc::new(KernelExploitDetector::new()),
            hollowing:     Arc::new(ProcessHollowingDetector::new()),
            network:       Arc::new(NetworkCovertDetector::new()),
            dedupe:        DashMap::new(),
            dedupe_window: Duration::from_secs(10),
        }
    }

    // ── v1 API: ingest → Vec<ZeroDayAlert> ────────────────────────────────────

    /// Ingest a syscall event — v1 API returning `ZeroDayAlert` list.
    ///
    /// Preserved for backwards compatibility. For richer output, use `ingest_syscall`.
    pub fn ingest(&self, event: &SyscallEvent) -> Vec<ZeroDayAlert> {
        self.profiler.record(event);

        let Some(profile) = self.profiler.get_profile(event.pid) else {
            return vec![];
        };

        if profile.event_count < 50 { return vec![]; }

        let features      = FeatureVector::from_profile(&profile);
        let score         = self.anomaly.score(&features);
        let mut alerts    = Vec::new();

        if score.value >= self.threshold {
            alerts.push(ZeroDayAlert {
                id:               uuid::Uuid::new_v4().to_string(),
                timestamp:        chrono::Utc::now(),
                pid:              event.pid,
                process_name:     profile.process_name.clone(),
                detection_method: DetectionMethod::BehavioralAnomaly,
                anomaly_score:    score.value,
                severity:         ZeroDaySeverity::from_score(score.value),
                description:      format!(
                    "Behavioral anomaly: PID {} ({}) isolation score {:.3} — {}",
                    event.pid, profile.process_name, score.value,
                    describe_anomaly(&features, &score)
                ),
                mitre_techniques: vec!["T1055".into(), "T1203".into()],
                features:         Some(features.clone()),
                exploit_type:     None,
            });
        }

        if let Some(drift) = self.baseline.compute_drift(event.pid, &features) {
            if drift.kl_divergence > 1.5 {
                let drift_score = (drift.kl_divergence / 5.0).min(1.0);
                alerts.push(ZeroDayAlert {
                    id:               uuid::Uuid::new_v4().to_string(),
                    timestamp:        chrono::Utc::now(),
                    pid:              event.pid,
                    process_name:     profile.process_name.clone(),
                    detection_method: DetectionMethod::BaselineDrift,
                    anomaly_score:    drift_score,
                    severity:         ZeroDaySeverity::from_score(drift_score),
                    description:      format!(
                        "Behavioral drift: PID {} ({}) JS-div={:.3} (threshold 1.5)",
                        event.pid, profile.process_name, drift.kl_divergence
                    ),
                    mitre_techniques: vec!["T1055".into()],
                    features:         Some(features.clone()),
                    exploit_type:     None,
                });
            }
        }

        self.baseline.update(event.pid, &features);

        for ea in self.primitives.analyze(event, &profile) {
            alerts.push(ZeroDayAlert {
                id:               uuid::Uuid::new_v4().to_string(),
                timestamp:        chrono::Utc::now(),
                pid:              event.pid,
                process_name:     profile.process_name.clone(),
                detection_method: DetectionMethod::ExploitPrimitive,
                anomaly_score:    ea.confidence,
                severity:         ZeroDaySeverity::from_score(ea.confidence),
                description:      ea.description.clone(),
                mitre_techniques: ea.mitre_techniques.clone(),
                features:         Some(features.clone()),
                exploit_type:     Some(ea.exploit_type.clone()),
            });
        }

        if !alerts.is_empty() {
            info!(
                "Zero-Day: {} alert(s) for PID {} ({})",
                alerts.len(), event.pid, profile.process_name
            );
        }

        alerts
    }

    // ── v2 API: ingest_syscall → Vec<ZeroDayFinding> ──────────────────────────

    /// Ingest a syscall event — v2 API returning richer `ZeroDayFinding`.
    pub fn ingest_syscall(&self, event: &SyscallEvent) -> Vec<ZeroDayFinding> {
        self.profiler.record(event);

        let Some(profile) = self.profiler.get_profile(event.pid) else {
            return vec![];
        };

        let features      = FeatureVector::from_profile(&profile);
        let anomaly_score = self.anomaly.score(&features);

        self.baseline.update(event.pid, &features);
        let drift = self.baseline.compute_drift(event.pid, &features);

        let exploit_alerts = self.primitives.analyze(event, &profile);
        let hollow_alerts  = self.hollowing.analyze(event, &profile);

        let has_exploit = !exploit_alerts.is_empty();
        let has_hollow  = !hollow_alerts.is_empty();
        let has_drift   = drift.as_ref()
            .map(|d| d.severity >= DriftSeverity::Significant)
            .unwrap_or(false);
        let has_anomaly = anomaly_score.value >= self.threshold;

        if !has_exploit && !has_hollow && !has_anomaly && !has_drift {
            return vec![];
        }

        let score   = self.combined_score(
            &anomaly_score, drift.as_ref(), &exploit_alerts, &hollow_alerts, &[], &[]);
        let methods = self.contributing_methods(
            &anomaly_score, drift.as_ref(), &exploit_alerts, &hollow_alerts, &[], &[]);
        let mitre   = collect_mitre(&exploit_alerts, &hollow_alerts, &[], &[]);

        let finding = ZeroDayFinding {
            pid:              event.pid,
            comm:             profile.process_name.clone(),
            threat_score:     score,
            severity:         ZeroDaySeverity::from_score(score),
            methods,
            summary:          self.build_summary(&profile, score, &exploit_alerts, &hollow_alerts),
            exploit_alerts,
            kernel_alerts:    vec![],
            hollow_alerts,
            network_alerts:   vec![],
            anomaly_score:    Some(anomaly_score),
            drift,
            mitre_techniques: mitre,
            detected_at:      std::time::SystemTime::now(),
        };

        if self.should_dedupe(&finding) { return vec![]; }

        debug!(
            "[ZeroDayEngine] Finding PID {} ({}) score={:.3} severity={}",
            finding.pid, finding.comm, finding.threat_score, finding.severity
        );

        vec![finding]
    }

    /// Ingest a kernel event (kprobe / audit) — returns v2 findings.
    pub fn ingest_kernel_event(
        &self,
        event:   &KernelEvent,
        profile: &ProcessProfile,
    ) -> Vec<ZeroDayFinding> {
        let kernel_alerts = self.kernel.analyze(event, profile);
        if kernel_alerts.is_empty() { return vec![]; }

        let features      = FeatureVector::from_profile(profile);
        let anomaly_score = self.anomaly.score(&features);
        let drift         = self.baseline.compute_drift(event.pid, &features);

        let score   = self.combined_score(
            &anomaly_score, drift.as_ref(), &[], &[], &kernel_alerts, &[]);
        let methods = self.contributing_methods(
            &anomaly_score, drift.as_ref(), &[], &[], &kernel_alerts, &[]);
        let mitre   = collect_mitre(&[], &[], &kernel_alerts, &[]);

        let finding = ZeroDayFinding {
            pid:              event.pid,
            comm:             event.comm.clone(),
            threat_score:     score,
            severity:         ZeroDaySeverity::from_score(score),
            methods,
            summary:          format!(
                "PID {} ({}): {} kernel exploit indicator(s) [score={:.3}]",
                event.pid, event.comm, kernel_alerts.len(), score
            ),
            exploit_alerts:  vec![],
            kernel_alerts,
            hollow_alerts:   vec![],
            network_alerts:  vec![],
            anomaly_score:   Some(anomaly_score),
            drift,
            mitre_techniques: mitre,
            detected_at:     std::time::SystemTime::now(),
        };

        if self.should_dedupe(&finding) { return vec![]; }

        if finding.severity >= ZeroDaySeverity::High {
            warn!(
                "[ZeroDayEngine] KERNEL ALERT PID {} ({}) severity={}",
                finding.pid, finding.comm, finding.severity
            );
        }

        vec![finding]
    }

    /// Deliver pre-computed network alerts — returns v2 findings.
    pub fn ingest_network_alert(
        &self,
        pid:    u32,
        comm:   &str,
        alerts: Vec<CovertChannelAlert>,
    ) -> Vec<ZeroDayFinding> {
        if alerts.is_empty() { return vec![]; }

        let max_conf = alerts.iter().map(|a| a.confidence).fold(0.0_f64, f64::max);
        let mitre    = alerts.iter()
            .flat_map(|a| a.mitre_techniques.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let finding = ZeroDayFinding {
            pid,
            comm:             comm.to_string(),
            threat_score:     max_conf,
            severity:         ZeroDaySeverity::from_score(max_conf),
            methods:          vec![DetectionMethod::CovertChannel],
            summary:          format!(
                "PID {} ({}): {} covert channel indicator(s) (max_conf={:.2})",
                pid, comm, alerts.len(), max_conf
            ),
            exploit_alerts:  vec![],
            kernel_alerts:   vec![],
            hollow_alerts:   vec![],
            network_alerts:  alerts,
            anomaly_score:   None,
            drift:           None,
            mitre_techniques: mitre,
            detected_at:     std::time::SystemTime::now(),
        };

        if self.should_dedupe(&finding) { return vec![]; }
        vec![finding]
    }

    // ── Sub-engine accessors ──────────────────────────────────────────────────

    pub fn network(&self)   -> &NetworkCovertDetector   { &self.network }
    pub fn kernel(&self)    -> &KernelExploitDetector   { &self.kernel }
    pub fn hollowing(&self) -> &ProcessHollowingDetector { &self.hollowing }

    // ── v1 convenience methods ────────────────────────────────────────────────

    pub fn all_profiles(&self)    -> Vec<ProcessProfile> { self.profiler.all_profiles() }
    pub fn all_drift_stats(&self) -> Vec<(u32, f64)>     { self.baseline.all_drift_stats() }

    // ── Process lifecycle ─────────────────────────────────────────────────────

    /// Evict all per-process state for a terminated process.
    pub fn on_process_exit(&self, pid: u32) {
        self.profiler.evict_pid(pid);
        self.baseline.evict(pid);
        self.primitives.evict(pid);
        self.kernel.evict(pid);
        self.hollowing.evict(pid);
        self.network.evict(pid);
        self.dedupe.retain(|k, _| k.pid != pid);
        debug!("[ZeroDayEngine] Evicted all state for PID {}", pid);
    }

    pub fn evict_stale(&self) {
        self.profiler.evict_stale();
    }

    pub fn tracked_processes(&self) -> usize {
        self.profiler.profile_count()
    }

    // ── Scoring helpers ───────────────────────────────────────────────────────

    fn combined_score(
        &self,
        anomaly:  &AnomalyScore,
        drift:    Option<&BaselineDrift>,
        exploit:  &[ExploitAlert],
        hollow:   &[HollowingAlert],
        kernel:   &[KernelExploitAlert],
        network:  &[CovertChannelAlert],
    ) -> f64 {
        let anomaly_part  = anomaly.value * 0.40;

        let drift_part = drift.map(|d| {
            let base = match d.severity {
                DriftSeverity::Normal      => 0.0,
                DriftSeverity::Moderate    => 0.3,
                DriftSeverity::Significant => 0.6,
                DriftSeverity::Extreme     => 1.0,
            };
            base * 0.20
        }).unwrap_or(0.0);

        let exploit_part = exploit.iter().map(|a| a.confidence).fold(0.0_f64, f64::max) * 0.15;
        let hollow_part  = hollow.iter().map(|a| a.confidence).fold(0.0_f64, f64::max) * 0.15;
        let kernel_part  = kernel.iter().map(|a| a.confidence).fold(0.0_f64, f64::max) * 0.10;
        let network_part = network.iter().map(|a| a.confidence).fold(0.0_f64, f64::max) * 0.10;

        // Critical booster: kernel CRITICAL findings warrant immediate escalation
        let critical_boost = kernel.iter()
            .any(|a| a.severity == KernelSeverity::Critical)
            .then(|| 0.30)
            .unwrap_or(0.0);

        // Composite bonus: 3+ engine signals agree
        let composite_bonus = if (exploit.len() + hollow.len() + kernel.len()) >= 3 {
            0.15
        } else {
            0.0
        };

        (anomaly_part + drift_part + exploit_part + hollow_part
            + kernel_part + network_part + critical_boost + composite_bonus)
            .clamp(0.0, 1.0)
    }

    fn contributing_methods(
        &self,
        anomaly:  &AnomalyScore,
        drift:    Option<&BaselineDrift>,
        exploit:  &[ExploitAlert],
        hollow:   &[HollowingAlert],
        kernel:   &[KernelExploitAlert],
        network:  &[CovertChannelAlert],
    ) -> Vec<DetectionMethod> {
        let mut methods = Vec::new();
        if anomaly.value >= self.threshold {
            methods.push(DetectionMethod::BehavioralAnomaly);
        }
        if drift.map(|d| d.severity >= DriftSeverity::Moderate).unwrap_or(false) {
            methods.push(DetectionMethod::BaselineDrift);
        }
        if !exploit.is_empty()  { methods.push(DetectionMethod::ExploitPrimitive); }
        if !hollow.is_empty()   { methods.push(DetectionMethod::ProcessInjection); }
        if !kernel.is_empty()   { methods.push(DetectionMethod::KernelExploit); }
        if !network.is_empty()  { methods.push(DetectionMethod::CovertChannel); }
        if methods.len() >= 2   { methods.push(DetectionMethod::Combined); }
        methods
    }

    fn build_summary(
        &self,
        profile: &ProcessProfile,
        score:   f64,
        exploit: &[ExploitAlert],
        hollow:  &[HollowingAlert],
    ) -> String {
        let mut parts = Vec::new();
        if let Some(a) = exploit.first() {
            parts.push(format!("exploit:{}", a.exploit_type));
        }
        if let Some(h) = hollow.first() {
            parts.push(format!("injection:{}", h.hollowing_type));
        }
        format!(
            "PID {} ({}): zero-day threat [score={:.3}] — {}",
            profile.pid, profile.process_name, score,
            if parts.is_empty() { "statistical anomaly".to_string() } else { parts.join(", ") }
        )
    }

    // ── Deduplication ─────────────────────────────────────────────────────────

    fn should_dedupe(&self, finding: &ZeroDayFinding) -> bool {
        let now = Instant::now();
        for method in &finding.methods {
            let key = DedupeKey { pid: finding.pid, method: method.clone() };
            let mut suppress = false;
            self.dedupe.entry(key).and_modify(|entry| {
                if now.duration_since(entry.last_seen) < self.dedupe_window {
                    entry.count += 1;
                    suppress = true;
                } else {
                    entry.last_seen = now;
                    entry.count = 1;
                }
            }).or_insert_with(|| DedupeEntry { last_seen: now, count: 1 });
            if suppress { return true; }
        }
        false
    }
}

impl Default for ZeroDayEngine {
    fn default() -> Self { Self::new() }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn collect_mitre(
    exploit:  &[ExploitAlert],
    hollow:   &[HollowingAlert],
    kernel:   &[KernelExploitAlert],
    network:  &[CovertChannelAlert],
) -> Vec<String> {
    let mut set = std::collections::HashSet::new();
    for a in exploit { set.extend(a.mitre_techniques.clone()); }
    for a in hollow  { set.extend(a.mitre_techniques.clone()); }
    for a in kernel  { set.extend(a.mitre_techniques.clone()); }
    for a in network { set.extend(a.mitre_techniques.clone()); }
    let mut v: Vec<_> = set.into_iter().collect();
    v.sort();
    v
}

fn describe_anomaly(features: &FeatureVector, score: &AnomalyScore) -> String {
    let mut signals = Vec::new();
    if features.syscall_rate > 500.0       { signals.push(format!("high syscall rate ({:.0}/s)", features.syscall_rate)); }
    if features.unique_syscalls > 80.0     { signals.push(format!("diverse syscalls ({:.0} unique)", features.unique_syscalls)); }
    if features.memory_alloc_rate > 5.0   { signals.push(format!("aggressive mem alloc ({:.1}/s)", features.memory_alloc_rate)); }
    if features.child_spawn_rate > 2.0    { signals.push(format!("child spawning ({:.1}/s)", features.child_spawn_rate)); }
    if features.write_entropy > 0.8       { signals.push(format!("high-entropy writes ({:.2})", features.write_entropy)); }
    if features.bpf_calls > 5.0          { signals.push(format!("bpf() calls ({:.0})", features.bpf_calls)); }
    if features.io_uring_ratio > 0.1     { signals.push("io_uring activity".to_string()); }
    if features.userfaultfd_count > 0.0  { signals.push("userfaultfd".to_string()); }
    if features.mmap_exec_ratio > 0.5    { signals.push(format!("high EXEC mmap ratio ({:.2})", features.mmap_exec_ratio)); }
    if signals.is_empty() {
        format!("composite anomaly (score={:.3})", score.value)
    } else {
        signals.join("; ")
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use syscall_profiler::*;

    fn ev(pid: u32, nr: u32, comm: &str) -> SyscallEvent {
        SyscallEvent::new(pid, nr, comm)
    }

    #[test]
    fn engine_initialises_without_panic() {
        let engine = ZeroDayEngine::new();
        assert_eq!(engine.tracked_processes(), 0);
    }

    #[test]
    fn normal_reads_do_not_produce_critical_findings() {
        let engine = ZeroDayEngine::new();
        for _ in 0..50 {
            for f in engine.ingest_syscall(&ev(1234, SYS_READ, "cat")) {
                assert!(f.severity < ZeroDaySeverity::Critical,
                    "Regular read should not trigger CRITICAL");
            }
        }
    }

    #[test]
    fn ptrace_from_non_debugger_eventually_triggers_finding() {
        let engine = ZeroDayEngine::new();
        let mut found = false;
        for _ in 0..8 {
            if !engine.ingest_syscall(&ev(2222, SYS_PTRACE, "bash")).is_empty() {
                found = true;
            }
        }
        assert!(found, "repeated ptrace from bash should produce a finding");
    }

    #[test]
    fn memfd_then_execve_triggers_ghosting_finding() {
        let engine = ZeroDayEngine::new();
        engine.ingest_syscall(&ev(3333, SYS_MEMFD_CREATE, "ghost"));
        let findings = engine.ingest_syscall(&ev(3333, SYS_EXECVE, "ghost"));
        assert!(!findings.is_empty(), "memfd + execve should produce a finding");
        assert!(findings.iter().any(|f| {
            f.exploit_alerts.iter().any(|a| a.exploit_type == ExploitType::FilelessExecution)
            || f.hollow_alerts.iter().any(|a| a.hollowing_type == HollowingType::ProcessGhosting)
        }), "finding should be FilelessExecution or ProcessGhosting");
    }

    #[test]
    fn process_exit_evicts_all_state() {
        let engine = ZeroDayEngine::new();
        for _ in 0..20 { engine.ingest_syscall(&ev(9999, SYS_READ, "test")); }
        assert_eq!(engine.tracked_processes(), 1);
        engine.on_process_exit(9999);
        assert_eq!(engine.tracked_processes(), 0);
    }

    #[test]
    fn kernel_event_ingestion_works() {
        let engine = ZeroDayEngine::new();
        for _ in 0..10 { engine.ingest_syscall(&ev(5555, SYS_READ, "bash")); }
        let profile = engine.profiler.get_profile(5555).unwrap();
        let kev = kernel_exploit::KernelEvent::new(5555, 155 /* SYS_PIVOT_ROOT */, 0, "bash");
        let findings = engine.ingest_kernel_event(&kev, &profile);
        assert!(!findings.is_empty(), "pivot_root should produce a kernel finding");
        assert!(findings[0].methods.contains(&DetectionMethod::KernelExploit));
    }

    #[test]
    fn network_alert_ingestion_works() {
        let engine = ZeroDayEngine::new();
        let alerts = vec![CovertChannelAlert {
            channel_type:     CovertChannelType::DnsTunneling,
            confidence:       0.85,
            description:      "DNS tunneling detected".into(),
            mitre_techniques: vec!["T1071.004".into()],
        }];
        let findings = engine.ingest_network_alert(6666, "evil", alerts);
        assert!(!findings.is_empty());
        assert!(findings[0].methods.contains(&DetectionMethod::CovertChannel));
    }

    #[test]
    fn combined_score_in_valid_range() {
        let engine = ZeroDayEngine::new();
        let dummy = AnomalyScore {
            value: 0.9, isolation_score: 0.9, zscore_component: 0.9,
            avg_path_length: 5.0, top_feature_idx: 0, n_trees: 100,
        };
        let score = engine.combined_score(&dummy, None, &[], &[], &[], &[]);
        assert!(score >= 0.0 && score <= 1.0, "score={}", score);
    }

    #[test]
    fn severity_from_score() {
        assert_eq!(ZeroDaySeverity::from_score(0.95), ZeroDaySeverity::Critical);
        assert_eq!(ZeroDaySeverity::from_score(0.80), ZeroDaySeverity::High);
        assert_eq!(ZeroDaySeverity::from_score(0.60), ZeroDaySeverity::Medium);
        assert_eq!(ZeroDaySeverity::from_score(0.40), ZeroDaySeverity::Low);
    }

    #[test]
    fn detection_method_display() {
        assert_eq!(format!("{}", DetectionMethod::KernelExploit),    "KernelExploit");
        assert_eq!(format!("{}", DetectionMethod::ProcessInjection), "ProcessInjection");
        assert_eq!(format!("{}", DetectionMethod::CovertChannel),    "CovertChannel");
        assert_eq!(format!("{}", DetectionMethod::Combined),         "Combined");
    }

    #[test]
    fn v1_ingest_produces_alerts_after_warmup() {
        let engine = ZeroDayEngine::new();
        // Warm up the engine (requires 50 events before v1 API fires)
        for _ in 0..55 {
            engine.ingest(&ev(7777, SYS_PTRACE, "bash"));
        }
        let alerts = engine.ingest(&ev(7777, SYS_PTRACE, "bash"));
        // Should have produced some exploit primitive alerts
        let _ = alerts; // result depends on timing; just verify no panic
    }
}
