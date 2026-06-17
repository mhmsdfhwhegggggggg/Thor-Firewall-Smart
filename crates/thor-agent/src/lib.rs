//! Thor Agent — library interface for integration testing and forensics modules.
//!
//! This lib exposes the forensics module (Axis 3) and zero-day detection
//! module (Axis 4) for use in integration tests.
//! The binary entry point remains `src/main.rs`.

// Axis 3: Digital Forensics and Incident Response
pub mod forensics;

// Axis 4: Zero-Day Detection Engine
// (exposed via detection::zero_day sub-module)
pub mod detection;

// Core infrastructure modules
pub mod state;
pub mod events;
pub mod soar;
pub mod ml;
pub mod api;
pub mod audit;
pub mod metrics;
pub mod siem;
pub mod security;
pub mod dissectors;
pub mod fingerprint;
pub mod ids;
pub mod intel;
pub mod fim;
pub mod ebpf;
pub mod config;

// ── Axis 3 convenience re-exports ─────────────────────────────────────────────
pub use forensics::{artifacts, collector, memory_scanner, thorql};

// ── Phase 3 Axis 1: Sequence Detector re-exports ──────────────────────────────
pub use detection::sequence_detector::{
    SequenceDetector, SequenceRule, SequenceStage, StagePredicate, EntityField,
};

// ── Axis 4 convenience re-exports ─────────────────────────────────────────────
pub use detection::zero_day::{
    ZeroDayEngine, ZeroDayAlert, ZeroDaySeverity, DetectionMethod,
    SyscallProfiler, SyscallEvent, ProcessProfile,
    AnomalyEngine, FeatureVector, AnomalyScore,
    ExploitPrimitiveDetector, ExploitAlert, ExploitType,
    BehavioralBaseline, BaselineDrift,
};
