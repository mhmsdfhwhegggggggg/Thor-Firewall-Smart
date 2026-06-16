//! Thor Forensics Module — Digital Forensics and Incident Response (DFIR)
//!
//! This module provides the complete Axis-3 capability set:
//!
//! * **ThorQL** — SQL-like query language for live endpoint investigation.
//! * **Artifacts** — library of 15+ pre-built forensic investigation templates
//!                   mapped to MITRE ATT&CK techniques.
//! * **Collector** — secure, in-memory evidence packaging with chain-of-custody
//!                   SHA-256 hashing.  Nothing written to disk.
//! * **Memory Scanner** — YARA-based scanning of live process memory for
//!                        fileless malware and injected code.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use crate::forensics::{thorql, artifacts, collector, memory_scanner};
//!
//! // 1. Run a ThorQL query
//! let result = thorql::execute_query(
//!     "SELECT pid, name FROM processes WHERE cmdline LIKE '%base64%'"
//! ).unwrap();
//!
//! // 2. Run a named artifact
//! let connections = artifacts::run_artifact("linux.network.active_connections").unwrap();
//!
//! // 3. Collect files into a sealed evidence package
//! let pkg = collector::collect_evidence(
//!     vec!["/etc/passwd".into(), "/etc/crontab".into()],
//!     Some("IR-2024-001".into()),
//! ).unwrap();
//! assert!(pkg.verify_integrity());
//!
//! // 4. Scan a process for in-memory malware
//! let scan = memory_scanner::scan_pid(1234).unwrap();
//! println!("{} YARA matches in PID 1234", scan.matches.len());
//! ```

pub mod artifacts;
pub mod collector;
pub mod memory_scanner;
pub mod thorql;

// Re-export the most commonly used types for ergonomic access.
pub use artifacts::{Artifact, ArtifactRegistry, run_artifact};
pub use collector::{
    CollectionRequest, EvidencePackage, FileManifestEntry, ForensicCollector,
    collect_evidence,
};
pub use memory_scanner::{
    MemoryMatch, MemoryRegion, MemoryScanner, ScanError, ScanResult,
    builtin_memory_rules, scan_pid,
};
pub use thorql::{QueryResult, execute_query};
