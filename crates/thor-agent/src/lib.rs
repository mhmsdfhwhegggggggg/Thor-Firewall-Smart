//! Thor Agent — library interface for integration testing and forensics modules.
//!
//! This lib exposes the forensics module (Axis 3) for use in integration tests
//! in `tests/forensics_tests.rs`.  The binary entry point remains `src/main.rs`.

// Allow integration tests to access forensics sub-modules
pub mod forensics;

// Re-export state and events for tests that need them
pub mod state;
pub mod events;
pub mod detection;
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

// Allow the binary to use the same module tree
pub use forensics::{artifacts, collector, memory_scanner, thorql};
