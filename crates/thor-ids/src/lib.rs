//! Thor IDS — Intrusion Detection System library.
//!
//! Provides:
//! - `dpi`: Neural Deep Packet Inspection engine (protocol classifier,
//!   anomaly detector, covert channel detector, packet encoder)

pub mod dpi;

pub use dpi::DpiEngine;
pub use dpi::DpiResult;
