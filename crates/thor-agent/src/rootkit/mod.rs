//! ThorRootkit — Rootkit and kernel-level threat detector
//!
//! Implements rootkit detection without external tools by:
//! 1. Cross-referencing /proc with kernel data (inotify, /proc/kcore)
//! 2. Comparing loaded kernel modules via /proc/modules vs sysfs
//! 3. Detecting hidden ports via /proc/net/ vs ss/netstat
//! 4. Detecting hook-based syscall table modifications
//! 5. Finding DKOM (Direct Kernel Object Manipulation) artifacts

pub mod checker;
pub mod hidden_process;
pub mod kernel_module;
pub mod network_compare;
pub mod syscall_hook;

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{error, info, warn};

use crate::events::RawEvent;
use crate::state::ThorState;

pub use self::checker::RootkitChecker;

// ─── Engine ───────────────────────────────────────────────────────────────────

pub struct RootkitEngine {
    checker:  RootkitChecker,
    state:    Arc<ThorState>,
    interval: Duration,
}

impl RootkitEngine {
    pub fn new(state: Arc<ThorState>) -> Self {
        Self {
            checker:  RootkitChecker::new(),
            state,
            interval: Duration::from_secs(300), // scan every 5 minutes
        }
    }

    pub fn with_interval(mut self, secs: u64) -> Self {
        self.interval = Duration::from_secs(secs);
        self
    }

    /// Run continuous rootkit scanning in background
    pub async fn run(self, tx: mpsc::Sender<RawEvent>) {
        let mut ticker = interval(self.interval);
        info!("🔎 ThorRootkit engine started (interval: {:?})", self.interval);

        loop {
            ticker.tick().await;

            // Run all checks concurrently
            let hidden_procs  = self.checker.check_hidden_processes().await;
            let hidden_mods   = self.checker.check_hidden_modules().await;
            let hidden_ports  = self.checker.check_hidden_ports().await;
            let hook_detected = self.checker.check_syscall_hooks().await;

            // Emit alerts for any findings
            for finding in hidden_procs.iter()
                .chain(hidden_mods.iter())
                .chain(hidden_ports.iter())
            {
                let event = RawEvent::Rootkit(RootkitEvent {
                    category:    finding.category.clone(),
                    description: finding.description.clone(),
                    severity:    finding.severity,
                    details:     finding.details.clone(),
                });

                if tx.send(event).await.is_err() {
                    return;
                }
            }

            if hook_detected {
                let event = RawEvent::Rootkit(RootkitEvent {
                    category:    "syscall_hook".to_string(),
                    description: "Potential syscall table hook detected".to_string(),
                    severity:    5,
                    details:     std::collections::HashMap::new(),
                });
                let _ = tx.send(event).await;
            }

            let total = hidden_procs.len() + hidden_mods.len() + hidden_ports.len();
            if total > 0 || hook_detected {
                warn!("🚨 Rootkit scan: {} findings detected", total);
            } else {
                info!("✅ Rootkit scan: clean");
            }
        }
    }
}

// ─── Events ───────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct RootkitEvent {
    pub category:    String,
    pub description: String,
    pub severity:    u8,
    pub details:     std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct RootkitFinding {
    pub category:    String,
    pub description: String,
    pub severity:    u8,
    pub details:     std::collections::HashMap<String, String>,
}
