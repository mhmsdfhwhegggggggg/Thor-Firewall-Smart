//! Main rootkit checker — orchestrates all detection methods

use std::collections::HashMap;
use tracing::{debug, warn};

use super::RootkitFinding;
use super::hidden_process::check_hidden_processes;
use super::kernel_module::check_hidden_modules;
use super::network_compare::check_hidden_ports;
use super::syscall_hook::check_syscall_hooks;

pub struct RootkitChecker;

impl RootkitChecker {
    pub fn new() -> Self { Self }

    pub async fn check_hidden_processes(&self) -> Vec<RootkitFinding> {
        check_hidden_processes()
    }

    pub async fn check_hidden_modules(&self) -> Vec<RootkitFinding> {
        check_hidden_modules()
    }

    pub async fn check_hidden_ports(&self) -> Vec<RootkitFinding> {
        check_hidden_ports()
    }

    pub async fn check_syscall_hooks(&self) -> bool {
        check_syscall_hooks()
    }
}
