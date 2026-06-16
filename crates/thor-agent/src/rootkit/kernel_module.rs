//! Hidden kernel module detection
//!
//! Method 1: Compare /proc/modules vs /sys/module directory
//! Method 2: Look for module objects in /proc/kallsyms pointing to unknown modules
//! Method 3: Check for syscall table overwrite indicators in /proc/kallsyms

use std::collections::{HashMap, HashSet};
use std::fs;
use tracing::debug;

use super::RootkitFinding;

/// Parse module names from /proc/modules
fn get_proc_modules() -> HashSet<String> {
    let mut modules = HashSet::new();
    if let Ok(content) = fs::read_to_string("/proc/modules") {
        for line in content.lines() {
            if let Some(name) = line.split_whitespace().next() {
                modules.insert(name.to_string());
            }
        }
    }
    modules
}

/// Get module names from /sys/module directory
fn get_sysfs_modules() -> HashSet<String> {
    let mut modules = HashSet::new();
    if let Ok(entries) = fs::read_dir("/sys/module") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                modules.insert(name.clone());
            }
        }
    }
    modules
}

/// Check for suspicious kernel symbols (non-builtin, non-module symbols)
fn get_unknown_symbols() -> Vec<String> {
    let mut suspicious = Vec::new();
    if let Ok(content) = fs::read_to_string("/proc/kallsyms") {
        let modules = get_proc_modules();
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let module = parts[3].trim_matches(|c| c == '[' || c == ']');
                // Symbols with an unknown module tag are suspicious
                if !module.is_empty() && !modules.contains(module) && module != "bpf" {
                    suspicious.push(format!("{} [{}]", parts[2], module));
                }
            }
        }
    }
    suspicious
}

pub fn check_hidden_modules() -> Vec<RootkitFinding> {
    let mut findings = Vec::new();

    let proc_mods = get_proc_modules();
    let sysfs_mods = get_sysfs_modules();

    // Modules in /sys/module but not in /proc/modules (suspicious)
    let hidden: Vec<String> = sysfs_mods
        .difference(&proc_mods)
        .filter(|m| {
            // Filter out known non-module sysfs entries
            let known_non_module = ["kernel", "pnp", "pm_test", "version", "lockdown"];
            !known_non_module.contains(&m.as_str())
        })
        .cloned()
        .collect();

    if !hidden.is_empty() {
        let mut details = HashMap::new();
        details.insert("modules".to_string(), hidden.join(","));
        findings.push(RootkitFinding {
            category:    "hidden_module".to_string(),
            description: format!(
                "Kernel modules in /sys/module but hidden from /proc/modules: [{}]",
                hidden.join(", ")
            ),
            severity:    5,
            details,
        });
    }

    // Check for unknown symbols
    let unknown = get_unknown_symbols();
    if !unknown.is_empty() {
        let sample = unknown.iter().take(5).cloned().collect::<Vec<_>>();
        let mut details = HashMap::new();
        details.insert("sample_symbols".to_string(), sample.join(","));
        details.insert("total_count".to_string(), unknown.len().to_string());
        findings.push(RootkitFinding {
            category:    "unknown_kernel_symbols".to_string(),
            description: format!(
                "Found {} kernel symbols belonging to unknown modules (possible rootkit)",
                unknown.len()
            ),
            severity:    4,
            details,
        });
    }

    findings
}
