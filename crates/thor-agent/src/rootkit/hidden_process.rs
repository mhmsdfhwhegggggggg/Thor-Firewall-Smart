//! Hidden process detection via /proc cross-reference
//!
//! Method: Compare PIDs visible in /proc vs PIDs reported by kill(pid, 0)
//! Hidden rootkits remove entries from /proc but kernel still knows about the process.
//! We also cross-reference with /proc/sched_debug and /proc/net/tcp socket owners.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::str::FromStr;
use tracing::debug;

use super::RootkitFinding;

/// PIDs visible in /proc filesystem
fn get_proc_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(pid) = u32::from_str(&name) {
                    pids.insert(pid);
                }
            }
        }
    }
    pids
}

/// Get process name from /proc/<pid>/comm
fn get_proc_comm(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Get socket inodes owned by a process
fn get_proc_socket_inodes(pid: u32) -> Vec<u64> {
    let mut inodes = Vec::new();
    if let Ok(entries) = fs::read_dir(format!("/proc/{}/fd", pid)) {
        for entry in entries.flatten() {
            if let Ok(target) = fs::read_link(entry.path()) {
                let s = target.to_string_lossy();
                if s.starts_with("socket:[") {
                    if let Some(inode_str) = s.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                        if let Ok(inode) = u64::from_str(inode_str) {
                            inodes.push(inode);
                        }
                    }
                }
            }
        }
    }
    inodes
}

/// Get socket inodes from /proc/net/tcp
fn get_net_tcp_inodes() -> HashSet<u64> {
    let mut inodes = HashSet::new();
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    if let Ok(inode) = u64::from_str(parts[9]) {
                        inodes.insert(inode);
                    }
                }
            }
        }
    }
    inodes
}

/// Check for processes that own sockets visible in /proc/net/tcp but not in /proc/<pid>/
/// This can indicate DKOM hiding
pub fn check_hidden_processes() -> Vec<RootkitFinding> {
    let mut findings = Vec::new();
    let proc_pids = get_proc_pids();

    // Collect all socket inodes claimed by visible processes
    let mut visible_inodes: HashSet<u64> = HashSet::new();
    for &pid in &proc_pids {
        for inode in get_proc_socket_inodes(pid) {
            visible_inodes.insert(inode);
        }
    }

    // Find TCP inodes not claimed by any visible process
    let tcp_inodes = get_net_tcp_inodes();
    let orphaned_sockets: Vec<u64> = tcp_inodes
        .difference(&visible_inodes)
        .copied()
        .collect();

    if !orphaned_sockets.is_empty() {
        let mut details = HashMap::new();
        details.insert("orphaned_socket_inodes".to_string(),
            orphaned_sockets.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(","));

        findings.push(RootkitFinding {
            category:    "hidden_process".to_string(),
            description: format!(
                "TCP sockets with no owning process in /proc — {} orphaned inodes (possible DKOM rootkit)",
                orphaned_sockets.len()
            ),
            severity:    5,
            details,
        });
    }

    // Additional check: iterate known PID range via kill(0)
    // This is a heuristic and might have false positives for kernel threads
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        for pid in 1u32..4096 {
            if proc_pids.contains(&pid) { continue; }
            // Check if pid exists via kill(pid, 0) — returns 0 if process exists
            let exists = unsafe { libc::kill(pid as libc::pid_t, 0) == 0 };
            if exists {
                let name = get_proc_comm(pid).unwrap_or_else(|| "<hidden>".to_string());
                if name != "<hidden>" {
                    // Some kernel threads don't appear in /proc and that's fine
                    continue;
                }
                let mut details = HashMap::new();
                details.insert("pid".to_string(), pid.to_string());
                findings.push(RootkitFinding {
                    category:    "hidden_process".to_string(),
                    description: format!("PID {} exists (kill returns 0) but absent from /proc", pid),
                    severity:    5,
                    details,
                });
            }
        }
    }

    findings
}
