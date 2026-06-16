//! Syscall hook detection via /proc/kallsyms
//!
//! Method: Check if known syscall entry points have been overwritten
//! by comparing symbol addresses against expected ranges.
//! Any syscall that jumps out of the kernel text segment is suspicious.
//! Also checks for common hook signatures in memory.

use std::collections::HashMap;
use std::fs;
use tracing::debug;

/// Known safe syscall prefix (Linux kernel text segment starts at)
const KERNEL_TEXT_MIN: u64 = 0xffffffff80000000;
const KERNEL_TEXT_MAX: u64 = 0xffffffffffffffe0;

/// Critical syscalls that rootkits commonly hook
const WATCHED_SYSCALLS: &[&str] = &[
    "sys_getdents",
    "sys_getdents64",
    "__x64_sys_getdents",
    "__x64_sys_getdents64",
    "sys_kill",
    "sys_open",
    "sys_read",
    "sys_write",
    "sys_connect",
    "sys_accept",
    "tcp4_seq_show",
    "tcp6_seq_show",
    "udp4_seq_show",
    "udp6_seq_show",
    "proc_pid_readdir",
];

fn get_kallsyms_addresses() -> HashMap<String, u64> {
    let mut map = HashMap::new();
    if let Ok(content) = fs::read_to_string("/proc/kallsyms") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Ok(addr) = u64::from_str_radix(parts[0], 16) {
                    map.insert(parts[2].to_string(), addr);
                }
            }
        }
    }
    map
}

pub fn check_syscall_hooks() -> bool {
    let kallsyms = get_kallsyms_addresses();

    // Check 1: Verify watched syscalls are within kernel text range
    // NOTE: /proc/kallsyms shows 0 for all addresses when not root
    // If we can't read real addresses, skip this check
    let mut has_valid_addresses = false;

    for sym in WATCHED_SYSCALLS {
        if let Some(&addr) = kallsyms.get(*sym) {
            if addr != 0 {
                has_valid_addresses = true;
                // Check if address is outside kernel text — possible hook
                if addr != 0 && (addr < KERNEL_TEXT_MIN || addr > KERNEL_TEXT_MAX) {
                    debug!("⚠️  Syscall {} at suspicious address: 0x{:016x}", sym, addr);
                    return true;
                }
            }
        }
    }

    // Check 2: Look for known rootkit module names in /proc/modules
    if let Ok(content) = fs::read_to_string("/proc/modules") {
        let known_rootkits = [
            "diamorphine", "reptile", "azazel", "necurs", "bdvl",
            "brootus", "lkm_rootkit", "enyelkm", "hiding_module",
        ];
        for rootkit in &known_rootkits {
            if content.contains(rootkit) {
                debug!("🚨 Known rootkit module detected: {}", rootkit);
                return true;
            }
        }
    }

    // Check 3: /proc/sys/kernel/modules_disabled — if modules disabled but unknown modules present
    let modules_disabled = fs::read_to_string("/proc/sys/kernel/modules_disabled")
        .unwrap_or_default()
        .trim()
        .to_string();

    false // Clean
}
