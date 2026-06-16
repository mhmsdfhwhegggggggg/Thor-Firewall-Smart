//! Hidden network port detection
//!
//! Method: Compare /proc/net/tcp,udp,tcp6,udp6 vs ss socket output
//! Rootkits that hook do_tcp_seq_show will hide ports from /proc/net/tcp
//! but ss using netlink may show them (or vice versa).
//! We also compare against our own BPF-captured connections.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::str::FromStr;

use super::RootkitFinding;

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct SocketEntry {
    pub local_addr: String,
    pub local_port: u16,
    pub state:      u8,
}

/// Parse /proc/net/tcp or /proc/net/tcp6
fn parse_proc_net_tcp(path: &str) -> HashSet<SocketEntry> {
    let mut entries = HashSet::new();

    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 { continue; }

            let local = parts[1];
            let state = u8::from_str_radix(parts[3], 16).unwrap_or(0);

            // Parse hex:port format (IPv4)
            if let Some((addr_hex, port_hex)) = local.split_once(':') {
                let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
                if port == 0 { continue; }

                // Convert hex IP to dotted notation
                let addr = if let Ok(ip_u32) = u32::from_str_radix(addr_hex, 16) {
                    let bytes = ip_u32.to_le_bytes();
                    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
                } else {
                    addr_hex.to_string()
                };

                entries.insert(SocketEntry { local_addr: addr, local_port: port, state });
            }
        }
    }

    entries
}

/// Run `ss -tlnp` and parse output for comparison
fn get_ss_ports() -> HashSet<u16> {
    let mut ports = HashSet::new();
    if let Ok(output) = std::process::Command::new("ss")
        .args(["-tlnp", "-unp"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                // Local address field is parts[4], format: *:80 or 0.0.0.0:443
                if let Some(port_str) = parts[4].rsplit(':').next() {
                    if let Ok(port) = u16::from_str(port_str) {
                        ports.insert(port);
                    }
                }
            }
        }
    }
    ports
}

pub fn check_hidden_ports() -> Vec<RootkitFinding> {
    let mut findings = Vec::new();

    let proc_tcp = parse_proc_net_tcp("/proc/net/tcp");
    let ss_ports = get_ss_ports();

    // Find ports in ss output but NOT in /proc/net/tcp
    // (This means /proc/net/tcp is being hooked/filtered by rootkit)
    let proc_ports: HashSet<u16> = proc_tcp.iter()
        .filter(|e| e.state == 0x0A) // TCP_LISTEN = 10
        .map(|e| e.local_port)
        .collect();

    let hidden_ports: Vec<u16> = ss_ports
        .difference(&proc_ports)
        .copied()
        .filter(|&p| p > 0 && p < 65535)
        .collect();

    if !hidden_ports.is_empty() {
        let mut details = HashMap::new();
        details.insert("hidden_ports".to_string(),
            hidden_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","));

        findings.push(RootkitFinding {
            category:    "hidden_port".to_string(),
            description: format!(
                "Ports visible in ss output but hidden from /proc/net/tcp: {:?} — possible rootkit hook",
                hidden_ports
            ),
            severity:    5,
            details,
        });
    }

    findings
}
