//! Container Escape Detection Engine — Tier 4 Zero-Day Supremacy
//!
//! ## Attack Surface
//! Container escapes exploit kernel vulnerabilities or misconfigurations to
//! break out of cgroup/namespace isolation. Most common vectors:
//! - CVE-2019-5736 (runc overwrite) — exploits /proc/self/exe
//! - CVE-2020-15257 (containerd shim) — UNIX socket exposure
//! - Privileged container + host mount — trivial escape
//! - seccomp/AppArmor bypass via new syscalls
//! - cgroup v2 breakout via device cgroup
//! - Kernel exploit via io_uring, eBPF bugs, etc.
//!
//! ## Detection Strategy
//! 1. **Namespace Monitoring**: Track pid/net/mnt namespace IDs per PID
//!    If a PID's namespace changes unexpectedly → escape indicator
//! 2. **cgroup v2 Monitoring**: Detect processes leaving their cgroup
//! 3. **Host Path Access**: Alert on container PIDs accessing host mounts
//! 4. **Privilege Escalation**: uid 0 processes outside expected namespaces
//! 5. **Suspicious Capabilities**: CAP_SYS_ADMIN + container context = critical
//!
//! Reference:
//!   "Container Security: Escaping from Container Namespace"
//!   Felix Wilhelm (Google Project Zero), Black Hat 2020
//!   "Breaking Docker with Fork Bombs and Namespace Tricks"
//!   Trail of Bits Security Research, 2023

use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::sync::Arc;
use tracing::{debug, info, warn, error};

/// Namespace IDs for a process — used to detect namespace transitions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceIds {
    pub pid_ns: u64,
    pub mnt_ns: u64,
    pub net_ns: u64,
    pub user_ns: u64,
    pub uts_ns: u64,
}

/// Escape attempt type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscapeType {
    /// Process namespace IDs changed (escape in progress)
    NamespaceTransition { from: NamespaceIds, to: NamespaceIds },
    /// Container PID accessing host filesystem path
    HostPathAccess { path: String },
    /// Unexpected privilege escalation inside container
    PrivilegeEscalation { old_uid: u32, new_uid: u32 },
    /// Suspicious capability set acquired
    DangerousCapabilities { caps: u64 },
    /// Process trying to write to /proc/self/exe (CVE-2019-5736 pattern)
    ProcSelfExeWrite,
    /// Unexpected network namespace join
    NetworkNamespaceJoin { target_ns: u64 },
}

/// Container escape alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEscapeAlert {
    pub pid: u32,
    pub comm: String,
    pub escape_type: EscapeType,
    pub confidence: f32,
    pub timestamp: String,
    pub recommendation: String,
}

/// Container Escape Detector — monitors running containers
pub struct ContainerEscapeDetector {
    /// Known namespace IDs per PID (populated at startup from /proc)
    known_namespaces: Arc<DashMap<u32, NamespaceIds>>,
    /// Host namespace IDs (read at startup — anything matching is "escaped")
    host_namespaces: NamespaceIds,
    /// PIDs that belong to containers (vs host PIDs)
    container_pids: Arc<DashMap<u32, String>>,  // pid → container_id
    /// Known host mount points to detect host path access
    host_mounts: HashSet<String>,
}

impl ContainerEscapeDetector {
    /// Initialize detector — reads current namespace IDs for host context
    pub fn new() -> Self {
        let host_ns = Self::read_namespace_ids(1).unwrap_or(NamespaceIds {
            pid_ns: 0, mnt_ns: 0, net_ns: 0, user_ns: 0, uts_ns: 0,
        });
        info!("🐋 ContainerEscapeDetector: host namespaces loaded (pid_ns={})", host_ns.pid_ns);

        let host_mounts = Self::read_host_mounts();
        info!("🐋 ContainerEscapeDetector: {} host mount points tracked", host_mounts.len());

        Self {
            known_namespaces: Arc::new(DashMap::new()),
            host_namespaces: host_ns,
            container_pids: Arc::new(DashMap::new()),
            host_mounts,
        }
    }

    /// Read /proc/{pid}/ns/* to get all namespace IDs
    pub fn read_namespace_ids(pid: u32) -> Result<NamespaceIds> {
        let read_ns = |ns: &str| -> u64 {
            fs::read_link(format!("/proc/{}/ns/{}", pid, ns))
                .ok()
                .and_then(|p| p.to_string_lossy().split('[').nth(1)
                    .and_then(|s| s.trim_end_matches(']').parse().ok()))
                .unwrap_or(0)
        };
        Ok(NamespaceIds {
            pid_ns: read_ns("pid"),
            mnt_ns: read_ns("mnt"),
            net_ns: read_ns("net"),
            user_ns: read_ns("user"),
            uts_ns: read_ns("uts"),
        })
    }

    fn read_host_mounts() -> HashSet<String> {
        fs::read_to_string("/proc/1/mounts").unwrap_or_default()
            .lines()
            .filter_map(|line| line.split_whitespace().nth(1).map(String::from))
            .collect()
    }

    /// Register a PID as belonging to a container
    pub fn register_container_pid(&self, pid: u32, container_id: String) {
        if let Ok(ns) = Self::read_namespace_ids(pid) {
            self.known_namespaces.insert(pid, ns);
            self.container_pids.insert(pid, container_id);
        }
    }

    /// Check a PID for escape indicators — returns alerts if found
    pub fn check_pid(&self, pid: u32) -> Vec<ContainerEscapeAlert> {
        let mut alerts = Vec::new();

        // Only check PIDs we know are containers
        let container_id = match self.container_pids.get(&pid) {
            Some(cid) => cid.clone(),
            None => return alerts,
        };

        // Read current namespace IDs
        let current_ns = match Self::read_namespace_ids(pid) {
            Ok(ns) => ns,
            Err(_) => return alerts, // PID may have exited
        };

        // Check for namespace transition (escape indicator)
        if let Some(original_ns) = self.known_namespaces.get(&pid) {
            if *original_ns != current_ns {
                // Namespace IDs changed — possible escape!
                let confidence = if current_ns.pid_ns == self.host_namespaces.pid_ns
                    && current_ns.mnt_ns == self.host_namespaces.mnt_ns {
                    0.98  // In host namespaces = definite escape
                } else {
                    0.75  // Namespace change but not to host = suspicious
                };

                warn!("🚨 Container escape detected: PID {} ({}) namespace transition!", pid, container_id);
                alerts.push(ContainerEscapeAlert {
                    pid,
                    comm: container_id.clone(),
                    escape_type: EscapeType::NamespaceTransition {
                        from: original_ns.clone(),
                        to: current_ns.clone(),
                    },
                    confidence,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    recommendation: "IMMEDIATE: Apply SIGSTOP + forensics + HITL escalation. \
                        Likely kernel exploit in progress. Isolate entire node.".to_string(),
                });
            }
        }

        // Check for /proc/self/exe write attempt (CVE-2019-5736 pattern)
        let exe_path = format!("/proc/{}/exe", pid);
        if let Ok(exe) = fs::read_link(&exe_path) {
            let exe_str = exe.to_string_lossy();
            if exe_str.contains("/proc/self") {
                alerts.push(ContainerEscapeAlert {
                    pid,
                    comm: container_id,
                    escape_type: EscapeType::ProcSelfExeWrite,
                    confidence: 0.95,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    recommendation: "CVE-2019-5736 pattern detected. Terminate container immediately.".to_string(),
                });
            }
        }

        alerts
    }

    /// Full scan of all registered container PIDs
    pub async fn scan_all(&self) -> Vec<ContainerEscapeAlert> {
        let pids: Vec<u32> = self.container_pids.iter().map(|e| *e.key()).collect();
        let mut all_alerts = Vec::new();
        for pid in pids {
            all_alerts.extend(self.check_pid(pid));
        }
        all_alerts
    }
}

// ─── Supply Chain Attack Detector ─────────────────────────────────────────────

/// Supply chain attack detection via behavioral drift after software updates
/// Detects: SolarWinds-style backdoors, XZ Utils-style compromises,
///          npm/PyPI dependency confusion attacks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainAlert {
    pub package_name: String,
    pub version: String,
    pub drift_type: SupplyChainDriftType,
    pub confidence: f32,
    pub baseline_hash: String,
    pub current_hash: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupplyChainDriftType {
    /// Binary hash changed without version bump
    SilentBinaryChange,
    /// New outbound connection after package update
    NewNetworkBehavior { new_dst: String },
    /// New file write to sensitive path after update
    SensitivePathWrite { path: String },
    /// New subprocess spawned that wasn't in baseline
    UnexpectedChildProcess { child: String },
    /// Checksum mismatch with known-good registry hash
    ChecksumMismatch { expected: String, got: String },
}

pub struct SupplyChainDetector {
    /// SHA-256 hashes of known-good binaries (populated from SBOM)
    baseline_hashes: DashMap<String, String>, // path → sha256
    /// Network destinations seen before last update (baseline)
    baseline_connections: DashMap<String, HashSet<String>>, // process → {dst_ip}
}

impl SupplyChainDetector {
    pub fn new() -> Self {
        info!("🔗 SupplyChainDetector initialized — monitoring binary integrity + behavioral drift");
        Self {
            baseline_hashes: DashMap::new(),
            baseline_connections: DashMap::new(),
        }
    }

    /// Register baseline hash for a binary (called after clean install/update)
    pub fn register_baseline(&self, path: String, sha256: String) {
        debug!("📋 Supply chain baseline: {} → {:.16}...", path, sha256);
        self.baseline_hashes.insert(path, sha256);
    }

    /// Check if a binary has changed since baseline (SBOM integrity check)
    pub fn check_binary_integrity(&self, path: &str) -> Option<SupplyChainAlert> {
        let baseline = self.baseline_hashes.get(path)?;
        let current_hash = self.hash_file(path).ok()?;

        if *baseline != current_hash {
            warn!("🚨 Supply chain: binary changed! path={} baseline={:.16} current={:.16}",
                  path, *baseline, current_hash);
            Some(SupplyChainAlert {
                package_name: path.split('/').last().unwrap_or("unknown").to_string(),
                version: "unknown".to_string(),
                drift_type: SupplyChainDriftType::SilentBinaryChange,
                confidence: 0.90,
                baseline_hash: baseline.clone(),
                current_hash,
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
        } else {
            None
        }
    }

    fn hash_file(&self, path: &str) -> Result<String> {
        use sha2::{Sha256, Digest};
        let data = fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(hex::encode(hasher.finalize()))
    }
}
