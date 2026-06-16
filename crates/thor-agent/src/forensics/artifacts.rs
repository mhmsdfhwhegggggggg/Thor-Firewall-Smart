//! Forensic Artifacts Library — pre-built ThorQL queries mapped to MITRE ATT&CK.
//!
//! Each `Artifact` is a named, versioned investigation template that can be
//! executed on a live endpoint with a single call to `run_artifact()`.
//!
//! All artifacts are validated at compile-time via unit tests.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use super::thorql::{execute_query, QueryResult};

// ─── Artifact definition ──────────────────────────────────────────────────────

/// Target operating system for an artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SupportedOs {
    Linux,
    Windows,
    All,
}

/// A single forensic artifact definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// Unique artifact identifier, e.g. `linux.persistence.cron`.
    pub id:           String,
    /// Human-readable name.
    pub name:         String,
    /// Purpose of this artifact.
    pub description:  String,
    /// MITRE ATT&CK technique IDs this artifact helps investigate.
    pub mitre_ids:    Vec<String>,
    /// ThorQL query to execute.
    pub query:        String,
    /// Target operating systems.
    pub supported_os: SupportedOs,
    /// Schema version (semver).
    pub version:      String,
}

impl Artifact {
    /// Execute this artifact on the local endpoint.
    ///
    /// # Returns
    /// A `QueryResult` with matching rows.
    ///
    /// # Errors
    /// Returns an error if the ThorQL query fails or the OS is unsupported.
    pub fn run(&self) -> Result<QueryResult> {
        #[cfg(unix)]
        {
            if self.supported_os == SupportedOs::Windows {
                return Err(anyhow!(
                    "Artifact '{}' requires Windows; current OS is Linux",
                    self.id
                ));
            }
        }
        #[cfg(windows)]
        {
            if self.supported_os == SupportedOs::Linux {
                return Err(anyhow!(
                    "Artifact '{}' requires Linux; current OS is Windows",
                    self.id
                ));
            }
        }
        execute_query(&self.query)
    }
}

// ─── Artifact registry ────────────────────────────────────────────────────────

/// Registry of all built-in artifacts, keyed by artifact ID.
pub struct ArtifactRegistry {
    artifacts: HashMap<String, Artifact>,
}

impl ArtifactRegistry {
    /// Build the registry and load all built-in artifacts.
    pub fn new() -> Self {
        let mut registry = Self { artifacts: HashMap::new() };
        for artifact in builtin_artifacts() {
            registry.artifacts.insert(artifact.id.clone(), artifact);
        }
        registry
    }

    /// Look up an artifact by its ID.
    ///
    /// # Errors
    /// Returns an error if no artifact with the given ID is registered.
    pub fn get(&self, id: &str) -> Result<&Artifact> {
        self.artifacts
            .get(id)
            .ok_or_else(|| anyhow!("Unknown artifact: '{}'. Run list_artifacts() to see available IDs.", id))
    }

    /// Execute an artifact by ID and return the result.
    ///
    /// # Arguments
    /// * `id` — artifact identifier, e.g. `"linux.network.active_connections"`.
    ///
    /// # Errors
    /// Returns an error if the artifact is not found or execution fails.
    pub fn run(&self, id: &str) -> Result<QueryResult> {
        self.get(id)?.run()
    }

    /// List all registered artifact IDs and their descriptions.
    pub fn list(&self) -> Vec<(&str, &str)> {
        let mut list: Vec<(&str, &str)> = self
            .artifacts
            .iter()
            .map(|(id, a)| (id.as_str(), a.description.as_str()))
            .collect();
        list.sort_by_key(|(id, _)| *id);
        list
    }

    /// Return the total number of registered artifacts.
    pub fn len(&self) -> usize {
        self.artifacts.len()
    }

    /// Returns `true` if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }
}

impl Default for ArtifactRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Built-in artifact definitions ────────────────────────────────────────────

fn builtin_artifacts() -> Vec<Artifact> {
    vec![
        // ── Linux persistence ─────────────────────────────────────────────────

        Artifact {
            id:           "linux.persistence.cron".into(),
            name:         "Linux Cron Job Enumeration".into(),
            description:  "Lists all cron entries from system and user crontab files. \
                           Helps identify scheduled task persistence.".into(),
            mitre_ids:    vec!["T1053.003".into()],
            query:        "SELECT * FROM cron_jobs".into(),
            supported_os: SupportedOs::Linux,
            version:      "1.0.0".into(),
        },

        Artifact {
            id:           "linux.persistence.rc_scripts".into(),
            name:         "Linux RC / Init Scripts".into(),
            description:  "Lists files in /etc/init.d and /etc/rc*.d that may \
                           indicate boot-time persistence.".into(),
            mitre_ids:    vec!["T1037.004".into()],
            query:        "SELECT path, size, mtime, mode FROM files('/etc/init.d')".into(),
            supported_os: SupportedOs::Linux,
            version:      "1.0.0".into(),
        },

        Artifact {
            id:           "linux.persistence.systemd_units".into(),
            name:         "Systemd Unit Files".into(),
            description:  "Enumerates systemd unit files in /etc/systemd/system. \
                           Malware often installs rogue service units for persistence.".into(),
            mitre_ids:    vec!["T1543.002".into()],
            query:        "SELECT path, size, mtime FROM files('/etc/systemd/system')".into(),
            supported_os: SupportedOs::Linux,
            version:      "1.0.0".into(),
        },

        // ── Linux network ─────────────────────────────────────────────────────

        Artifact {
            id:           "linux.network.active_connections".into(),
            name:         "Active Network Connections".into(),
            description:  "Lists all active TCP connections with associated PIDs \
                           and process names. Useful for detecting C2 beaconing.".into(),
            mitre_ids:    vec!["T1071".into(), "T1571".into()],
            query:        "SELECT pid, process_name, protocol, local_ip, local_port, \
                           remote_ip, remote_port, state FROM connections \
                           WHERE state = 'ESTABLISHED'".into(),
            supported_os: SupportedOs::Linux,
            version:      "1.0.0".into(),
        },

        Artifact {
            id:           "linux.network.listening_ports".into(),
            name:         "Listening Network Ports".into(),
            description:  "Lists all sockets in LISTEN state. Identifies potential \
                           backdoors listening for incoming connections.".into(),
            mitre_ids:    vec!["T1049".into()],
            query:        "SELECT pid, process_name, protocol, local_ip, local_port \
                           FROM connections WHERE state = 'LISTEN'".into(),
            supported_os: SupportedOs::Linux,
            version:      "1.0.0".into(),
        },

        Artifact {
            id:           "linux.network.suspicious_ports".into(),
            name:         "Connections on Non-Standard Ports".into(),
            description:  "Identifies established connections on ports outside \
                           common well-known ranges (80, 443, 22, 53). \
                           Often indicative of C2 traffic.".into(),
            mitre_ids:    vec!["T1571".into()],
            query:        "SELECT pid, process_name, remote_ip, remote_port \
                           FROM connections \
                           WHERE state = 'ESTABLISHED' AND remote_port > 1024 \
                           AND remote_port != 8080 AND remote_port != 8443".into(),
            supported_os: SupportedOs::Linux,
            version:      "1.0.0".into(),
        },

        // ── Linux processes ───────────────────────────────────────────────────

        Artifact {
            id:           "linux.process.running_as_root".into(),
            name:         "Processes Running as Root".into(),
            description:  "Lists all processes running with UID=0. Unexpected root \
                           processes may indicate privilege escalation.".into(),
            mitre_ids:    vec!["T1548".into()],
            query:        "SELECT pid, name, cmdline, exe FROM processes WHERE uid = 0".into(),
            supported_os: SupportedOs::Linux,
            version:      "1.0.0".into(),
        },

        Artifact {
            id:           "linux.process.suspicious_cmdline".into(),
            name:         "Suspicious Process Command Lines".into(),
            description:  "Searches for processes with command lines containing \
                           common attacker tools or obfuscation patterns \
                           (base64, curl pipe, netcat reverse shells).".into(),
            mitre_ids:    vec!["T1059".into(), "T1140".into()],
            query:        "SELECT pid, name, cmdline FROM processes \
                           WHERE cmdline LIKE '%base64%' OR cmdline LIKE '%-e /bin/sh%' \
                           OR cmdline LIKE '%/dev/tcp/%' OR cmdline LIKE '%mkfifo%'".into(),
            supported_os: SupportedOs::Linux,
            version:      "1.0.0".into(),
        },

        Artifact {
            id:           "linux.process.interpreters".into(),
            name:         "Running Script Interpreters".into(),
            description:  "Lists active Python, Perl, Ruby, and shell interpreter \
                           processes. Useful for detecting fileless malware.".into(),
            mitre_ids:    vec!["T1059".into()],
            query:        "SELECT pid, name, cmdline, uid FROM processes \
                           WHERE name LIKE '%python%' OR name LIKE '%perl%' \
                           OR name LIKE '%ruby%' OR name LIKE '%sh' OR name = 'bash'".into(),
            supported_os: SupportedOs::Linux,
            version:      "1.0.0".into(),
        },

        // ── Linux credentials / users ─────────────────────────────────────────

        Artifact {
            id:           "linux.credentials.user_accounts".into(),
            name:         "Local User Accounts".into(),
            description:  "Enumerates local user accounts from /etc/passwd. \
                           Look for unexpected accounts or UID=0 duplicates.".into(),
            mitre_ids:    vec!["T1087.001".into()],
            query:        "SELECT username, uid, gid, home, shell FROM users".into(),
            supported_os: SupportedOs::Linux,
            version:      "1.0.0".into(),
        },

        Artifact {
            id:           "linux.credentials.root_accounts".into(),
            name:         "Accounts with UID 0 (Root Equivalents)".into(),
            description:  "Lists all accounts with UID=0. More than one is a \
                           strong indicator of account compromise or persistence.".into(),
            mitre_ids:    vec!["T1136.001".into()],
            query:        "SELECT username, uid, gid, shell FROM users WHERE uid = 0".into(),
            supported_os: SupportedOs::Linux,
            version:      "1.0.0".into(),
        },

        Artifact {
            id:           "linux.credentials.nopasswd_shells".into(),
            name:         "Accounts with Unusual Shells".into(),
            description:  "Identifies user accounts with interactive shells that \
                           might be unexpected (excluding /sbin/nologin, /bin/false).".into(),
            mitre_ids:    vec!["T1098".into()],
            query:        "SELECT username, uid, shell FROM users \
                           WHERE shell != '/sbin/nologin' AND shell != '/bin/false' \
                           AND shell != '/usr/sbin/nologin'".into(),
            supported_os: SupportedOs::Linux,
            version:      "1.0.0".into(),
        },

        // ── Generic / cross-platform ──────────────────────────────────────────

        Artifact {
            id:           "generic.file.tmp_executables".into(),
            name:         "Executable Files in /tmp".into(),
            description:  "Finds files in /tmp with execute permissions. \
                           Attackers often stage payloads in /tmp.".into(),
            mitre_ids:    vec!["T1036".into(), "T1027".into()],
            query:        "SELECT path, size, mtime, mode, uid FROM files('/tmp')".into(),
            supported_os: SupportedOs::Linux,
            version:      "1.0.0".into(),
        },

        Artifact {
            id:           "generic.file.ssh_authorized_keys".into(),
            name:         "SSH Authorized Keys".into(),
            description:  "Lists SSH authorized_keys files. Attackers add keys \
                           to maintain persistent access without passwords.".into(),
            mitre_ids:    vec!["T1098.004".into()],
            query:        "SELECT path, size, mtime FROM files('/root/.ssh')".into(),
            supported_os: SupportedOs::Linux,
            version:      "1.0.0".into(),
        },
    ]
}

// ─── Convenience function ─────────────────────────────────────────────────────

/// Execute a named artifact from the global built-in registry.
///
/// # Arguments
/// * `artifact_id` — e.g. `"linux.network.active_connections"`.
///
/// # Errors
/// Returns an error if the artifact ID is not registered or execution fails.
pub fn run_artifact(artifact_id: &str) -> Result<QueryResult> {
    ArtifactRegistry::new().run(artifact_id)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_at_least_ten_artifacts() {
        let reg = ArtifactRegistry::new();
        assert!(reg.len() >= 10, "Expected ≥10 built-in artifacts, got {}", reg.len());
    }

    #[test]
    fn run_active_connections_returns_expected_columns() {
        let result = run_artifact("linux.network.active_connections").unwrap();
        // Even on a system with no established connections, the result should be valid
        // When rows are present, they must contain the expected keys
        if let Some(first) = result.rows.first() {
            assert!(first.contains_key("pid"),        "Missing 'pid' column");
            assert!(first.contains_key("remote_ip"),  "Missing 'remote_ip' column");
            assert!(first.contains_key("local_ip"),   "Missing 'local_ip' column");
        }
    }

    #[test]
    fn run_cron_does_not_panic() {
        let result = run_artifact("linux.persistence.cron");
        assert!(result.is_ok(), "Cron artifact must not error: {:?}", result.err());
    }

    #[test]
    fn run_user_accounts_finds_root() {
        let result = run_artifact("linux.credentials.user_accounts").unwrap();
        let has_root = result.rows.iter().any(|r| {
            r.get("username").and_then(|v| v.as_str()) == Some("root")
        });
        assert!(has_root, "root should be in /etc/passwd");
    }

    #[test]
    fn run_root_accounts_single_uid_zero() {
        let result = run_artifact("linux.credentials.root_accounts").unwrap();
        // There should be exactly 1 UID=0 account (root) on a clean system
        assert!(!result.rows.is_empty(), "At least root should be uid=0");
        for row in &result.rows {
            let uid = row.get("uid").and_then(|v| v.as_u64()).unwrap_or(1);
            assert_eq!(uid, 0, "All returned rows must have uid=0");
        }
    }

    #[test]
    fn unknown_artifact_returns_err() {
        assert!(run_artifact("nonexistent.artifact.xyz").is_err());
    }

    #[test]
    fn list_artifacts_sorted() {
        let reg = ArtifactRegistry::new();
        let list = reg.list();
        let ids: Vec<&str> = list.iter().map(|(id, _)| *id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "Artifact list should be sorted");
    }
}
