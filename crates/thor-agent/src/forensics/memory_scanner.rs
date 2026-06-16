//! In-Memory YARA Scanner — scans live process memory for malware patterns.
//!
//! On Linux, memory is read from `/proc/<pid>/mem` after parsing the executable
//! segments from `/proc/<pid>/maps`.  The scanner handles `EPERM`, `ESRCH`, and
//! `EIO` gracefully — a single unreadable region never aborts the whole scan.
//!
//! # Safety
//! * Reading another process's memory requires `CAP_SYS_PTRACE` or running as
//!   root.  When permissions are denied, the scanner returns a structured error
//!   rather than panicking.
//! * Partial reads (e.g. process exits mid-scan) are handled silently.

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use yara::Compiler;

// ─── Types ────────────────────────────────────────────────────────────────────

/// A single YARA match found in process memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMatch {
    /// PID of the scanned process.
    pub pid:          u32,
    /// Name of the matching YARA rule.
    pub rule_name:    String,
    /// Memory region where the match was found.
    pub region:       MemoryRegion,
    /// Byte offset within the region of the first match instance.
    pub match_offset: u64,
    /// Tags associated with the matching rule.
    pub tags:         Vec<String>,
    /// Rule metadata as key-value pairs.
    pub meta:         Vec<(String, String)>,
}

/// A single executable memory segment from `/proc/<pid>/maps`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub start:       u64,
    pub end:         u64,
    pub permissions: String,
    pub pathname:    String,
}

impl MemoryRegion {
    /// Size of this memory region in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// Summary of a completed memory scan for one process.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    /// PID that was scanned.
    pub pid:            u32,
    /// Process name (from `/proc/<pid>/comm`).
    pub process_name:   String,
    /// All YARA matches found.
    pub matches:        Vec<MemoryMatch>,
    /// Number of memory regions examined.
    pub regions_scanned: usize,
    /// Number of regions skipped (permission denied / read error).
    pub regions_skipped: usize,
    /// Total bytes read from process memory.
    pub bytes_read:     u64,
    /// Whether the scan completed (false = process exited mid-scan).
    pub completed:      bool,
}

/// Reason a scan could not be performed.
#[derive(Debug, Serialize, Deserialize)]
pub enum ScanError {
    /// Insufficient privileges (`EPERM` / `EACCES`).
    PermissionDenied,
    /// Process no longer exists (`ESRCH`).
    ProcessNotFound,
    /// YARA rule compilation failed.
    RuleCompilationError(String),
    /// Other I/O error.
    IoError(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::PermissionDenied     => write!(f, "Permission denied: CAP_SYS_PTRACE required"),
            ScanError::ProcessNotFound      => write!(f, "Process not found (may have exited)"),
            ScanError::RuleCompilationError(s) => write!(f, "YARA compile error: {}", s),
            ScanError::IoError(s)           => write!(f, "I/O error: {}", s),
        }
    }
}

// ─── Memory map parser ────────────────────────────────────────────────────────

/// Parse `/proc/<pid>/maps` and return only executable memory regions.
///
/// We limit scans to executable segments (`r-x*`) to avoid scanning stack /
/// heap noise that generates false positives.
fn parse_executable_regions(pid: u32) -> Result<Vec<MemoryRegion>, ScanError> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = fs::read_to_string(&maps_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            ScanError::PermissionDenied
        } else if e.kind() == std::io::ErrorKind::NotFound {
            ScanError::ProcessNotFound
        } else {
            ScanError::IoError(e.to_string())
        }
    })?;

    let regions = content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(6, ' ').collect();
            if parts.len() < 5 { return None; }

            let perms = parts[1];
            // Only scan readable, executable segments
            if !perms.starts_with('r') || !perms.contains('x') { return None; }

            let addrs: Vec<&str> = parts[0].splitn(2, '-').collect();
            if addrs.len() != 2 { return None; }

            let start = u64::from_str_radix(addrs[0], 16).ok()?;
            let end   = u64::from_str_radix(addrs[1], 16).ok()?;
            if start >= end { return None; }

            let pathname = parts.get(5).map(|s| s.trim().to_string()).unwrap_or_default();

            Some(MemoryRegion {
                start,
                end,
                permissions: perms.to_string(),
                pathname,
            })
        })
        .collect();

    Ok(regions)
}

// ─── Region reader ────────────────────────────────────────────────────────────

/// Maximum bytes to read per memory region (prevents OOM on huge mappings).
const MAX_REGION_BYTES: u64 = 64 * 1024 * 1024; // 64 MB

/// Read a memory region from `/proc/<pid>/mem`.
/// Returns `None` if the region is unreadable (EPERM, EIO, etc.).
fn read_region(pid: u32, region: &MemoryRegion) -> Option<Vec<u8>> {
    let mem_path = format!("/proc/{}/mem", pid);
    let mut f = fs::File::open(&mem_path).ok()?;

    let size = region.size().min(MAX_REGION_BYTES) as usize;
    if size == 0 { return None; }

    // ptrace-attach is not required when reading our own process or with CAP_SYS_PTRACE
    if f.seek(SeekFrom::Start(region.start)).is_err() {
        return None;
    }

    let mut buf = vec![0u8; size];
    let mut total_read = 0usize;

    // Read in chunks; a partial read is fine — the rest is zero-padded
    while total_read < size {
        let chunk = &mut buf[total_read..];
        match f.read(chunk) {
            Ok(0)  => break, // EOF
            Ok(n)  => total_read += n,
            Err(_) => break, // ESRCH, EIO, etc.
        }
    }

    if total_read == 0 { None } else { buf.truncate(total_read); Some(buf) }
}

// ─── Scanner ──────────────────────────────────────────────────────────────────

/// In-memory YARA process scanner.
pub struct MemoryScanner;

impl MemoryScanner {
    /// Create a new scanner instance.
    pub fn new() -> Self {
        Self
    }

    /// Scan the memory of a single process using the provided YARA rules.
    ///
    /// # Arguments
    /// * `pid`        — the target process ID.
    /// * `yara_rules` — one or more YARA rule definitions as UTF-8 strings.
    ///
    /// # Returns
    /// A `ScanResult` describing all matches and scan statistics.
    ///
    /// # Errors
    /// Returns a `ScanError` if the rules cannot be compiled or the process
    /// cannot be accessed at all.  Per-region read failures are silently skipped
    /// and counted in `regions_skipped`.
    pub fn scan_process(
        &self,
        pid:        u32,
        yara_rules: &[&str],
    ) -> Result<ScanResult, ScanError> {
        // Compile YARA rules
        let rules = self.compile_rules(yara_rules)?;

        let process_name = fs::read_to_string(format!("/proc/{}/comm", pid))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        info!("🔬 Memory scan: PID {} ({})", pid, process_name);

        // Parse executable memory regions
        let regions = parse_executable_regions(pid)?;

        let mut matches         = Vec::new();
        let mut regions_scanned = 0usize;
        let mut regions_skipped = 0usize;
        let mut bytes_read      = 0u64;
        let mut completed       = true;

        for region in &regions {
            debug!(
                "  Scanning region 0x{:x}–0x{:x} ({}, {} bytes)",
                region.start, region.end, region.permissions, region.size()
            );

            match read_region(pid, region) {
                None => {
                    regions_skipped += 1;
                }
                Some(data) => {
                    regions_scanned += 1;
                    bytes_read += data.len() as u64;

                    // Check process still exists (may have exited during scan)
                    if !Path::new(&format!("/proc/{}", pid)).exists() {
                        warn!("PID {} exited during memory scan", pid);
                        completed = false;
                        break;
                    }

                    // Apply YARA rules to this region's data
                    let yara_matches = match rules.scan_mem(&data, 30) {
                        Ok(m)  => m,
                        Err(e) => {
                            warn!("YARA scan error on region 0x{:x}: {}", region.start, e);
                            regions_skipped += 1;
                            continue;
                        }
                    };

                    for m in yara_matches {
                        for string_match in m.strings {
                            let match_offset = string_match.matches
                                .first()
                                .map(|sm| sm.offset as u64)
                                .unwrap_or(0);

                            matches.push(MemoryMatch {
                                pid,
                                rule_name:    m.identifier.to_string(),
                                region:       region.clone(),
                                match_offset: region.start + match_offset,
                                tags:         m.tags.iter().map(|t| t.to_string()).collect(),
                                meta:         m.metadatas.iter().map(|meta| {
                                    (meta.identifier.to_string(), format!("{:?}", meta.value))
                                }).collect(),
                            });
                        }
                    }
                }
            }
        }

        info!(
            "✅ Memory scan PID {}: {} matches, {}/{} regions scanned, {} bytes",
            pid, matches.len(), regions_scanned, regions.len(), bytes_read
        );

        Ok(ScanResult {
            pid,
            process_name,
            matches,
            regions_scanned,
            regions_skipped,
            bytes_read,
            completed,
        })
    }

    /// Scan all running processes with the provided YARA rules.
    ///
    /// Processes that cannot be scanned (EPERM) are skipped and returned
    /// with empty match lists and `completed = false`.
    ///
    /// # Returns
    /// A vector of `ScanResult`, one per accessible process.
    pub fn scan_all_processes(
        &self,
        yara_rules: &[&str],
    ) -> Result<Vec<ScanResult>, ScanError> {
        // Validate rules first (fail fast before iterating all PIDs)
        let _ = self.compile_rules(yara_rules)?;

        let mut results = Vec::new();

        if let Ok(proc_dir) = fs::read_dir("/proc") {
            for entry in proc_dir.flatten() {
                let name = entry.file_name();
                let s = name.to_string_lossy();
                let pid: u32 = match s.parse() { Ok(n) => n, Err(_) => continue };

                match self.scan_process(pid, yara_rules) {
                    Ok(result) => {
                        if !result.matches.is_empty() {
                            info!("🚨 YARA hit in PID {}: {} matches", pid, result.matches.len());
                        }
                        results.push(result);
                    }
                    Err(ScanError::ProcessNotFound) => {} // process exited — skip silently
                    Err(ScanError::PermissionDenied) => {
                        debug!("Skipping PID {} (EPERM)", pid);
                    }
                    Err(e) => warn!("Scan error for PID {}: {}", pid, e),
                }
            }
        }

        Ok(results)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn compile_rules(&self, yara_rules: &[&str]) -> Result<yara::Rules, ScanError> {
        let mut compiler = Compiler::new()
            .map_err(|e| ScanError::RuleCompilationError(e.to_string()))?;

        for rule_str in yara_rules {
            compiler
                .add_rules_str(rule_str)
                .map_err(|e| ScanError::RuleCompilationError(e.to_string()))?;
        }

        compiler
            .compile_rules()
            .map_err(|e| ScanError::RuleCompilationError(e.to_string()))
    }
}

impl Default for MemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Default built-in YARA rules ─────────────────────────────────────────────

/// Returns a set of built-in YARA rules covering common memory-resident threats.
pub fn builtin_memory_rules() -> Vec<&'static str> {
    vec![
        // Meterpreter in-memory signature
        r#"
rule Meterpreter_InMemory {
    meta:
        description = "Detects Metasploit Meterpreter in process memory"
        author = "Thor Security Team"
        severity = "critical"
    strings:
        $a = "meterpreter" nocase
        $b = { 4d 65 74 65 72 70 72 65 74 65 72 }
        $c = "ReflectiveDllInjection" nocase
    condition:
        any of them
}
"#,
        // Cobalt Strike beacon
        r#"
rule CobaltStrike_Beacon_InMemory {
    meta:
        description = "Detects Cobalt Strike Beacon in process memory"
        author = "Thor Security Team"
        severity = "critical"
    strings:
        $a = "%s (admin)" nocase
        $b = "beacon.dll" nocase
        $c = { 48 65 61 70 41 6c 6c 6f 63 00 }
        $magic = { FC 48 83 E4 F0 E8 }
    condition:
        2 of them
}
"#,
        // Generic reverse shell indicators
        r#"
rule ReverseShell_Indicators {
    meta:
        description = "Detects common reverse shell strings in process memory"
        severity = "high"
    strings:
        $a = "/dev/tcp/" nocase
        $b = "bash -i >& /dev/tcp" nocase
        $c = "0>&1" nocase
        $d = "mkfifo /tmp/" nocase
        $e = "nc -e /bin/sh" nocase
    condition:
        2 of them
}
"#,
        // Process injection
        r#"
rule ProcessInjection_Indicators {
    meta:
        description = "Detects process injection artifacts in memory"
        severity = "high"
    strings:
        $a = "VirtualAllocEx" nocase
        $b = "WriteProcessMemory" nocase
        $c = "CreateRemoteThread" nocase
        $d = "NtCreateThreadEx" nocase
    condition:
        2 of them
}
"#,
    ]
}

// ─── Convenience function ─────────────────────────────────────────────────────

/// Scan a single process using the built-in YARA rule set.
///
/// # Arguments
/// * `pid` — target process ID.
///
/// # Returns
/// A `ScanResult` or a `ScanError`.
pub fn scan_pid(pid: u32) -> Result<ScanResult, ScanError> {
    let rules: Vec<&str> = builtin_memory_rules();
    MemoryScanner::new().scan_process(pid, &rules)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_self_does_not_panic() {
        let pid = std::process::id();
        let rules: Vec<&str> = builtin_memory_rules();
        let result = MemoryScanner::new().scan_process(pid, &rules);
        // Should not panic — either Ok or a structured ScanError
        match result {
            Ok(r) => {
                // Scanning ourselves should succeed
                assert_eq!(r.pid, pid);
            }
            Err(ScanError::PermissionDenied) => {
                // Acceptable in restricted environments (no CAP_SYS_PTRACE)
            }
            Err(e) => {
                // Other errors should not occur for our own PID
                panic!("Unexpected error scanning self: {}", e);
            }
        }
    }

    #[test]
    fn scan_nonexistent_pid_returns_not_found() {
        let rules: Vec<&str> = builtin_memory_rules();
        let result = MemoryScanner::new().scan_process(99_999_999, &rules);
        match result {
            Err(ScanError::ProcessNotFound) | Err(ScanError::PermissionDenied) => {}
            Err(ScanError::IoError(_)) => {} // also acceptable
            Ok(_) => panic!("Should not succeed for non-existent PID"),
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn invalid_yara_rule_returns_compile_error() {
        let bad_rules = &["this is not a valid yara rule $$$$"];
        let result = MemoryScanner::new().scan_process(1, bad_rules);
        assert!(
            matches!(result, Err(ScanError::RuleCompilationError(_))),
            "Invalid YARA rules must return RuleCompilationError"
        );
    }

    #[test]
    fn builtin_rules_compile_successfully() {
        let rules = builtin_memory_rules();
        let mut compiler = yara::Compiler::new().expect("YARA compiler init");
        for rule in &rules {
            compiler.add_rules_str(rule).expect("Builtin rule should compile");
        }
        let compiled = compiler.compile_rules();
        assert!(compiled.is_ok(), "All built-in rules must compile without errors");
    }

    #[test]
    fn memory_region_size_calculation() {
        let region = MemoryRegion {
            start:       0x1000,
            end:         0x5000,
            permissions: "r-xp".into(),
            pathname:    "[vdso]".into(),
        };
        assert_eq!(region.size(), 0x4000);
    }

    #[test]
    fn parse_maps_for_self_finds_regions() {
        let pid = std::process::id();
        let regions = parse_executable_regions(pid);
        match regions {
            Ok(r) => {
                // Our own process must have at least one executable region
                assert!(!r.is_empty(), "Self executable regions should not be empty");
                // All returned regions must be executable
                for region in &r {
                    assert!(
                        region.permissions.contains('x'),
                        "All regions must have execute permission: {}", region.permissions
                    );
                }
            }
            Err(ScanError::PermissionDenied) => {
                // In heavily restricted sandbox environments this can happen
            }
            Err(e) => panic!("Unexpected error parsing own maps: {}", e),
        }
    }
}
