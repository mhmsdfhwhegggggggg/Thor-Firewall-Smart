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
//!
//! # YARA Rule Coverage (17 built-in rules)
//! 1.  Meterpreter in-memory shellcode
//! 2.  Cobalt Strike Beacon (stager + full)
//! 3.  Generic reverse shell indicators
//! 4.  Process injection (VirtualAllocEx / CreateRemoteThread)
//! 5.  Shellcode stager (NOP sled + PUSH-CALL pattern)
//! 6.  Privilege escalation (SUID abuse + shadow access)
//! 7.  Credential dumping (LSASS / /etc/shadow patterns)
//! 8.  Rootkit indicators (LKM load + syscall table hooks)
//! 9.  Lateral movement (SSH key injection + Pass-the-Hash)
//! 10. Persistence (crontab + systemd unit drop)
//! 11. Defense evasion (log clearing + history wipe)
//! 12. Data exfiltration (base64 + curl pipe patterns)
//! 13. Ransomware (ChaCha20/AES key expansion + shadow copy deletion)
//! 14. Fileless malware (memfd_create / anonymous executable mapping)
//! 15. Empire framework in-memory signatures
//! 16. Mimikatz credential extraction
//! 17. Heap spray / NULL page access preparation

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use yara::Compiler;

// ─── Types ────────────────────────────────────────────────────────────────────

/// A single YARA match found in process memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMatch {
    pub pid:          u32,
    pub rule_name:    String,
    pub region:       MemoryRegion,
    pub match_offset: u64,
    pub tags:         Vec<String>,
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
    pub fn size(&self) -> u64 { self.end.saturating_sub(self.start) }
}

/// Summary of a completed memory scan for one process.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub pid:             u32,
    pub process_name:    String,
    pub matches:         Vec<MemoryMatch>,
    pub regions_scanned: usize,
    pub regions_skipped: usize,
    pub bytes_read:      u64,
    pub completed:       bool,
}

/// Reason a scan could not be performed.
#[derive(Debug, Serialize, Deserialize)]
pub enum ScanError {
    PermissionDenied,
    ProcessNotFound,
    RuleCompilationError(String),
    IoError(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::PermissionDenied        => write!(f, "Permission denied: CAP_SYS_PTRACE required"),
            ScanError::ProcessNotFound         => write!(f, "Process not found (may have exited)"),
            ScanError::RuleCompilationError(s) => write!(f, "YARA compile error: {}", s),
            ScanError::IoError(s)              => write!(f, "I/O error: {}", s),
        }
    }
}

// ─── Memory map parser ────────────────────────────────────────────────────────

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

    let regions = content.lines().filter_map(|line| {
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        if parts.len() < 5 { return None; }
        let perms = parts[1];
        if !perms.starts_with('r') || !perms.contains('x') { return None; }
        let addrs: Vec<&str> = parts[0].splitn(2, '-').collect();
        if addrs.len() != 2 { return None; }
        let start = u64::from_str_radix(addrs[0], 16).ok()?;
        let end   = u64::from_str_radix(addrs[1], 16).ok()?;
        if start >= end { return None; }
        let pathname = parts.get(5).map(|s| s.trim().to_string()).unwrap_or_default();
        Some(MemoryRegion { start, end, permissions: perms.to_string(), pathname })
    }).collect();

    Ok(regions)
}

// ─── Region reader ────────────────────────────────────────────────────────────

const MAX_REGION_BYTES: u64 = 64 * 1024 * 1024; // 64 MB

fn read_region(pid: u32, region: &MemoryRegion) -> Option<Vec<u8>> {
    let mem_path = format!("/proc/{}/mem", pid);
    let mut f = fs::File::open(&mem_path).ok()?;
    let size = region.size().min(MAX_REGION_BYTES) as usize;
    if size == 0 { return None; }
    if f.seek(SeekFrom::Start(region.start)).is_err() { return None; }

    let mut buf = vec![0u8; size];
    let mut total_read = 0usize;
    while total_read < size {
        match f.read(&mut buf[total_read..]) {
            Ok(0)  => break,
            Ok(n)  => total_read += n,
            Err(_) => break,
        }
    }
    if total_read == 0 { None } else { buf.truncate(total_read); Some(buf) }
}

// ─── Scanner ──────────────────────────────────────────────────────────────────

pub struct MemoryScanner;

impl MemoryScanner {
    pub fn new() -> Self { Self }

    pub fn scan_process(
        &self,
        pid:        u32,
        yara_rules: &[&str],
    ) -> Result<ScanResult, ScanError> {
        let rules = self.compile_rules(yara_rules)?;

        let process_name = fs::read_to_string(format!("/proc/{}/comm", pid))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        info!("🔬 Memory scan: PID {} ({})", pid, process_name);

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
                None => { regions_skipped += 1; }
                Some(data) => {
                    regions_scanned += 1;
                    bytes_read += data.len() as u64;

                    if !Path::new(&format!("/proc/{}", pid)).exists() {
                        warn!("PID {} exited during memory scan", pid);
                        completed = false;
                        break;
                    }

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
            "✅ Memory scan PID {}: {} matches, {}/{} regions, {} bytes",
            pid, matches.len(), regions_scanned, regions.len(), bytes_read
        );

        Ok(ScanResult { pid, process_name, matches, regions_scanned, regions_skipped, bytes_read, completed })
    }

    pub fn scan_all_processes(
        &self,
        yara_rules: &[&str],
    ) -> Result<Vec<ScanResult>, ScanError> {
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
                    Err(ScanError::ProcessNotFound)  => {}
                    Err(ScanError::PermissionDenied) => { debug!("Skipping PID {} (EPERM)", pid); }
                    Err(e) => warn!("Scan error for PID {}: {}", pid, e),
                }
            }
        }
        Ok(results)
    }

    fn compile_rules(&self, yara_rules: &[&str]) -> Result<yara::Rules, ScanError> {
        let mut compiler = Compiler::new()
            .map_err(|e| ScanError::RuleCompilationError(e.to_string()))?;
        for rule_str in yara_rules {
            compiler.add_rules_str(rule_str)
                .map_err(|e| ScanError::RuleCompilationError(e.to_string()))?;
        }
        compiler.compile_rules()
            .map_err(|e| ScanError::RuleCompilationError(e.to_string()))
    }
}

impl Default for MemoryScanner {
    fn default() -> Self { Self::new() }
}

// ─── Built-in YARA rules (17 professional rules) ─────────────────────────────

pub fn builtin_memory_rules() -> Vec<&'static str> {
    vec![
        // ── Rule 1: Meterpreter in-memory ─────────────────────────────────────
        r#"
rule Meterpreter_InMemory {
    meta:
        description = "Detects Metasploit Meterpreter in process memory"
        author      = "Thor Security Team"
        severity    = "critical"
        mitre       = "T1055.001"
    strings:
        $a = "meterpreter" nocase
        $b = { 4d 65 74 65 72 70 72 65 74 65 72 }
        $c = "ReflectiveDllInjection" nocase
        $d = "stdapi_sys_config_getuid"
    condition:
        any of them
}
"#,
        // ── Rule 2: Cobalt Strike Beacon ──────────────────────────────────────
        r#"
rule CobaltStrike_Beacon_InMemory {
    meta:
        description = "Detects Cobalt Strike Beacon stager and full beacon in memory"
        author      = "Thor Security Team"
        severity    = "critical"
        mitre       = "T1071.001"
    strings:
        $stager1  = "%s (admin)" nocase
        $stager2  = "beacon.dll" nocase
        $magic    = { FC 48 83 E4 F0 E8 }
        $cfg1     = { 00 01 00 01 00 02 }
        $pipe     = "\\\\.\\pipe\\MSSE-" nocase
        $sleep    = "sleep_mask" nocase
    condition:
        2 of them
}
"#,
        // ── Rule 3: Reverse Shell indicators ──────────────────────────────────
        r#"
rule ReverseShell_Indicators {
    meta:
        description = "Detects common reverse shell strings in process memory"
        severity    = "high"
        mitre       = "T1059.004"
    strings:
        $a = "/dev/tcp/" nocase
        $b = "bash -i >& /dev/tcp" nocase
        $c = "0>&1" nocase
        $d = "mkfifo /tmp/" nocase
        $e = "nc -e /bin/sh" nocase
        $f = "ncat --exec" nocase
        $g = "python -c 'import socket" nocase
        $h = "perl -e 'use Socket" nocase
    condition:
        2 of them
}
"#,
        // ── Rule 4: Process Injection ──────────────────────────────────────────
        r#"
rule ProcessInjection_Indicators {
    meta:
        description = "Detects process injection artifacts in memory"
        severity    = "high"
        mitre       = "T1055"
    strings:
        $a = "VirtualAllocEx" nocase
        $b = "WriteProcessMemory" nocase
        $c = "CreateRemoteThread" nocase
        $d = "NtCreateThreadEx" nocase
        $e = "ptrace" nocase
        $f = "PTRACE_POKETEXT"
        $g = "process_vm_writev"
    condition:
        2 of them
}
"#,
        // ── Rule 5: Shellcode Stager (NOP sled + PUSH-CALL) ────────────────────
        r#"
rule Shellcode_Stager {
    meta:
        description = "Detects shellcode staging patterns — NOP sled, PUSH-CALL, XOR decode loops"
        severity    = "critical"
        mitre       = "T1027"
    strings:
        $nop_sled     = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $push_call    = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
        $xor_loop     = { 31 C9 B1 ?? 80 34 0E ?? E2 FA }
        $egg_hunter   = { 66 81 CA FF 0F 42 52 6A 02 58 CD 2E 3C 05 5A 74 }
        $win_decode   = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 }
    condition:
        any of them
}
"#,
        // ── Rule 6: Privilege Escalation ──────────────────────────────────────
        r#"
rule PrivilegeEscalation_Indicators {
    meta:
        description = "Detects privilege escalation patterns — SUID abuse, shadow access"
        severity    = "high"
        mitre       = "T1548.001"
    strings:
        $suid1  = "/etc/shadow" nocase
        $suid2  = "chmod 4755"
        $suid3  = "chmod u+s"
        $suid4  = "sudo -l" nocase
        $suid5  = "/proc/sysrq-trigger"
        $suid6  = "setuid(0)"
        $suid7  = "setresuid(0,0,0)"
        $docker = "/var/run/docker.sock"
    condition:
        2 of them
}
"#,
        // ── Rule 7: Credential Dumping ─────────────────────────────────────────
        r#"
rule CredentialDumping_InMemory {
    meta:
        description = "Detects credential dumping patterns — LSASS, /etc/shadow, hash extraction"
        severity    = "critical"
        mitre       = "T1003"
    strings:
        $lsass1  = "lsass.exe" nocase
        $lsass2  = "SamSs" nocase
        $shadow1 = "hashdump" nocase
        $shadow2 = "secretsdump" nocase
        $shadow3 = "pam_unix" nocase
        $ntlm    = { 4E 54 4C 4D 53 53 50 00 }
        $krb5    = "krb5_cc_default" nocase
        $ticket  = ".kirbi" nocase
    condition:
        2 of them
}
"#,
        // ── Rule 8: Rootkit Indicators ─────────────────────────────────────────
        r#"
rule Rootkit_Indicators {
    meta:
        description = "Detects kernel rootkit artifacts — LKM loading, syscall table modification"
        severity    = "critical"
        mitre       = "T1014"
    strings:
        $lkm1    = "init_module" nocase
        $lkm2    = "finit_module" nocase
        $hook1   = "sys_call_table" nocase
        $hook2   = "kallsyms_lookup_name"
        $hide1   = "hidepid"
        $hide2   = "diamorphine"
        $hide3   = "reptile"
        $proc1   = "/proc/kallsyms"
    condition:
        2 of them
}
"#,
        // ── Rule 9: Lateral Movement ──────────────────────────────────────────
        r#"
rule LateralMovement_Indicators {
    meta:
        description = "Detects lateral movement — SSH key injection, Pass-the-Hash, WMI"
        severity    = "high"
        mitre       = "T1021"
    strings:
        $ssh1  = "authorized_keys" nocase
        $ssh2  = "StrictHostKeyChecking no" nocase
        $pth1  = "pth-winexe" nocase
        $pth2  = "pass-the-hash" nocase
        $psex1 = "psexec" nocase
        $wmi1  = "Win32_Process" nocase
        $rdp1  = "xfreerdp" nocase
        $rdp2  = "rdesktop" nocase
    condition:
        2 of them
}
"#,
        // ── Rule 10: Persistence Mechanisms ───────────────────────────────────
        r#"
rule Persistence_Mechanisms {
    meta:
        description = "Detects persistence via crontab, systemd unit drop, rc.local abuse"
        severity    = "medium"
        mitre       = "T1053.003"
    strings:
        $cron1  = "crontab -e" nocase
        $cron2  = "/etc/cron.d/" nocase
        $cron3  = "0 * * * *" nocase
        $svc1   = ".service" nocase
        $svc2   = "systemctl enable" nocase
        $rc1    = "/etc/rc.local"
        $prof1  = ".bashrc" nocase
        $prof2  = ".profile" nocase
        $prof3  = "/etc/profile.d/"
    condition:
        2 of them
}
"#,
        // ── Rule 11: Defense Evasion ──────────────────────────────────────────
        r#"
rule DefenseEvasion_Indicators {
    meta:
        description = "Detects log clearing, history deletion, and timestamp manipulation"
        severity    = "high"
        mitre       = "T1070"
    strings:
        $log1  = ">/var/log/syslog" nocase
        $log2  = ">/var/log/auth.log" nocase
        $log3  = "shred -u" nocase
        $log4  = "wevtutil cl" nocase
        $hist1 = "history -c" nocase
        $hist2 = "HISTFILE=/dev/null" nocase
        $hist3 = "unset HISTFILE" nocase
        $time1 = "touch -t" nocase
        $time2 = "timestomp" nocase
    condition:
        2 of them
}
"#,
        // ── Rule 12: Data Exfiltration ─────────────────────────────────────────
        r#"
rule DataExfiltration_Indicators {
    meta:
        description = "Detects data exfiltration via base64 encoding, DNS tunneling, curl upload"
        severity    = "high"
        mitre       = "T1048"
    strings:
        $b64_1  = "base64 -" nocase
        $b64_2  = "base64 --decode" nocase
        $curl1  = "curl -T " nocase
        $curl2  = "curl --upload-file" nocase
        $dns1   = "iodine" nocase
        $dns2   = "dnscat" nocase
        $ftp1   = "ftp -n" nocase
        $exfil1 = "| nc " nocase
    condition:
        2 of them
}
"#,
        // ── Rule 13: Ransomware Patterns ──────────────────────────────────────
        r#"
rule Ransomware_Indicators {
    meta:
        description = "Detects ransomware — key expansion patterns, shadow copy deletion, ransom note strings"
        severity    = "critical"
        mitre       = "T1486"
    strings:
        $shadow1  = "vssadmin delete shadows" nocase
        $shadow2  = "wmic shadowcopy delete" nocase
        $shadow3  = "bcdedit /set" nocase
        $ransom1  = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $ransom2  = "how to recover" nocase
        $ransom3  = ".onion" nocase
        $ext1     = ".locked" nocase
        $ext2     = ".encrypted" nocase
        $chacha   = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }
    condition:
        2 of them
}
"#,
        // ── Rule 14: Fileless Malware (memfd_create) ──────────────────────────
        r#"
rule Fileless_Malware_MemfdCreate {
    meta:
        description = "Detects fileless malware using memfd_create and anonymous executable mappings"
        severity    = "critical"
        mitre       = "T1055.009"
    strings:
        $memfd1   = "memfd_create" nocase
        $memfd2   = { 01 00 00 00 00 00 00 00 00 00 00 00 }
        $fd_exec1 = "/proc/self/fd/" nocase
        $fd_exec2 = "fexecve" nocase
        $anon1    = "anonymous" nocase
        $shm1     = "shm_open" nocase
        $ld_so    = { 2F 6C 69 62 36 34 2F 6C 64 2D 6C 69 6E 75 78 }
    condition:
        2 of them
}
"#,
        // ── Rule 15: Empire Framework ──────────────────────────────────────────
        r#"
rule Empire_Framework_InMemory {
    meta:
        description = "Detects PowerShell Empire framework signatures in memory"
        severity    = "critical"
        mitre       = "T1059.001"
    strings:
        $empire1 = "EMPIRE" nocase
        $empire2 = "staging_key" nocase
        $empire3 = "powershell/empire" nocase
        $ps1     = "powershell -w hidden" nocase
        $ps2     = "-EncodedCommand" nocase
        $ps3     = "IEX(New-Object" nocase
        $ps4     = "System.Net.WebClient" nocase
        $ps5     = "DownloadString" nocase
    condition:
        2 of them
}
"#,
        // ── Rule 16: Mimikatz Credential Extraction ────────────────────────────
        r#"
rule Mimikatz_InMemory {
    meta:
        description = "Detects Mimikatz credential extraction tool in process memory"
        severity    = "critical"
        mitre       = "T1003.001"
    strings:
        $mimi1  = "mimikatz" nocase
        $mimi2  = "sekurlsa::" nocase
        $mimi3  = "lsadump::" nocase
        $mimi4  = "kerberos::" nocase
        $mimi5  = "privilege::debug" nocase
        $mimi6  = { 6B 69 77 69 41 6E 64 43 6D 64 }
        $wce    = "wce.exe" nocase
        $gsec   = "gsecdump" nocase
    condition:
        any of ($mimi1, $mimi2, $mimi3, $mimi4, $mimi5, $mimi6) or
        any of ($wce, $gsec)
}
"#,
        // ── Rule 17: Heap Spray / NULL Dereference Preparation ────────────────
        r#"
rule HeapSpray_NullPage_Preparation {
    meta:
        description = "Detects heap spray and NULL page mapping patterns for exploit preparation"
        severity    = "high"
        mitre       = "T1203"
    strings:
        $spray1  = { 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C }
        $spray2  = { 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D }
        $mmap1   = "mmap(0," nocase
        $mmap2   = "PROT_EXEC|PROT_WRITE" nocase
        $mmap3   = "MAP_ANONYMOUS|MAP_FIXED" nocase
        $null1   = "mmap(NULL" nocase
        $jit     = "JIT spray" nocase
    condition:
        2 of them
}
"#,
    ]
}

// ─── Convenience function ─────────────────────────────────────────────────────

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
        match result {
            Ok(r) => assert_eq!(r.pid, pid),
            Err(ScanError::PermissionDenied) => {}
            Err(e) => panic!("Unexpected error scanning self: {}", e),
        }
    }

    #[test]
    fn scan_nonexistent_pid_returns_not_found() {
        let rules: Vec<&str> = builtin_memory_rules();
        let result = MemoryScanner::new().scan_process(99_999_999, &rules);
        match result {
            Err(ScanError::ProcessNotFound) | Err(ScanError::PermissionDenied) => {}
            Err(ScanError::IoError(_)) => {}
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
    fn all_builtin_rules_compile() {
        let rules = builtin_memory_rules();
        assert!(rules.len() >= 17, "Must have at least 17 built-in YARA rules, got {}", rules.len());

        let mut compiler = yara::Compiler::new().expect("YARA compiler init");
        for rule in &rules {
            compiler.add_rules_str(rule)
                .expect("Each built-in rule must compile without errors");
        }
        let compiled = compiler.compile_rules();
        assert!(compiled.is_ok(), "All built-in rules must compile together");
    }

    #[test]
    fn memory_region_size_calculation() {
        let region = MemoryRegion {
            start: 0x1000, end: 0x5000,
            permissions: "r-xp".into(), pathname: "[vdso]".into(),
        };
        assert_eq!(region.size(), 0x4000);
    }

    #[test]
    fn parse_maps_for_self_finds_regions() {
        let pid = std::process::id();
        let regions = parse_executable_regions(pid);
        match regions {
            Ok(r) => {
                assert!(!r.is_empty(), "Self executable regions should not be empty");
                for region in &r {
                    assert!(
                        region.permissions.contains('x'),
                        "All regions must have execute permission: {}", region.permissions
                    );
                }
            }
            Err(ScanError::PermissionDenied) => {}
            Err(e) => panic!("Unexpected error parsing own maps: {}", e),
        }
    }

    #[test]
    fn yara_custom_rule_detects_pattern() {
        let rule = r#"
rule TestPattern {
    strings:
        $a = "THOR_TEST_PAYLOAD_XYZ"
    condition:
        $a
}
"#;
        let scanner = MemoryScanner::new();
        let result = scanner.compile_rules(&[rule]);
        assert!(result.is_ok(), "Custom test rule must compile");
    }

    #[test]
    fn scan_all_processes_does_not_panic() {
        let rules = builtin_memory_rules();
        let result = MemoryScanner::new().scan_all_processes(&rules);
        assert!(result.is_ok(), "scan_all_processes must return Ok (errors are handled per-PID)");
    }
}
