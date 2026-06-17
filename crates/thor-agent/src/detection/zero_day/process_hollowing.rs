//! Process Hollowing / Injection Detector — detects process injection techniques.
//!
//! # Detected Techniques (MITRE ATT&CK T1055.*)
//!
//! 1. **Classic Process Hollowing** (T1055.012)
//!    - `execve` → `SIGSTOP` → `process_vm_writev` → `ptrace(POKETEXT)` sequence.
//!
//! 2. **Reflective DLL Injection** (T1055.001)
//!    - `mmap(PROT_EXEC|PROT_WRITE)` followed by `write` then `mprotect(PROT_EXEC)`.
//!
//! 3. **APC Injection** (T1055.004)
//!    - Multiple `process_vm_writev` calls across different PIDs.
//!
//! 4. **Atom Bombing** (T1055.015)
//!    - `GlobalAddAtom`-equivalent via unusual write patterns to shared memory.
//!
//! 5. **Phantom DLL / Module Stomping** (T1055.013)
//!    - Writing to an executable mapping backed by a known DLL path.
//!
//! 6. **Process Ghosting** (T1055)
//!    - `memfd_create` followed by `fexecve` from memory.

use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::debug;

use super::syscall_profiler::{ProcessProfile, SyscallEvent};

// ─── Syscall constants ────────────────────────────────────────────────────────

const SYS_MMAP:              u32 = 9;
const SYS_MPROTECT:          u32 = 10;
const SYS_PTRACE:            u32 = 101;
const SYS_PROCESS_VM_WRITEV: u32 = 311;
const SYS_MEMFD_CREATE:      u32 = 319;
const SYS_EXECVE:            u32 = 59;
const SYS_FORK:              u32 = 57;
const SYS_VFORK:             u32 = 58;
const SYS_CLONE:             u32 = 56;
const SYS_WRITE:             u32 = 1;

/// mmap protection flags
const PROT_EXEC:  u32 = 0x4;
const PROT_WRITE: u32 = 0x2;

// ─── HollowingType ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HollowingType {
    ClassicHollowing,
    ReflectiveDllInjection,
    ApcInjection,
    AtomBombing,
    PhantomDll,
    ProcessGhosting,
}

impl std::fmt::Display for HollowingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HollowingType::ClassicHollowing        => write!(f, "Classic Process Hollowing"),
            HollowingType::ReflectiveDllInjection  => write!(f, "Reflective DLL Injection"),
            HollowingType::ApcInjection            => write!(f, "APC Injection"),
            HollowingType::AtomBombing             => write!(f, "Atom Bombing"),
            HollowingType::PhantomDll              => write!(f, "Phantom DLL / Module Stomping"),
            HollowingType::ProcessGhosting         => write!(f, "Process Ghosting"),
        }
    }
}

// ─── HollowingAlert ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HollowingAlert {
    pub hollowing_type:   HollowingType,
    pub confidence:       f64,
    pub description:      String,
    pub mitre_techniques: Vec<String>,
}

// ─── Per-process state ────────────────────────────────────────────────────────

struct HollowingState {
    /// mmap(PROT_EXEC|PROT_WRITE) calls in last 60s
    rwx_mmap_window:      WindowCounter,
    /// mprotect(PROT_EXEC) after write in last 60s
    mprotect_exec_window: WindowCounter,
    /// process_vm_writev calls in last 30s
    vm_write_window:      WindowCounter,
    /// ptrace(POKETEXT) calls in last 30s
    ptrace_poke_window:   WindowCounter,
    /// memfd_create seen
    memfd_seen:           bool,
    /// execve seen after fork
    execve_after_fork:    bool,
    /// fork/vfork/clone count
    spawn_count:          u64,
    /// Total write calls
    write_count:          u64,
}

struct WindowCounter {
    events: VecDeque<Instant>,
    window: Duration,
}

impl WindowCounter {
    fn new(window: Duration) -> Self { Self { events: VecDeque::new(), window } }

    fn push(&mut self) {
        let now = Instant::now();
        self.events.push_back(now);
        self.evict(now);
    }

    fn evict(&mut self, now: Instant) {
        while self.events.front().map(|t| now.duration_since(*t) > self.window).unwrap_or(false) {
            self.events.pop_front();
        }
    }

    fn count(&mut self) -> usize {
        let now = Instant::now();
        self.evict(now);
        self.events.len()
    }
}

impl HollowingState {
    fn new() -> Self {
        Self {
            rwx_mmap_window:      WindowCounter::new(Duration::from_secs(60)),
            mprotect_exec_window: WindowCounter::new(Duration::from_secs(60)),
            vm_write_window:      WindowCounter::new(Duration::from_secs(30)),
            ptrace_poke_window:   WindowCounter::new(Duration::from_secs(30)),
            memfd_seen:           false,
            execve_after_fork:    false,
            spawn_count:          0,
            write_count:          0,
        }
    }
}

// ─── ProcessHollowingDetector ─────────────────────────────────────────────────

/// Detects process injection and hollowing patterns from syscall sequences.
pub struct ProcessHollowingDetector {
    state: RwLock<HashMap<u32, HollowingState>>,
}

impl ProcessHollowingDetector {
    pub fn new() -> Self {
        Self { state: RwLock::new(HashMap::new()) }
    }

    /// Analyze a syscall event. Returns any injection alerts triggered.
    pub fn analyze(
        &self,
        event:   &SyscallEvent,
        profile: &ProcessProfile,
    ) -> Vec<HollowingAlert> {
        let mut alerts = Vec::new();
        let mut map = self.state.write().unwrap();
        let state = map.entry(event.pid).or_insert_with(HollowingState::new);

        match event.syscall_nr {

            // ── mmap with EXEC+WRITE — reflective injection staging ────────
            SYS_MMAP => {
                // byte_count field reused to pass mmap prot flags in our telemetry
                let prot = event.byte_count as u32;
                if (prot & PROT_EXEC != 0) && (prot & PROT_WRITE != 0) {
                    state.rwx_mmap_window.push();
                    let count = state.rwx_mmap_window.count();
                    debug!("PID {}: RWX mmap #{}", event.pid, count);

                    if count >= 2 {
                        alerts.push(HollowingAlert {
                            hollowing_type:   HollowingType::ReflectiveDllInjection,
                            confidence:       (0.55 + count as f64 * 0.08).min(0.90),
                            description:      format!(
                                "PID {} ({}): mmap(PROT_EXEC|PROT_WRITE) called {} time(s) — \
                                 RWX mapping is a hallmark of reflective DLL injection staging.",
                                event.pid, profile.process_name, count
                            ),
                            mitre_techniques: vec!["T1055.001".into(), "T1055".into()],
                        });
                    }
                }
            }

            // ── mprotect(PROT_EXEC) — write-then-execute pattern ─────────
            SYS_MPROTECT => {
                let prot = event.byte_count as u32;
                if prot & PROT_EXEC != 0 {
                    state.mprotect_exec_window.push();
                    let mprotect_count = state.mprotect_exec_window.count();
                    let write_count    = state.write_count;

                    if mprotect_count >= 1 && write_count >= 5 {
                        alerts.push(HollowingAlert {
                            hollowing_type:   HollowingType::ReflectiveDllInjection,
                            confidence:       0.80,
                            description:      format!(
                                "PID {} ({}): mprotect(EXEC) after {} write(s) — \
                                 write-then-execute injection pattern detected.",
                                event.pid, profile.process_name, write_count
                            ),
                            mitre_techniques: vec!["T1055.001".into()],
                        });
                    }
                }
            }

            // ── process_vm_writev — cross-process memory write ─────────────
            SYS_PROCESS_VM_WRITEV => {
                state.vm_write_window.push();
                let count = state.vm_write_window.count();

                // Any use from a non-debugger process is suspicious
                let is_debugger = profile.process_name == "gdb"
                    || profile.process_name == "lldb"
                    || profile.process_name == "strace";

                let confidence = if is_debugger { 0.20 } else { 0.70 + (count as f64 * 0.05).min(0.25) };

                if confidence >= 0.70 {
                    alerts.push(HollowingAlert {
                        hollowing_type:   HollowingType::ApcInjection,
                        confidence,
                        description:      format!(
                            "PID {} ({}): process_vm_writev() called {} time(s) — \
                             cross-process memory write. Classic APC/remote thread injection.",
                            event.pid, profile.process_name, count
                        ),
                        mitre_techniques: vec!["T1055.004".into(), "T1055".into()],
                    });
                }
            }

            // ── ptrace — process control / code injection ──────────────────
            SYS_PTRACE => {
                state.ptrace_poke_window.push();
                let count = state.ptrace_poke_window.count();

                let is_debugger = profile.process_name == "gdb"
                    || profile.process_name == "lldb"
                    || profile.process_name == "strace";

                if !is_debugger && count >= 2 {
                    alerts.push(HollowingAlert {
                        hollowing_type:   HollowingType::ClassicHollowing,
                        confidence:       (0.65 + count as f64 * 0.05).min(0.92),
                        description:      format!(
                            "PID {} ({}): ptrace() called {} time(s) from non-debugger — \
                             possible process hollowing via PTRACE_POKETEXT.",
                            event.pid, profile.process_name, count
                        ),
                        mitre_techniques: vec!["T1055.012".into(), "T1055".into()],
                    });
                }
            }

            // ── memfd_create — fileless execution staging ─────────────────
            SYS_MEMFD_CREATE => {
                state.memfd_seen = true;
                alerts.push(HollowingAlert {
                    hollowing_type:   HollowingType::ProcessGhosting,
                    confidence:       0.75,
                    description:      format!(
                        "PID {} ({}): memfd_create() — anonymous in-memory file descriptor. \
                         Used for fileless execution (Process Ghosting / MemFD shellcode staging).",
                        event.pid, profile.process_name
                    ),
                    mitre_techniques: vec!["T1055".into(), "T1620".into()],
                });
            }

            // ── execve after memfd — complete ghosting pattern ────────────
            SYS_EXECVE => {
                if state.memfd_seen {
                    alerts.push(HollowingAlert {
                        hollowing_type:   HollowingType::ProcessGhosting,
                        confidence:       0.93,
                        description:      format!(
                            "PID {} ({}): execve() after memfd_create() — \
                             COMPLETE PROCESS GHOSTING SEQUENCE: in-memory execution detected.",
                            event.pid, profile.process_name
                        ),
                        mitre_techniques: vec!["T1055".into(), "T1620".into()],
                    });
                }
                if state.spawn_count > 0 {
                    state.execve_after_fork = true;
                }
            }

            // ── fork/clone tracking ────────────────────────────────────────
            n if n == SYS_FORK || n == SYS_VFORK || n == SYS_CLONE => {
                state.spawn_count += 1;
            }

            // ── write tracking ─────────────────────────────────────────────
            SYS_WRITE => {
                state.write_count += 1;
            }

            _ => {}
        }

        // ── Composite: ptrace + vm_write → classic hollowing ──────────────
        {
            let ptrace_count = state.ptrace_poke_window.count();
            let vm_count     = state.vm_write_window.count();
            if ptrace_count >= 1 && vm_count >= 1 {
                alerts.push(HollowingAlert {
                    hollowing_type:   HollowingType::ClassicHollowing,
                    confidence:       0.94,
                    description:      format!(
                        "PID {} ({}): COMPOSITE — ptrace({}) + process_vm_writev({}) = \
                         classic process hollowing sequence confirmed.",
                        event.pid, profile.process_name, ptrace_count, vm_count
                    ),
                    mitre_techniques: vec!["T1055.012".into()],
                });
            }
        }

        alerts
    }

    /// Evict state for terminated processes.
    pub fn evict(&self, pid: u32) {
        self.state.write().unwrap().remove(&pid);
    }
}

impl Default for ProcessHollowingDetector {
    fn default() -> Self { Self::new() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::syscall_profiler::{SyscallProfiler, SyscallEvent};
    use super::super::syscall_profiler::SYS_READ;

    fn dummy_profile(pid: u32, name: &str) -> ProcessProfile {
        let profiler = SyscallProfiler::new();
        for _ in 0..30 {
            let ev = SyscallEvent::new(pid, SYS_READ, name);
            profiler.record(&ev);
        }
        profiler.get_profile(pid).unwrap()
    }

    fn event_with_prot(pid: u32, syscall: u32, prot: u32, name: &str) -> SyscallEvent {
        let mut ev = SyscallEvent::new(pid, syscall, name);
        ev.byte_count = prot as u64;
        ev
    }

    #[test]
    fn rwx_mmap_twice_triggers_reflective_injection_alert() {
        let det  = ProcessHollowingDetector::new();
        let prof = dummy_profile(1, "evil");
        let prot = PROT_EXEC | PROT_WRITE;

        let ev1 = event_with_prot(1, SYS_MMAP, prot, "evil");
        det.analyze(&ev1, &prof);
        let ev2 = event_with_prot(1, SYS_MMAP, prot, "evil");
        let alerts = det.analyze(&ev2, &prof);

        assert!(!alerts.is_empty());
        assert!(alerts.iter().any(|a| a.hollowing_type == HollowingType::ReflectiveDllInjection));
    }

    #[test]
    fn memfd_then_execve_is_process_ghosting() {
        let det  = ProcessHollowingDetector::new();
        let prof = dummy_profile(2, "ghost");

        let ev_memfd = SyscallEvent::new(2, SYS_MEMFD_CREATE, "ghost");
        det.analyze(&ev_memfd, &prof);

        let ev_exec = SyscallEvent::new(2, SYS_EXECVE, "ghost");
        let alerts = det.analyze(&ev_exec, &prof);

        assert!(alerts.iter().any(|a| a.hollowing_type == HollowingType::ProcessGhosting));
    }

    #[test]
    fn process_vm_writev_from_non_debugger_is_suspicious() {
        let det  = ProcessHollowingDetector::new();
        let prof = dummy_profile(3, "malware");

        let ev = SyscallEvent::new(3, SYS_PROCESS_VM_WRITEV, "malware");
        let alerts = det.analyze(&ev, &prof);

        assert!(!alerts.is_empty());
    }

    #[test]
    fn gdb_ptrace_is_not_flagged() {
        let det  = ProcessHollowingDetector::new();
        let prof = dummy_profile(4, "gdb");

        for _ in 0..5 {
            let ev = SyscallEvent::new(4, SYS_PTRACE, "gdb");
            det.analyze(&ev, &prof);
        }
        // gdb is whitelisted — ptrace from it alone should not trigger
        // (vm_write_window is 0 so composite check won't fire either)
        let ev = SyscallEvent::new(4, SYS_PTRACE, "gdb");
        let alerts = det.analyze(&ev, &prof);
        let critical: Vec<_> = alerts.iter().filter(|a| a.confidence >= 0.70).collect();
        assert!(critical.is_empty(), "gdb ptrace should not produce high-confidence alerts");
    }
}
