//! Syscall Profiler — builds per-process behavioral profiles from eBPF events.
//!
//! The profiler maintains a sliding-window histogram of syscall calls per
//! process.  Each `SyscallEvent` (produced either by the eBPF ring buffer or
//! a synthetic source in tests) updates the full 24-dimensional feature space
//! used by the AnomalyEngine and all sub-detectors.
//!
//! # New in v2
//! * Tracking for bpf(), io_uring, userfaultfd, pidfd_open (2022-2024 attack vectors)
//! * Cross-process write counter (process_vm_writev / ptrace)
//! * Privilege syscall ratio
//! * DashMap for lock-free concurrent access under high event load

use std::time::{Duration, Instant};
use std::collections::VecDeque;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::debug;

// ─── Syscall numbers (Linux x86-64) ──────────────────────────────────────────

pub const SYS_READ:             u32 = 0;
pub const SYS_WRITE:            u32 = 1;
pub const SYS_OPEN:             u32 = 2;
pub const SYS_MMAP:             u32 = 9;
pub const SYS_MPROTECT:         u32 = 10;
pub const SYS_MUNMAP:           u32 = 11;
pub const SYS_BRK:              u32 = 12;
pub const SYS_IOCTL:            u32 = 16;
pub const SYS_SENDMSG:          u32 = 46;
pub const SYS_RECVMSG:          u32 = 47;
pub const SYS_FORK:             u32 = 57;
pub const SYS_VFORK:            u32 = 58;
pub const SYS_EXECVE:           u32 = 59;
pub const SYS_SOCKET:           u32 = 41;
pub const SYS_CONNECT:          u32 = 42;
pub const SYS_CLONE:            u32 = 56;
pub const SYS_PTRACE:           u32 = 101;
pub const SYS_INIT_MODULE:      u32 = 175;
pub const SYS_FINIT_MODULE:     u32 = 313;
pub const SYS_CREATE_MODULE:    u32 = 174;
pub const SYS_PROCESS_VM_READV: u32 = 310;
pub const SYS_PROCESS_VM_WRITEV:u32 = 311;
pub const SYS_MEMFD_CREATE:     u32 = 319;

// ── New critical syscalls (2022-2024 attack vectors) ─────────────────────────
pub const SYS_BPF:              u32 = 321;  // eBPF rootkits
pub const SYS_IO_URING_SETUP:   u32 = 425;  // io_uring privilege escalation
pub const SYS_IO_URING_ENTER:   u32 = 426;  // io_uring kernel exploit
pub const SYS_IO_URING_REGISTER:u32 = 427;  // io_uring registration
pub const SYS_USERFAULTFD:      u32 = 323;  // userfaultfd kernel exploit
pub const SYS_PIDFD_OPEN:       u32 = 434;  // pidfd cross-process operations
pub const SYS_PIDFD_SEND_SIGNAL:u32 = 424;  // pidfd signal injection
pub const SYS_PERF_EVENT_OPEN:  u32 = 298;  // Spectre/Meltdown side-channel
pub const SYS_SETUID:           u32 = 105;  // privilege escalation
pub const SYS_SETGID:           u32 = 106;
pub const SYS_SETRESUID:        u32 = 117;
pub const SYS_SETRESGID:        u32 = 119;
pub const SYS_CAPSET:           u32 = 126;  // capability manipulation
pub const SYS_UNSHARE:          u32 = 272;  // container escape
pub const SYS_SETNS:            u32 = 308;  // namespace escape
pub const SYS_PIVOT_ROOT:       u32 = 155;  // container escape
pub const SYS_MOUNT:            u32 = 165;  // container escape
pub const SYS_KEYCTL:           u32 = 250;  // kernel keyring theft
pub const SYS_PRCTL:            u32 = 157;  // security disablement
pub const SYS_SHMGET:           u32 = 29;   // shared memory (atom bombing)
pub const SYS_SHMAT:            u32 = 30;   // shared memory attach

/// Set of privilege-escalation / high-risk syscall numbers for fast lookup.
const PRIV_SYSCALLS: &[u32] = &[
    SYS_PTRACE, SYS_INIT_MODULE, SYS_FINIT_MODULE, SYS_CREATE_MODULE,
    SYS_PROCESS_VM_READV, SYS_PROCESS_VM_WRITEV, SYS_MEMFD_CREATE,
    SYS_BPF, SYS_IO_URING_SETUP, SYS_IO_URING_ENTER, SYS_IO_URING_REGISTER,
    SYS_USERFAULTFD, SYS_PIDFD_OPEN, SYS_PIDFD_SEND_SIGNAL,
    SYS_SETUID, SYS_SETGID, SYS_SETRESUID, SYS_SETRESGID,
    SYS_CAPSET, SYS_UNSHARE, SYS_SETNS, SYS_PIVOT_ROOT, SYS_KEYCTL,
];

// ─── SyscallEvent ─────────────────────────────────────────────────────────────

/// A single syscall event produced by the eBPF probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// Process ID that made the call.
    pub pid:        u32,
    /// Thread group ID.
    pub tgid:       u32,
    /// Syscall number (Linux x86-64).
    pub syscall_nr: u32,
    /// Return value (−errno on failure, otherwise syscall-specific).
    pub ret_val:    i64,
    /// Byte count for read/write/send/recv syscalls (0 otherwise).
    /// Also reused for mmap prot flags when syscall_nr == SYS_MMAP.
    pub byte_count: u64,
    /// Monotonic timestamp in nanoseconds (from ktime_get_ns()).
    pub ts_ns:      u64,
    /// Process name from task_comm (max 16 bytes, NUL-padded).
    pub comm:       String,
    /// UID of the calling process (0 = root).
    pub uid:        u32,
    /// Whether this is a kernel-space event.
    pub is_kernel:  bool,
}

impl SyscallEvent {
    pub fn new(pid: u32, syscall_nr: u32, comm: &str) -> Self {
        Self {
            pid,
            tgid:       pid,
            syscall_nr,
            ret_val:    0,
            byte_count: 0,
            ts_ns:      0,
            comm:       comm.to_string(),
            uid:        1000,
            is_kernel:  false,
        }
    }

    pub fn is_exec_event(&self) -> bool {
        matches!(self.syscall_nr,
            n if n == SYS_EXECVE || n == SYS_FORK || n == SYS_VFORK || n == SYS_CLONE)
    }

    pub fn is_memory_event(&self) -> bool {
        matches!(self.syscall_nr,
            n if n == SYS_MMAP || n == SYS_MPROTECT || n == SYS_BRK || n == SYS_MUNMAP)
    }

    pub fn is_dangerous(&self) -> bool {
        PRIV_SYSCALLS.contains(&self.syscall_nr)
    }

    /// Returns true if this syscall is a 2022-2024 generation attack vector.
    pub fn is_modern_attack_vector(&self) -> bool {
        matches!(self.syscall_nr,
            SYS_BPF | SYS_IO_URING_SETUP | SYS_IO_URING_ENTER |
            SYS_IO_URING_REGISTER | SYS_USERFAULTFD | SYS_PIDFD_OPEN |
            SYS_PIDFD_SEND_SIGNAL)
    }
}

// ─── ProcessProfile ───────────────────────────────────────────────────────────

/// Behavioral profile for a single process — 24-dimensional feature space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessProfile {
    pub pid:                     u32,
    pub process_name:            String,
    pub event_count:             u64,
    pub syscall_counts:          std::collections::HashMap<u32, u64>,
    pub unique_syscall_count:    usize,
    pub syscall_rate_ema:        f64,
    pub child_spawns:            u64,
    pub memory_alloc_events:     u64,
    pub total_network_bytes:     u64,
    pub write_entropy_estimate:  f64,
    pub dangerous_syscall_count: u64,
    // ── New tracking fields (v2) ──────────────────────────────────────────────
    /// bpf() syscall count — eBPF rootkit staging
    pub bpf_call_count:          u64,
    /// io_uring syscall count — kernel exploit vector
    pub io_uring_count:          u64,
    /// userfaultfd() count — kernel exploit via fault handler
    pub userfaultfd_count:       u64,
    /// pidfd_open + pidfd_send_signal — cross-process operations
    pub pidfd_count:             u64,
    /// mmap(PROT_EXEC) calls — shellcode staging
    pub mmap_exec_count:         u64,
    /// Total mmap calls
    pub mmap_total_count:        u64,
    /// process_vm_writev calls — cross-process memory writes
    pub cross_proc_write_count:  u64,
    /// ptrace calls
    pub ptrace_count:            u64,
    /// memfd_create calls — fileless execution
    pub memfd_count:             u64,
    /// setuid/setgid/setresuid/setresgid calls
    pub setuid_attempt_count:    u64,
    /// capset() calls
    pub cap_change_count:        u64,
    /// init_module/finit_module calls
    pub module_load_count:       u64,
    /// unshare/setns calls
    pub namespace_change_count:  u64,
    /// Privileged syscalls / total syscalls ratio (updated as EMA)
    pub priv_syscall_ratio_ema:  f64,
    /// Inter-event timing: coefficient of variation (low = beaconing)
    pub timing_cv:               f64,
    /// perf_event_open calls — side-channel
    pub perf_event_count:        u64,
    /// Observation window start.
    pub window_start:            Option<Instant>,
    pub last_event_ts:           Option<Instant>,
    /// Recent inter-event intervals (nanoseconds, capped at 128 entries)
    #[serde(skip)]
    pub recent_intervals:        VecDeque<u64>,
}

impl ProcessProfile {
    fn new(pid: u32, comm: &str) -> Self {
        Self {
            pid,
            process_name:            comm.to_string(),
            event_count:             0,
            syscall_counts:          std::collections::HashMap::new(),
            unique_syscall_count:    0,
            syscall_rate_ema:        0.0,
            child_spawns:            0,
            memory_alloc_events:     0,
            total_network_bytes:     0,
            write_entropy_estimate:  0.0,
            dangerous_syscall_count: 0,
            bpf_call_count:          0,
            io_uring_count:          0,
            userfaultfd_count:       0,
            pidfd_count:             0,
            mmap_exec_count:         0,
            mmap_total_count:        0,
            cross_proc_write_count:  0,
            ptrace_count:            0,
            memfd_count:             0,
            setuid_attempt_count:    0,
            cap_change_count:        0,
            module_load_count:       0,
            namespace_change_count:  0,
            priv_syscall_ratio_ema:  0.0,
            timing_cv:               1.0,
            perf_event_count:        0,
            window_start:            None,
            last_event_ts:           None,
            recent_intervals:        VecDeque::new(),
        }
    }

    fn update(&mut self, event: &SyscallEvent) {
        let now = Instant::now();

        if self.window_start.is_none() {
            self.window_start = Some(now);
        }

        self.event_count += 1;
        *self.syscall_counts.entry(event.syscall_nr).or_insert(0) += 1;
        self.unique_syscall_count = self.syscall_counts.len();

        // ── Timing ─────────────────────────────────────────────────────────
        if let Some(last) = self.last_event_ts {
            let dt_ns = now.duration_since(last).as_nanos() as u64;
            let dt_secs = dt_ns as f64 / 1_000_000_000.0;
            // EMA of syscall rate
            let inst_rate = if dt_secs > 1e-9 { 1.0 / dt_secs } else { 1.0 };
            self.syscall_rate_ema = 0.05 * inst_rate + 0.95 * self.syscall_rate_ema;
            // Record interval for timing analysis
            self.recent_intervals.push_back(dt_ns);
            if self.recent_intervals.len() > 128 {
                self.recent_intervals.pop_front();
            }
            // Update timing CV
            if self.recent_intervals.len() >= 16 {
                self.timing_cv = compute_cv(&self.recent_intervals);
            }
        }
        self.last_event_ts = Some(now);

        // ── Category tracking ──────────────────────────────────────────────
        if event.is_exec_event()   { self.child_spawns += 1; }
        if event.is_memory_event() { self.memory_alloc_events += 1; }
        if event.is_dangerous()    { self.dangerous_syscall_count += 1; }

        // ── New vector syscalls ────────────────────────────────────────────
        match event.syscall_nr {
            SYS_BPF => {
                self.bpf_call_count += 1;
            }
            SYS_IO_URING_SETUP | SYS_IO_URING_ENTER | SYS_IO_URING_REGISTER => {
                self.io_uring_count += 1;
            }
            SYS_USERFAULTFD => {
                self.userfaultfd_count += 1;
            }
            SYS_PIDFD_OPEN | SYS_PIDFD_SEND_SIGNAL => {
                self.pidfd_count += 1;
            }
            SYS_MMAP => {
                self.mmap_total_count += 1;
                let prot = event.byte_count as u32;
                if (prot & 0x4) != 0 { // PROT_EXEC
                    self.mmap_exec_count += 1;
                }
            }
            SYS_PROCESS_VM_WRITEV => {
                self.cross_proc_write_count += 1;
            }
            SYS_PTRACE => {
                self.ptrace_count += 1;
            }
            SYS_MEMFD_CREATE => {
                self.memfd_count += 1;
            }
            SYS_SETUID | SYS_SETGID | SYS_SETRESUID | SYS_SETRESGID => {
                self.setuid_attempt_count += 1;
            }
            SYS_CAPSET => {
                self.cap_change_count += 1;
            }
            SYS_INIT_MODULE | SYS_FINIT_MODULE => {
                self.module_load_count += 1;
            }
            SYS_UNSHARE | SYS_SETNS => {
                self.namespace_change_count += 1;
            }
            SYS_PERF_EVENT_OPEN => {
                self.perf_event_count += 1;
            }
            _ => {}
        }

        // ── Network bytes ──────────────────────────────────────────────────
        if matches!(event.syscall_nr,
            SYS_SENDMSG | SYS_RECVMSG | SYS_READ | SYS_WRITE)
            && event.byte_count > 0
        {
            self.total_network_bytes += event.byte_count;
        }

        // ── Write entropy (Shannon proxy via LSB distribution) ──────────────
        if event.syscall_nr == SYS_WRITE && event.byte_count > 0 {
            let lsb = (event.byte_count & 0xFF) as f64 / 255.0;
            self.write_entropy_estimate =
                0.1 * lsb + 0.9 * self.write_entropy_estimate;
        }

        // ── Privileged syscall ratio EMA ───────────────────────────────────
        let is_priv = if event.is_dangerous() { 1.0 } else { 0.0 };
        self.priv_syscall_ratio_ema =
            0.02 * is_priv + 0.98 * self.priv_syscall_ratio_ema;
    }

    pub fn window_secs(&self) -> f64 {
        match self.window_start {
            Some(start) => start.elapsed().as_secs_f64().max(1.0),
            None        => 1.0,
        }
    }

    pub fn child_spawn_rate(&self) -> f64 {
        self.child_spawns as f64 / self.window_secs()
    }

    pub fn memory_alloc_rate(&self) -> f64 {
        self.memory_alloc_events as f64 / self.window_secs()
    }

    pub fn module_load_rate(&self) -> f64 {
        self.module_load_count as f64 / self.window_secs()
    }

    pub fn mmap_exec_ratio(&self) -> f64 {
        if self.mmap_total_count == 0 { 0.0 }
        else { self.mmap_exec_count as f64 / self.mmap_total_count as f64 }
    }

    pub fn io_uring_ratio(&self) -> f64 {
        if self.event_count == 0 { 0.0 }
        else { self.io_uring_count as f64 / self.event_count as f64 }
    }
}

/// Coefficient of variation for a sliding window of nanosecond intervals.
fn compute_cv(intervals: &VecDeque<u64>) -> f64 {
    if intervals.len() < 2 { return 1.0; }
    let n = intervals.len() as f64;
    let mean = intervals.iter().sum::<u64>() as f64 / n;
    if mean < 1.0 { return 1.0; }
    let var = intervals.iter()
        .map(|&x| { let d = x as f64 - mean; d * d })
        .sum::<f64>() / n;
    (var.sqrt() / mean).clamp(0.0, 10.0)
}

// ─── SyscallProfiler ─────────────────────────────────────────────────────────

/// Lock-free per-process syscall profiler using DashMap.
pub struct SyscallProfiler {
    profiles:    DashMap<u32, ProcessProfile>,
    evict_after: Duration,
}

impl SyscallProfiler {
    pub fn new() -> Self {
        Self {
            profiles:    DashMap::new(),
            evict_after: Duration::from_secs(300),
        }
    }

    pub fn record(&self, event: &SyscallEvent) {
        let mut entry = self.profiles
            .entry(event.pid)
            .or_insert_with(|| ProcessProfile::new(event.pid, &event.comm));
        entry.value_mut().update(event);
        debug!(
            "SyscallProfiler: PID {} ({}) event #{} syscall={}",
            event.pid, event.comm, entry.event_count, event.syscall_nr
        );
    }

    pub fn get_profile(&self, pid: u32) -> Option<ProcessProfile> {
        self.profiles.get(&pid).map(|r| r.value().clone())
    }

    pub fn all_profiles(&self) -> Vec<ProcessProfile> {
        self.profiles.iter().map(|r| r.value().clone()).collect()
    }

    pub fn evict_stale(&self) {
        let threshold = self.evict_after;
        self.profiles.retain(|_, profile| {
            profile.last_event_ts
                .map(|t| t.elapsed() < threshold)
                .unwrap_or(false)
        });
    }

    pub fn evict_pid(&self, pid: u32) {
        self.profiles.remove(&pid);
    }

    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }
}

impl Default for SyscallProfiler {
    fn default() -> Self { Self::new() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(pid: u32, syscall_nr: u32) -> SyscallEvent {
        SyscallEvent::new(pid, syscall_nr, "test_proc")
    }

    #[test]
    fn profile_accumulates_events() {
        let profiler = SyscallProfiler::new();
        for _ in 0..10 {
            profiler.record(&make_event(1234, SYS_READ));
        }
        let profile = profiler.get_profile(1234).expect("Profile must exist");
        assert_eq!(profile.event_count, 10);
        assert_eq!(*profile.syscall_counts.get(&SYS_READ).unwrap(), 10);
    }

    #[test]
    fn unique_syscall_count_is_accurate() {
        let profiler = SyscallProfiler::new();
        for nr in [SYS_READ, SYS_WRITE, SYS_MMAP, SYS_EXECVE] {
            profiler.record(&make_event(5678, nr));
        }
        let profile = profiler.get_profile(5678).unwrap();
        assert_eq!(profile.unique_syscall_count, 4);
    }

    #[test]
    fn child_spawns_counted_correctly() {
        let profiler = SyscallProfiler::new();
        profiler.record(&make_event(100, SYS_FORK));
        profiler.record(&make_event(100, SYS_EXECVE));
        profiler.record(&make_event(100, SYS_CLONE));
        profiler.record(&make_event(100, SYS_READ));
        let profile = profiler.get_profile(100).unwrap();
        assert_eq!(profile.child_spawns, 3);
    }

    #[test]
    fn dangerous_syscalls_flagged() {
        let profiler = SyscallProfiler::new();
        profiler.record(&make_event(200, SYS_PTRACE));
        profiler.record(&make_event(200, SYS_MEMFD_CREATE));
        profiler.record(&make_event(200, SYS_WRITE));
        let profile = profiler.get_profile(200).unwrap();
        assert_eq!(profile.dangerous_syscall_count, 2);
    }

    #[test]
    fn bpf_calls_tracked() {
        let profiler = SyscallProfiler::new();
        for _ in 0..5 { profiler.record(&make_event(300, SYS_BPF)); }
        let profile = profiler.get_profile(300).unwrap();
        assert_eq!(profile.bpf_call_count, 5);
    }

    #[test]
    fn io_uring_tracked() {
        let profiler = SyscallProfiler::new();
        profiler.record(&make_event(400, SYS_IO_URING_SETUP));
        profiler.record(&make_event(400, SYS_IO_URING_ENTER));
        let profile = profiler.get_profile(400).unwrap();
        assert_eq!(profile.io_uring_count, 2);
    }

    #[test]
    fn userfaultfd_tracked() {
        let profiler = SyscallProfiler::new();
        profiler.record(&make_event(500, SYS_USERFAULTFD));
        let profile = profiler.get_profile(500).unwrap();
        assert_eq!(profile.userfaultfd_count, 1);
    }

    #[test]
    fn multiple_pids_are_independent() {
        let profiler = SyscallProfiler::new();
        profiler.record(&make_event(1, SYS_READ));
        profiler.record(&make_event(2, SYS_WRITE));
        profiler.record(&make_event(2, SYS_WRITE));
        assert_eq!(profiler.get_profile(1).unwrap().event_count, 1);
        assert_eq!(profiler.get_profile(2).unwrap().event_count, 2);
        assert!(profiler.get_profile(3).is_none());
    }

    #[test]
    fn eviction_removes_stale_profiles() {
        use std::sync::RwLock;
        let profiler = SyscallProfiler {
            profiles:    DashMap::new(),
            evict_after: Duration::from_nanos(1),
        };
        profiler.record(&make_event(999, SYS_READ));
        std::thread::sleep(Duration::from_millis(1));
        profiler.evict_stale();
        assert_eq!(profiler.profile_count(), 0);
    }

    #[test]
    fn all_profiles_returns_all() {
        let profiler = SyscallProfiler::new();
        for pid in [10, 20, 30] {
            profiler.record(&make_event(pid, SYS_READ));
        }
        assert_eq!(profiler.all_profiles().len(), 3);
    }

    #[test]
    fn setuid_attempts_tracked() {
        let profiler = SyscallProfiler::new();
        profiler.record(&make_event(600, SYS_SETUID));
        profiler.record(&make_event(600, SYS_SETRESUID));
        let profile = profiler.get_profile(600).unwrap();
        assert_eq!(profile.setuid_attempt_count, 2);
    }

    #[test]
    fn module_load_tracked() {
        let profiler = SyscallProfiler::new();
        profiler.record(&make_event(700, SYS_INIT_MODULE));
        profiler.record(&make_event(700, SYS_FINIT_MODULE));
        let profile = profiler.get_profile(700).unwrap();
        assert_eq!(profile.module_load_count, 2);
    }
}
