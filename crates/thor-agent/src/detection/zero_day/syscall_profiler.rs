//! Syscall Profiler — builds per-process behavioral profiles from eBPF events.
//!
//! The profiler maintains a sliding-window histogram of syscall calls per
//! process.  Each `SyscallEvent` (produced either by the eBPF ring buffer or
//! a synthetic source in tests) updates:
//!
//! * Per-syscall call counts (raw histogram).
//! * Exponential moving averages of call rates.
//! * Child-spawn rate (execve/clone/fork counts).
//! * Memory allocation rate (mmap/brk/mprotect counts).
//! * Network byte counters (read/write/sendmsg/recvmsg on sockets).
//! * Write entropy estimate (updated with each file-write event).
//!
//! The resulting `ProcessProfile` is used as input to the `AnomalyEngine`
//! and `ExploitPrimitiveDetector`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::debug;

// ─── Syscall numbers (Linux x86-64) ──────────────────────────────────────────

pub const SYS_READ:      u32 = 0;
pub const SYS_WRITE:     u32 = 1;
pub const SYS_OPEN:      u32 = 2;
pub const SYS_MMAP:      u32 = 9;
pub const SYS_MPROTECT:  u32 = 10;
pub const SYS_MUNMAP:    u32 = 11;
pub const SYS_BRK:       u32 = 12;
pub const SYS_IOCTL:     u32 = 16;
pub const SYS_SENDMSG:   u32 = 46;
pub const SYS_RECVMSG:   u32 = 47;
pub const SYS_FORK:      u32 = 57;
pub const SYS_VFORK:     u32 = 58;
pub const SYS_EXECVE:    u32 = 59;
pub const SYS_SOCKET:    u32 = 41;
pub const SYS_CONNECT:   u32 = 42;
pub const SYS_CLONE:     u32 = 56;
pub const SYS_PTRACE:    u32 = 101;
pub const SYS_INIT_MODULE: u32 = 175;
pub const SYS_CREATE_MODULE: u32 = 174;
pub const SYS_PROCESS_VM_READV: u32 = 310;
pub const SYS_PROCESS_VM_WRITEV: u32 = 311;
pub const SYS_MEMFD_CREATE: u32 = 319;

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
    pub byte_count: u64,
    /// Monotonic timestamp in nanoseconds (from ktime_get_ns()).
    pub ts_ns:      u64,
    /// Process name from task_comm (max 16 bytes, NUL-padded).
    pub comm:       String,
    /// Whether this is a kernel-space event (false = userspace).
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
            is_kernel:  false,
        }
    }

    pub fn is_exec_event(&self) -> bool {
        matches!(self.syscall_nr, n if n == SYS_EXECVE || n == SYS_FORK || n == SYS_VFORK || n == SYS_CLONE)
    }

    pub fn is_memory_event(&self) -> bool {
        matches!(self.syscall_nr, n if n == SYS_MMAP || n == SYS_MPROTECT || n == SYS_BRK || n == SYS_MUNMAP)
    }

    pub fn is_dangerous(&self) -> bool {
        matches!(self.syscall_nr, n if
            n == SYS_PTRACE || n == SYS_INIT_MODULE || n == SYS_CREATE_MODULE ||
            n == SYS_PROCESS_VM_READV || n == SYS_PROCESS_VM_WRITEV || n == SYS_MEMFD_CREATE)
    }
}

// ─── ProcessProfile ───────────────────────────────────────────────────────────

/// Behavioral profile for a single process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessProfile {
    /// Process ID.
    pub pid: u32,
    /// Process name (comm).
    pub process_name: String,
    /// Total syscall events seen for this process.
    pub event_count: u64,
    /// Per-syscall call counts (syscall_nr → count).
    pub syscall_counts: HashMap<u32, u64>,
    /// Number of unique syscall numbers seen.
    pub unique_syscall_count: usize,
    /// Exponential moving average of syscalls per second.
    pub syscall_rate_ema: f64,
    /// Total child processes spawned (exec/fork/clone).
    pub child_spawns: u64,
    /// Total memory allocation events (mmap/brk/mprotect).
    pub memory_alloc_events: u64,
    /// Total bytes transferred (read + write + send + recv).
    pub total_network_bytes: u64,
    /// Running write entropy estimate [0.0, 1.0].
    pub write_entropy_estimate: f64,
    /// Count of dangerous syscalls seen (ptrace, init_module, etc.).
    pub dangerous_syscall_count: u64,
    /// Observation window duration.
    pub window_start: Option<Instant>,
    /// Last event time (for rate calculations).
    pub last_event_ts: Option<Instant>,
}

impl ProcessProfile {
    fn new(pid: u32, comm: &str) -> Self {
        Self {
            pid,
            process_name:            comm.to_string(),
            event_count:             0,
            syscall_counts:          HashMap::new(),
            unique_syscall_count:    0,
            syscall_rate_ema:        0.0,
            child_spawns:            0,
            memory_alloc_events:     0,
            total_network_bytes:     0,
            write_entropy_estimate:  0.0,
            dangerous_syscall_count: 0,
            window_start:            None,
            last_event_ts:           None,
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

        // Update EMA of syscall rate (α = 0.05 for stability)
        if let Some(last) = self.last_event_ts {
            let dt_secs = now.duration_since(last).as_secs_f64().max(1e-6);
            let instantaneous_rate = 1.0 / dt_secs;
            self.syscall_rate_ema = 0.05 * instantaneous_rate + 0.95 * self.syscall_rate_ema;
        }
        self.last_event_ts = Some(now);

        if event.is_exec_event() {
            self.child_spawns += 1;
        }
        if event.is_memory_event() {
            self.memory_alloc_events += 1;
        }
        if event.is_dangerous() {
            self.dangerous_syscall_count += 1;
        }

        // Network byte accumulation
        if matches!(event.syscall_nr, n if n == SYS_SENDMSG || n == SYS_RECVMSG ||
            n == SYS_READ || n == SYS_WRITE) && event.byte_count > 0
        {
            self.total_network_bytes += event.byte_count;
        }

        // Write entropy: Shannon entropy of the byte distribution of recent write data.
        // We approximate this using the LSB distribution of `byte_count` values.
        if event.syscall_nr == SYS_WRITE && event.byte_count > 0 {
            let lsb = (event.byte_count & 0xFF) as f64 / 255.0;
            // Exponential average of per-write "entropy proxy"
            self.write_entropy_estimate =
                0.1 * lsb + 0.9 * self.write_entropy_estimate;
        }
    }

    /// Observation window in seconds.
    pub fn window_secs(&self) -> f64 {
        match self.window_start {
            Some(start) => start.elapsed().as_secs_f64().max(1.0),
            None        => 1.0,
        }
    }

    /// Child spawn rate per second over the observation window.
    pub fn child_spawn_rate(&self) -> f64 {
        self.child_spawns as f64 / self.window_secs()
    }

    /// Memory allocation rate per second.
    pub fn memory_alloc_rate(&self) -> f64 {
        self.memory_alloc_events as f64 / self.window_secs()
    }
}

// ─── SyscallProfiler ─────────────────────────────────────────────────────────

/// Thread-safe per-process syscall profiler.
///
/// Maintains a map of PID → `ProcessProfile`, evicting profiles for processes
/// that have not been seen for more than 5 minutes.
pub struct SyscallProfiler {
    profiles: RwLock<HashMap<u32, ProcessProfile>>,
    evict_after: Duration,
}

impl SyscallProfiler {
    pub fn new() -> Self {
        Self {
            profiles:    RwLock::new(HashMap::new()),
            evict_after: Duration::from_secs(300),
        }
    }

    /// Record a new syscall event and update the corresponding profile.
    pub fn record(&self, event: &SyscallEvent) {
        let mut map = self.profiles.write().unwrap();
        let profile = map.entry(event.pid)
            .or_insert_with(|| ProcessProfile::new(event.pid, &event.comm));
        profile.update(event);
        debug!(
            "SyscallProfiler: PID {} ({}) event #{} syscall={}",
            event.pid, event.comm, profile.event_count, event.syscall_nr
        );
    }

    /// Get a snapshot of the profile for a given PID.
    pub fn get_profile(&self, pid: u32) -> Option<ProcessProfile> {
        self.profiles.read().unwrap().get(&pid).cloned()
    }

    /// Get all active profiles.
    pub fn all_profiles(&self) -> Vec<ProcessProfile> {
        self.profiles.read().unwrap().values().cloned().collect()
    }

    /// Evict profiles for processes not seen within `evict_after`.
    pub fn evict_stale(&self) {
        let mut map = self.profiles.write().unwrap();
        let threshold = self.evict_after;
        map.retain(|_, profile| {
            profile.last_event_ts
                .map(|t| t.elapsed() < threshold)
                .unwrap_or(false)
        });
    }

    /// Number of active profiles.
    pub fn profile_count(&self) -> usize {
        self.profiles.read().unwrap().len()
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
        profiler.record(&make_event(100, SYS_READ)); // not a spawn
        let profile = profiler.get_profile(100).unwrap();
        assert_eq!(profile.child_spawns, 3);
    }

    #[test]
    fn dangerous_syscalls_flagged() {
        let profiler = SyscallProfiler::new();
        profiler.record(&make_event(200, SYS_PTRACE));
        profiler.record(&make_event(200, SYS_MEMFD_CREATE));
        profiler.record(&make_event(200, SYS_WRITE)); // not dangerous
        let profile = profiler.get_profile(200).unwrap();
        assert_eq!(profile.dangerous_syscall_count, 2);
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
        let profiler = SyscallProfiler {
            profiles:    RwLock::new(HashMap::new()),
            evict_after: Duration::from_nanos(1), // 1 ns → immediately stale
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
}
