//! FIM Monitor eBPF loader — loads fim_monitor.bpf.c and delivers events

use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Ebpf};
use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tracing::{info, warn, error};

use crate::ThorBpfBytes;

// ─── Event structure (mirrors the C struct) ───────────────────────────────────

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FimEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub operation: u8,
    pub pad: [u8; 3],
    pub inode: u64,
    pub path: [u8; 256],
    pub comm: [u8; 16],
    pub flags: u32,
    pub mode: u32,
}

impl FimEvent {
    pub fn path_str(&self) -> String {
        let end = self.path.iter().position(|&b| b == 0).unwrap_or(256);
        String::from_utf8_lossy(&self.path[..end]).to_string()
    }

    pub fn comm_str(&self) -> String {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.comm[..end]).to_string()
    }

    pub fn operation_name(&self) -> &'static str {
        match self.operation {
            0 => "open",
            1 => "create",
            2 => "write",
            3 => "unlink",
            4 => "rename",
            5 => "chmod",
            6 => "chown",
            _ => "unknown",
        }
    }
}

// ─── eBPF FIM Loader ──────────────────────────────────────────────────────────

pub struct FimBpfLoader;

impl FimBpfLoader {
    pub async fn attach(
        bpf: &mut Ebpf,
        event_tx: mpsc::Sender<FimEvent>,
    ) -> Result<()> {
        // Attach tracepoints
        let syscalls = [
            ("syscalls", "sys_enter_openat",    "tracepoint__syscalls__sys_enter_openat"),
            ("syscalls", "sys_enter_unlinkat",  "tracepoint__syscalls__sys_enter_unlinkat"),
            ("syscalls", "sys_enter_renameat2", "tracepoint__syscalls__sys_enter_renameat2"),
            ("syscalls", "sys_enter_fchmodat",  "tracepoint__syscalls__sys_enter_fchmodat"),
            ("syscalls", "sys_enter_fchownat",  "tracepoint__syscalls__sys_enter_fchownat"),
        ];

        let mut attached = 0usize;
        for (category, name, prog_name) in &syscalls {
            match bpf.program_mut(*prog_name) {
                Some(prog) => {
                    let tp: &mut TracePoint = prog.try_into()?;
                    tp.load()?;
                    match tp.attach(category, name) {
                        Ok(_) => { attached += 1; }
                        Err(e) => warn!("FIM: Cannot attach {}/{}: {}", category, name, e),
                    }
                }
                None => warn!("FIM program not found: {}", prog_name),
            }
        }

        info!("🔒 FIM eBPF: {} tracepoints attached", attached);

        // Spawn ring buffer reader
        let ring_buf: RingBuf<_> = bpf.map_mut("thor_fim_events")
            .context("thor_fim_events map not found")?
            .try_into()?;

        tokio::spawn(async move {
            read_fim_events(ring_buf, event_tx).await;
        });

        Ok(())
    }
}

async fn read_fim_events(mut ring_buf: RingBuf<&mut aya::maps::MapData>, tx: mpsc::Sender<FimEvent>) {
    loop {
        while let Some(item) = ring_buf.next() {
            if item.len() < std::mem::size_of::<FimEvent>() {
                continue;
            }
            let evt = unsafe {
                std::ptr::read_unaligned(item.as_ptr() as *const FimEvent)
            };
            if tx.send(evt).await.is_err() {
                return;
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_micros(500)).await;
    }
}
