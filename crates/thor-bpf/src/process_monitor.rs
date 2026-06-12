//! Thor Process Monitor — ring buffer consumer for process tracepoint events
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn, debug};
use thor_common::{ProcessExecEvent, EVENT_PROCESS_EXEC, EVENT_PROCESS_EXIT};

#[derive(Debug, Clone)]
pub enum ThorProcessEvent {
    Exec { pid: u32, ppid: u32, uid: u32, comm: String, filename: String, timestamp_ns: u64 },
    Exit { pid: u32, exit_code: u32, timestamp_ns: u64 },
}

impl ThorProcessEvent {
    pub fn pid(&self) -> u32 { match self { Self::Exec { pid, .. } => *pid, Self::Exit { pid, .. } => *pid } }
}

pub struct ProcessMonitor;

impl ProcessMonitor {
    pub fn attach(bpf: &mut Ebpf) -> Result<()> {
        info!("Attaching process monitor tracepoints...");
        let exec_prog: &mut TracePoint = bpf.program_mut("thor_trace_exec")
            .context("Program not found")?.try_into()?;
        exec_prog.load()?;
        exec_prog.attach("sched", "sched_process_exec")?;
        info!("✅ Attached sched:sched_process_exec");

        let exit_prog: &mut TracePoint = bpf.program_mut("thor_trace_exit")
            .context("Program not found")?.try_into()?;
        exit_prog.load()?;
        exit_prog.attach("sched", "sched_process_exit")?;
        info!("✅ Attached sched:sched_process_exit");
        Ok(())
    }

    pub fn spawn_consumer(
        ring_buf: RingBuf<aya::maps::MapData>,
        event_tx: mpsc::Sender<ThorProcessEvent>,
    ) -> JoinHandle<()> {
        tokio::task::spawn_blocking(move || {
            use aya::maps::ring_buf::RingBufItem;
            let mut ring = ring_buf;
            loop {
                if let Some(item) = ring.next() {
                    if item.len() < std::mem::size_of::<ProcessExecEvent>() { continue; }
                    let raw: ProcessExecEvent = unsafe { std::ptr::read(item.as_ptr() as *const ProcessExecEvent) };
                    let evt = match raw.event_type {
                        t if t == EVENT_PROCESS_EXEC => ThorProcessEvent::Exec {
                            pid: raw.pid, ppid: raw.ppid, uid: raw.uid,
                            comm: c_str(&raw.comm), filename: c_str(&raw.filename),
                            timestamp_ns: raw.timestamp_ns,
                        },
                        t if t == EVENT_PROCESS_EXIT => ThorProcessEvent::Exit {
                            pid: raw.pid, exit_code: raw.exit_code, timestamp_ns: raw.timestamp_ns,
                        },
                        _ => continue,
                    };
                    if event_tx.blocking_send(evt).is_err() { return; }
                }
            }
        })
    }
}

fn c_str(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}
