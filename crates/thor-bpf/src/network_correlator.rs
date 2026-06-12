//! Thor Network Correlator — kprobe loader for TCP connect events
use aya::maps::RingBuf;
use aya::programs::KProbe;
use aya::Ebpf;
use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::info;
use thor_common::{NetworkEvent, EVENT_NET_CONNECT};

#[derive(Debug, Clone)]
pub struct ThorNetworkEvent {
    pub pid: u32,
    pub uid: u32,
    pub src_ip: std::net::Ipv4Addr,
    pub dst_ip: std::net::Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub comm: String,
    pub timestamp_ns: u64,
}

pub struct NetworkCorrelator;

impl NetworkCorrelator {
    pub fn attach(bpf: &mut Ebpf) -> Result<()> {
        info!("Attaching network correlator kprobe...");
        let prog: &mut KProbe = bpf.program_mut("thor_kprobe_connect")
            .context("kprobe program not found")?.try_into()?;
        prog.load()?;
        prog.attach("tcp_v4_connect", 0)?;
        info!("✅ Attached kprobe: tcp_v4_connect");
        Ok(())
    }

    pub fn spawn_consumer(
        ring_buf: RingBuf<aya::maps::MapData>,
        event_tx: mpsc::Sender<ThorNetworkEvent>,
    ) -> JoinHandle<()> {
        tokio::task::spawn_blocking(move || {
            let mut ring = ring_buf;
            loop {
                if let Some(item) = ring.next() {
                    if item.len() < std::mem::size_of::<NetworkEvent>() { continue; }
                    let raw: NetworkEvent = unsafe { std::ptr::read(item.as_ptr() as *const NetworkEvent) };
                    if raw.event_type != EVENT_NET_CONNECT { continue; }
                    let evt = ThorNetworkEvent {
                        pid: raw.pid, uid: raw.uid,
                        src_ip: std::net::Ipv4Addr::from(u32::from_be(raw.src_ip4)),
                        dst_ip: std::net::Ipv4Addr::from(u32::from_be(raw.dst_ip4)),
                        src_port: raw.src_port, dst_port: raw.dst_port,
                        protocol: raw.protocol,
                        comm: c_str(&raw.comm),
                        timestamp_ns: raw.timestamp_ns,
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
