//! BPF Manager — loads all eBPF programs and manages their lifecycle

use anyhow::{Context, Result};
use aya::Ebpf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::events::RawEvent;
use crate::state::ThorState;
use super::super::events::{RawEvent as SuperRawEvent};

use thor_bpf::xdp_drop::XdpThreatDropper;
use thor_bpf::process_monitor::ProcessMonitor;
use thor_bpf::network_correlator::NetworkCorrelator;

pub struct BpfManager {
    pub xdp: Arc<RwLock<XdpThreatDropper>>,
}

impl BpfManager {
    pub async fn start(
        interface: &str,
        raw_tx: flume::Sender<RawEvent>,
        state: Arc<ThorState>,
    ) -> Result<Self> {
        info!("🔧 Initializing eBPF runtime...");

        // Load pre-compiled eBPF object bytes (embedded at compile time)
        // In production these are built by build.rs / bpf-linker
        let xdp_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/xdp_drop.bpf.o"));
        let proc_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/process_monitor.bpf.o"));
        let net_bytes  = include_bytes!(concat!(env!("OUT_DIR"), "/network_correlator.bpf.o"));

        // Load XDP program
        let mut xdp_bpf = Ebpf::load(xdp_bytes).context("Failed to load XDP BPF object")?;
        let xdp_dropper = XdpThreatDropper::load_and_attach(&mut xdp_bpf, interface)
            .context("Failed to attach XDP dropper")?;
        let xdp = Arc::new(RwLock::new(xdp_dropper));

        // Load process monitor
        let mut proc_bpf = Ebpf::load(proc_bytes).context("Failed to load process monitor BPF")?;
        ProcessMonitor::attach(&mut proc_bpf).context("Failed to attach process monitor")?;
        let proc_ring = proc_bpf.take_map("thor_process_events")
            .context("Process event ringbuf not found")?;
        let proc_ring = aya::maps::RingBuf::try_from(proc_ring)?;

        // Load network correlator
        let mut net_bpf = Ebpf::load(net_bytes).context("Failed to load network correlator BPF")?;
        NetworkCorrelator::attach(&mut net_bpf).context("Failed to attach network correlator")?;
        let net_ring = net_bpf.take_map("thor_network_events")
            .context("Network event ringbuf not found")?;
        let net_ring = aya::maps::RingBuf::try_from(net_ring)?;

        // Spawn ring buffer consumers
        let (proc_tx, mut proc_rx) = tokio::sync::mpsc::channel(16384);
        let (net_tx, mut net_rx) = tokio::sync::mpsc::channel(16384);

        ProcessMonitor::spawn_consumer(proc_ring, proc_tx);
        NetworkCorrelator::spawn_consumer(net_ring, net_tx);

        // Bridge to unified raw event channel
        let raw_tx2 = raw_tx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(ev) = proc_rx.recv() => {
                        let _ = raw_tx2.try_send(RawEvent::Process(ev));
                    }
                    Some(ev) = net_rx.recv() => {
                        let _ = raw_tx2.try_send(RawEvent::Network(ev));
                    }
                }
            }
        });

        info!("✅ All eBPF programs loaded and consuming events");
        Ok(Self { xdp })
    }
}
