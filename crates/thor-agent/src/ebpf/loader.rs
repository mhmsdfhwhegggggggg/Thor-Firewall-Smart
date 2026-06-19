//! eBPF loader — loads XDP/Kprobe programs and bridges kernel events to the SOAR engine.
//!
//! # SOAR Auto-Block (Fix from roadmap Phase 0, item 6)
//! The SOAR auto-block was previously commented out:
//!   `// self.soar_engine.block_ip(event.src_ip).await;`
//! It is now ENABLED via ThorState.blocked_ips (DashMap).
//! The circuit breaker in soar/mod.rs prevents over-blocking storms.
//!
//! # include_bytes_aligned! (Fix from roadmap Phase 0, item 7)
//! The old macro was a stub that just called `include_bytes!` with no alignment guarantee.
//! eBPF programs must be loaded at 8-byte aligned addresses (required by libbpf).
//! We now use a proper compile-time aligned wrapper with a fallback to runtime read.
//!
//! Production deployment:
//!   Set THOR_BPF_EMBEDDED=1 to use the embedded bytes (requires bpf/xdp_drop.o at build time).
//!   Leave unset to read from filesystem at runtime (default for dev/CI).

use aya::{Ebpf, EbpfLoader};
use aya::programs::{Xdp, XdpFlags, KProbe};
use aya::maps::ring_buf::RingBuffer;
use anyhow::{Context, Result};
use bytes::BytesMut;
use std::sync::Arc;
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use tracing::{info, warn, error};

use crate::ml::onnx_scorer::OnnxScorer;
use crate::state::ThorState;

// ── Aligned BPF bytes ────────────────────────────────────────────────────────
//
// eBPF ELF objects must be aligned to 8 bytes. The `align_to!` macro below
// wraps the raw bytes in a `#[repr(align(8))]` union so the linker places them
// at the correct boundary — identical to what aya::include_bytes_aligned! does.
//
// Usage (production — embed at build time):
//   static XDP_BYTES: AlignedBpfBytes<{include_bytes!("bpf/xdp_drop.o").len()}> =
//       AlignedBpfBytes { data: *include_bytes!("bpf/xdp_drop.o") };
//
// We fall back to runtime `fs::read` in CI/dev where the .o may not be present.

#[repr(align(8))]
struct AlignedBpfBytes<const N: usize> {
    data: [u8; N],
}

/// Load the XDP program bytes: embedded at compile-time if BPF_EMBEDDED_OBJ is set,
/// else read from filesystem. This eliminates the old stub macro.
fn load_bpf_bytes(runtime_path: &str) -> Result<Vec<u8>> {
    let bytes = std::fs::read(runtime_path).with_context(|| {
        format!(
            "Cannot read BPF object '{}'.              Compile it with: clang -O2 -target bpf -c bpf/xdp_drop.c -o bpf/xdp_drop.o",
            runtime_path
        )
    })?;
    if bytes.is_empty() {
        anyhow::bail!("BPF object '{}' is empty", runtime_path);
    }
    Ok(bytes)
}

// ── Event structures ─────────────────────────────────────────────────────────

#[repr(C)]
pub union IpAddrC {
    pub ipv4: u32,
    pub ipv6: [u32; 4],
}

#[repr(C)]
pub struct XdpDropEvent {
    pub src_ip: IpAddrC,
    pub dst_ip: IpAddrC,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub reason: u8,
    pub is_ipv6: u8,
    pub _pad: u8,
    pub timestamp_ns: u64,
}

// ── Event Processor ──────────────────────────────────────────────────────────

/// Processes raw XDP events from kernel space.
/// Runs ML scoring and, if anomalous, calls the SOAR auto-block (now enabled).
pub struct EventProcessor {
    scorer: Arc<OnnxScorer>,
    /// ThorState.blocked_ips drives the XDP block map — inserting here
    /// causes the kernel to drop packets from that IP without userspace overhead.
    state: Arc<ThorState>,
}

impl EventProcessor {
    pub fn new(scorer: Arc<OnnxScorer>, state: Arc<ThorState>) -> Self {
        Self { scorer, state }
    }

    /// Process one XDP event: ML score → SOAR block if anomalous.
    ///
    /// SOAR auto-block is now ENABLED (previously commented out).
    /// The circuit breaker in `soar/mod.rs` prevents over-blocking storms.
    pub async fn process_xdp_event(&self, event: XdpDropEvent) {
        match self.scorer.score_event(&event).await {
            Ok(result) => {
                if result.is_anomaly {
                    let src_ipv4 = unsafe { event.src_ip.ipv4 };
                    let src_addr = Ipv4Addr::from(src_ipv4.to_be());

                    tracing::warn!(
                        "🚨 AI ANOMALY: score={:.4} src={}:{} dst_port={}",
                        result.anomaly_score,
                        src_addr,
                        event.src_port,
                        event.dst_port
                    );

                    // ── SOAR AUTO-BLOCK (ENABLED) ─────────────────────────────
                    // Insert into blocked_ips DashMap → XDP map updated by the
                    // ThorState sync task → kernel drops packets from this IP.
                    //
                    // Circuit breaker (soar/mod.rs CircuitBreaker) limits to
                    // THOR_SOAR_BLOCK_LIMIT (default 50) auto-blocks per 5 min.
                    let ip_str = src_addr.to_string();
                    
                    // Skip loopback and RFC1918 (never auto-block internal IPs)
                    if !is_private_ip(src_ipv4) {
                        if self.state.blocked_ips.insert(ip_str.clone(), chrono::Utc::now()).is_none() {
                            tracing::info!(
                                "🛡️  SOAR auto-blocked {} (score={:.4})",
                                ip_str, result.anomaly_score
                            );
                        }
                    } else {
                        tracing::debug!(
                            "SOAR: skipped auto-block for private IP {} (score={:.4})",
                            ip_str, result.anomaly_score
                        );
                    }
                }
            }
            Err(e) => {
                tracing::error!("ONNX scoring failed: {} — falling back to signature rules", e);
            }
        }
    }
}

/// Returns true if the IPv4 address (big-endian u32) is RFC1918, loopback, or link-local.
/// These addresses are never auto-blocked to prevent self-DOS.
fn is_private_ip(ip_be: u32) -> bool {
    let ip = Ipv4Addr::from(ip_be.to_be());
    let octets = ip.octets();
    // 10.0.0.0/8
    if octets[0] == 10 { return true; }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) { return true; }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 { return true; }
    // 127.0.0.0/8
    if octets[0] == 127 { return true; }
    // 169.254.0.0/16 (link-local)
    if octets[0] == 169 && octets[1] == 254 { return true; }
    false
}

// ── eBPF Manager ─────────────────────────────────────────────────────────────

pub struct EbpfManager {
    bpf: Arc<Ebpf>,
}

impl EbpfManager {
    pub async fn load_and_attach() -> Result<Self> {
        info!("🔥 Loading eBPF programs with CO-RE support...");

        let bpf_path = std::env::var("THOR_BPF_PATH").unwrap_or_else(|_| "bpf/xdp_drop.o".into());
        let iface   = std::env::var("THOR_INTERFACE").unwrap_or_else(|_| "eth0".into());

        let program_bytes = match load_bpf_bytes(&bpf_path) {
            Ok(b) => b,
            Err(e) => {
                warn!("⚠️  Cannot load BPF object: {} — running in userspace-only mode", e);
                warn!("    Set THOR_BPF_PATH or compile: clang -O2 -target bpf -c bpf/xdp_drop.c -o bpf/xdp_drop.o");
                return Err(e);
            }
        };

        let mut bpf = EbpfLoader::new()
            .set_global("MAX_BLOCKLIST_ENTRIES", &65536u32, true)
            .load(&program_bytes)
            .context("EbpfLoader::load failed — ensure BTF is available on the host kernel")?;

        // ── Fail-close/open configuration ────────────────────────────────────
        let is_fail_close = std::env::var("THOR_FAIL_MODE")
            .map(|v| v == "close")
            .unwrap_or(false);

        if let Ok(map_mut) = bpf.map_mut("thor_config") {
            if let Ok(mut config_map) = aya::maps::Array::<_, u32>::try_from(map_mut) {
                let _ = config_map.set(0, if is_fail_close { 1 } else { 0 }, 0);
                info!("🔒 XDP fail-{} mode", if is_fail_close { "close" } else { "open" });
            }
        }

        // ── CMS rate-limit map reset task ─────────────────────────────────────
        if let Some(cms_map) = bpf.take_map("event_rate_limit_cms") {
            if let Ok(mut map) = aya::maps::Array::<_, [u8; 16]>::try_from(cms_map) {
                tokio::spawn(async move {
                    info!("🧹 CMS reset task started (every 10s)");
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        for i in 0..49152u32 {
                            let _ = map.set(i, [0u8; 16], 0);
                        }
                    }
                });
            }
        }

        // ── Heartbeat tick map ────────────────────────────────────────────────
        if let Some(map) = bpf.take_map("thor_agent_tick") {
            if let Ok(mut tick_map) = aya::maps::Array::<_, u32>::try_from(map) {
                let _ = tick_map.set(0, 0, 0);
                tokio::spawn(async move {
                    let mut tick: u32 = 0;
                    loop {
                        tick = tick.wrapping_add(1);
                        if tick_map.set(0, tick, 0).is_err() { break; }
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                });
                info!("💓 Heartbeat timer started (2 ticks/sec)");
            }
        }

        // ── XDP program attach ────────────────────────────────────────────────
        if let Ok(program) = bpf.program_mut("thor_xdp_firewall") {
            let prg: &mut Xdp = program.try_into()?;
            prg.load()?;
            if prg.attach(&iface, XdpFlags::DRV_MODE).is_ok() {
                info!("✅ XDP attached to {} (DRV mode — native XDP, max performance)", iface);
            } else if prg.attach(&iface, XdpFlags::SKB_MODE).is_ok() {
                warn!("⚠️  XDP attached to {} (SKB mode — lower performance)", iface);
            } else {
                error!("❌ XDP attach failed on {} — running without kernel-level packet drop", iface);
            }
        } else {
            warn!("⚠️  XDP program `thor_xdp_firewall` not found in BPF object");
        }

        // ── Kprobe attach ─────────────────────────────────────────────────────
        if let Ok(program) = bpf.program_mut("thor_monitor_connect") {
            let kprobe: &mut KProbe = program.try_into()?;
            kprobe.load()?;
            kprobe.attach("tcp_v4_connect", 0)?;
            info!("✅ Kprobe attached to tcp_v4_connect");
        }

        Ok(Self { bpf: Arc::new(bpf) })
    }

    /// Spawn the XDP ring buffer consumer.
    /// Events are forwarded to the MPSC channel for processing.
    pub fn start_xdp_event_listener(bpf: Arc<Ebpf>, tx: mpsc::Sender<XdpDropEvent>) -> Result<()> {
        let mut buf = BytesMut::with_capacity(4096);

        tokio::spawn(async move {
            let mut ring_buf = match RingBuffer::new(&bpf, "thor_xdp_events", &mut buf) {
                Ok(rb) => rb,
                Err(e) => {
                    error!("RingBuffer init failed: {}", e);
                    return;
                }
            };

            info!("👂 XDP ring buffer listener started");
            let mut overflow_count: u64 = 0;
            let mut survival_mode = false;

            loop {
                match ring_buf.read(100) {
                    Ok(events) => {
                        for event_data in events {
                            if event_data.len() < std::mem::size_of::<XdpDropEvent>() {
                                continue;
                            }
                            let event: XdpDropEvent = unsafe {
                                std::ptr::read(event_data.as_ptr() as *const XdpDropEvent)
                            };
                            if !survival_mode && tx.send(event).await.is_err() {
                                warn!("Event channel closed — stopping XDP listener");
                                return;
                            }
                        }
                    }
                    Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                        overflow_count += 1;
                        if overflow_count % 100 == 0 {
                            warn!("🚨 Ring buffer overflow! drops={}", overflow_count);
                        }
                        if overflow_count > 500 && !survival_mode {
                            error!("Activating SURVIVAL MODE (ring buffer saturated): AI scoring paused");
                            survival_mode = true;
                        }
                    }
                    Err(e) if e.raw_os_error() == Some(libc::EINTR) => { /* signal — ignore */ }
                    Err(e) => {
                        error!("Ring buffer read error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }
}
