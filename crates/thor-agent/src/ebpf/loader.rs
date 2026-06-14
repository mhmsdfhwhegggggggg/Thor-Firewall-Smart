use aya::{Ebpf, EbpfLoader};
use aya::programs::{Xdp, XdpFlags, KProbe};
use aya::maps::ring_buf::RingBuffer;
use anyhow::{Context, Result};
use bytes::BytesMut;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, error};

// Macro definition mock since standard rust doesn't have include_bytes_aligned! out of the box unless using a specific crate
macro_rules! include_bytes_aligned {
    ($path:expr) => {
        include_bytes!($path) // Stub for compilation, in reality requires proper aligned memory
    };
}

#[repr(C)]
pub union IpAddrC {
    pub ipv4: u32,
    pub ipv6: [u32; 4],
}

// هياكل البيانات المطابقة تماماً لما في كود C (يجب أن تكون #[repr(C)])
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

use crate::ml::onnx_scorer::OnnxScorer;

pub struct EventProcessor {
    scorer: Arc<OnnxScorer>,
    // ... قنوات إرسال إلى SIEM أو SOAR
}

impl EventProcessor {
    pub fn new(scorer: Arc<OnnxScorer>) -> Self {
        Self { scorer }
    }

    pub async fn process_xdp_event(&self, event: XdpDropEvent) {
        // 1. التقييم الفوري بالذكاء الاصطناعي
        match self.scorer.score_event(&event).await {
            Ok(result) => {
                if result.is_anomaly {
                    let source_ip_v4 = unsafe { event.src_ip.ipv4 };
                    tracing::warn!(
                        "🚨 AI ANOMALY DETECTED! Score: {:.4} | SrcIP: {:?} | DstPort: {}",
                        result.anomaly_score,
                        source_ip_v4,
                        event.dst_port
                    );
                    
                    // 2. هنا يتم استدعاء SOAR لعزل المصدر أو تحديث قائمة الحظر ديناميكياً
                    // self.soar_engine.block_ip(event.src_ip).await;
                }
            }
            Err(e) => {
                tracing::error!("ONNX Scoring failed for event: {}", e);
                // Fallback: الاعتماد على القواعد التقليدية (Sigma/YARA)
            }
        }
    }
}

pub struct EbpfManager {
    bpf: Arc<Ebpf>,
}

impl EbpfManager {
    pub async fn load_and_attach() -> Result<Self> {
        info!("🔥 Loading eBPF programs with CO-RE support...");

        // 1. تحميل ملف ELF المجمع مسبقاً (يحتوي على BTF مدمج)
        // ملاحظة: في الإنتاج، نستخدم include_bytes_aligned!
        let program_bytes = std::fs::read("bpf/xdp_drop.o").unwrap_or_else(|_| {
            tracing::warn!("bpf/xdp_drop.o not found! Ensure you compile the eBPF C code first. Returning early...");
            vec![]
        });
        
        if program_bytes.is_empty() {
            tracing::error!("BPF bytes are empty. Cannot initialize BPF. Exiting EbpfManager load.");
            return Err(anyhow::anyhow!("bpf/xdp_drop.o is empty or missing"));
        }
        
        let mut bpf = EbpfLoader::new()
            .set_global("MAX_BLOCKLIST_ENTRIES", &65536u32, true)
            .load(&program_bytes)?;

        // Configuration Map
        let is_fail_close = std::env::var("THOR_FAIL_MODE").unwrap_or_else(|_| "open".to_string()) == "close";
        if let Ok(mut config_map) = aya::maps::Array::<_, u32>::try_from(bpf.map_mut("thor_config").unwrap()) {
            config_map.set(0, if is_fail_close { 1 } else { 0 }, 0).unwrap_or_else(|e| {
                tracing::error!("Failed to set fail-close configuration: {}", e);
            });
            tracing::info!("🔒 Thor XDP Firewall set to Fail-{} mode", if is_fail_close { "Close" } else { "Open" });
        }

        // Heartbeat Map Initialization (Fail-Close robust mechanism)
        if let Some(map) = bpf.take_map("thor_agent_tick") {
            if let Ok(mut tick_map) = aya::maps::Array::<_, u32>::try_from(map) {
                let _ = tick_map.set(0, 0, 0); 
                // Spawn background task to update tick
                tokio::spawn(async move {
                    let mut tick: u32 = 0;
                    loop {
                        tick = tick.wrapping_add(1);
                        if let Err(e) = tick_map.set(0, tick, 0) {
                            tracing::error!("Failed to update heartbeat map: {}", e);
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                });
                tracing::info!("💓 Thor Heartbeat Timer started (2 ticks/sec)");
            }
        }

        // 2. تحميل وتثبيت برنامج XDP - Only if loaded
        if let Ok(program) = bpf.program_mut("thor_xdp_firewall") {
            let prg: &mut Xdp = program.try_into()?;
            prg.load()?;
            prg.attach("eth0", XdpFlags::DRV_MODE)
                .or_else(|_| {
                    warn!("DRV mode not supported, falling back to SKB mode");
                    prg.attach("eth0", XdpFlags::SKB_MODE)
                })?;
            info!("✅ XDP Firewall attached to eth0");
        } else {
            tracing::error!("XDP program `thor_xdp_firewall` could not be found or loaded.");
        }

        // 3. تحميل وتثبيت Kprobe
        let kprobe_prog: &mut KProbe = bpf.program_mut("thor_monitor_connect").unwrap().try_into()?;
        kprobe_prog.load()?;
        kprobe_prog.attach("tcp_v4_connect", 0)?;
        info!("✅ Kprobe attached to tcp_v4_connect");

        Ok(Self { bpf: Arc::new(bpf) })
    }

    /// بدء الاستماع لأحداث الحظر من النواة (Non-Blocking)
    pub fn start_xdp_event_listener(bpf: Arc<Ebpf>, tx: mpsc::Sender<XdpDropEvent>) -> Result<()> {
        let mut buf = BytesMut::with_capacity(4096);
        
        tokio::spawn(async move {
            // إنشاء Ring Buffer consumer
            let mut ring_buf = match RingBuffer::new(&bpf, "thor_xdp_events", &mut buf) {
                Ok(rb) => rb,
                Err(e) => {
                    error!("Failed to create RingBuffer: {}", e);
                    return;
                }
            };

            info!("👂 Listening to XDP Ring Buffer...");
            let mut drop_count = 0;
            let mut survival_mode = false;

            loop {
                // القراءة غير المتزامنة (مع مهلة قصيرة للتعامل مع الـ Backpressure)
                match ring_buf.read(100) { // Timeout 100ms
                    Ok(events) => {
                        for event_data in events {
                            if event_data.len() < std::mem::size_of::<XdpDropEvent>() {
                                continue;
                            }
                            
                            // تحويل آمن للبيانات (Zero-Copy interpretation)
                            let event: XdpDropEvent = unsafe {
                                std::ptr::read(event_data.as_ptr() as *const XdpDropEvent)
                            };

                            // إذا كنا في وضع النجاة، نتجاوز معالجة AI ونكتفي بالـ XDP
                            if !survival_mode {
                                // إرسال الحدث لمحرك المعالجة (Detection/SIEM)
                                if tx.send(event).await.is_err() {
                                    warn!("Channel closed, stopping XDP listener");
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                        // ⚠️ RingBuffer Overflow detected!
                        drop_count += 1;
                        tracing::warn!("🚨 RingBuffer Overflow! Drops: {}", drop_count);
                        
                        if drop_count > 100 && !survival_mode {
                            tracing::error!("Activating SURVIVAL MODE: Disabling AI scoring to save CPU.");
                            // تعطيل إرسال البيانات لـ ONNX مؤقتاً، والاعتماد فقط على XDP Drop الصامت
                            survival_mode = true;
                        }
                    }
                    Err(e) => {
                        // EINTR هو أمر طبيعي عند مقاطعة الإشارة، نتجاهله
                        if e.raw_os_error() != Some(libc::EINTR) {
                            error!("RingBuffer read error: {}", e);
                        }
                    }
                }
            }
        });

        Ok(())
    }
}
