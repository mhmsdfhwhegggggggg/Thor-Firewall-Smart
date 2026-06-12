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

// هياكل البيانات المطابقة تماماً لما في كود C (يجب أن تكون #[repr(C)])
#[repr(C)]
pub struct XdpDropEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub reason: u8,
    pub _pad: [u8; 2],
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
                    tracing::warn!(
                        "🚨 AI ANOMALY DETECTED! Score: {:.4} | SrcIP: {:?} | DstPort: {}",
                        result.anomaly_score,
                        event.src_ip,
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

    bpf: Arc<Ebpf>,
}

impl EbpfManager {
    pub async fn load_and_attach() -> Result<Self> {
        info!("🔥 Loading eBPF programs with CO-RE support...");

        // 1. تحميل ملف ELF المجمع مسبقاً (يحتوي على BTF مدمج)
        // ملاحظة: في الإنتاج، نستخدم include_bytes_aligned!
        let mut bpf = EbpfLoader::new()
            .set_global("MAX_BLOCKLIST_ENTRIES", &65536u32, true)
            // Using dummy bytes since we can't compile C to BPF in this fast preview environment directly
            // .load(include_bytes_aligned!("../../bpf/xdp_drop.o"))?;
            .load(&[])?;

        // 2. تحميل وتثبيت برنامج XDP
        let program: &mut Xdp = bpf.program_mut("thor_xdp_firewall").unwrap().try_into()?;
        program.load()?;
        // استخدام SKB_MODE كـ Fallback آمن إذا كان DRV_MODE غير مدعوم من كارت الشبكة
        program.attach("eth0", XdpFlags::DRV_MODE)
            .or_else(|_| {
                warn!("DRV mode not supported, falling back to SKB mode (still safe)");
                program.attach("eth0", XdpFlags::SKB_MODE)
            })?;
        info!("✅ XDP Firewall attached to eth0");

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
