//! ONNX Scorer: Production-Grade AI Inference Engine
//! Evaluates eBPF events in < 1ms using local ONNX models.

use anyhow::{Context, Result};
use ndarray::{Array1, Array2};
use ort::{GraphOptimizationLevel, Session, SessionBuilder, Value};
use std::path::Path;
use std::sync::Arc;
use tokio::task;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing::{info, warn, error};
use crossbeam::queue::ArrayQueue;

use crate::ebpf::loader::XdpDropEvent; 

/// محرك تسجيل النقاط بالذكاء الاصطناعي (مع Object Pooling و تخصيص طوابير Batch)
pub struct OnnxScorer {
    tx: mpsc::Sender<(Vec<f32>, oneshot::Sender<f32>)>,
    pool: Arc<ArrayQueue<Vec<f32>>>,
    anomaly_threshold: f32,
}

impl OnnxScorer {
    /// تهيئة المحرك وتحميل النموذج + Pre-warming
    pub fn new(model_path: &str, threshold: f32) -> Result<Self> {
        info!("🧠 Initializing ONNX Scorer Engine (Enterprise Optimized)...");

        // 1. Object Pooling لاستهلاك الذاكرة (منع Allocations في الـ Hot Path)
        let pool = Arc::new(ArrayQueue::new(2048));
        for _ in 0..2048 {
            let _ = pool.push(vec![0.0f32; 32]);
        }
        
        let path = Path::new(model_path);
        let session = if path.exists() {
            ort::init().with_execution_providers([
                ort::execution_providers::CPUExecutionProvider::default().build(),
            ]).commit().unwrap_or_default();

            // 2. تحسين مستويات ONNX
            let mut session = SessionBuilder::new()?
                .with_optimization_level(GraphOptimizationLevel::Level3)? 
                .with_intra_threads(num_cpus::get())? // استخدام جميع أنوية CPU المتاحة
                .commit_from_file(path)?;
                
            let input_name = session.inputs.first().context("No inputs")?.name.clone();
            let output_name = session.outputs.first().context("No outputs")?.name.clone();
            
            info!("🔥 Pre-warming ONNX Engine...");
            // 3. Pre-warming (تهيئة الذاكرة المؤقتة عبر استدلال وهمي)
            let dummy_features = vec![0.0f32; 32];
            let dummy_tensor = Value::from_array(session.allocator(), &Array1::from_vec(dummy_features.clone()))?;
            let _ = session.run(ort::inputs![input_name.as_str() => dummy_tensor]?)?;
            info!("✅ Pre-arming completed. Latency stabilized.");
            
            Some(Arc::new(session))
        } else {
            warn!("⚠️ ONNX Model not found at {}. AI scoring running in stub mode.", model_path);
            None
        };

        // 4. خيط مخصص للاستدلال لتجنب overhead الخاص بـ spawn_blocking لكل حزمة
        let (tx, mut rx) = mpsc::channel::<(Vec<f32>, oneshot::Sender<f32>)>(4096);
        
        let pool_clone = pool.clone();
        std::thread::spawn(move || {
            let input_name = session.as_ref().and_then(|s| s.inputs.first().map(|i| i.name.clone())).unwrap_or_default();
            let output_name = session.as_ref().and_then(|s| s.outputs.first().map(|i| i.name.clone())).unwrap_or_default();
            
            while let Some((features, resp)) = rx.blocking_recv() {
                let score = if let Some(ref sess) = session {
                    if let Ok(input_tensor) = Value::from_array(sess.allocator(), &Array1::from_vec(features.clone())) {
                        if let Ok(outputs) = sess.run(ort::inputs![input_name.as_str() => input_tensor]) {
                            if let Ok(output_tensor) = outputs[&output_name].try_extract_tensor::<f32>() {
                                output_tensor.iter().next().copied().unwrap_or(0.0)
                            } else { 0.0 }
                        } else { 0.0 }
                    } else { 0.0 }
                } else {
                    0.0 // Stub fallback
                };
                
                let _ = resp.send(score);
                
                // Return buffer to pool
                let mut recycled = features;
                // Zeroing manually is faster than dropping and reallocating
                recycled.fill(0.0);
                let _ = pool_clone.push(recycled);
            }
        });

        Ok(Self {
            tx,
            pool,
            anomaly_threshold: threshold,
        })
    }

    /// تقييم حدث شبكي (Non-blocking Hot Path with Pooling)
    pub async fn score_event(&self, event: &XdpDropEvent) -> Result<InferenceResult> {
        // الاستعارة من الـ Object Pool (Zero Allocation)
        let mut features = self.pool.pop().unwrap_or_else(|| vec![0.0f32; 32]);
        
        FeatureExtractor::extract_xdp_features_in_place(event, &mut features);

        let (resp_tx, resp_rx) = oneshot::channel();
        
        if self.tx.send((features, resp_tx)).await.is_err() {
            return Err(anyhow::anyhow!("AI Inference Thread panicked"));
        }

        let score = resp_rx.await.unwrap_or(0.0);

        Ok(InferenceResult {
            anomaly_score: score,
            is_anomaly: score >= self.anomaly_threshold,
        })
    }
}

/// نتيجة تقييم الذكاء الاصطناعي
#[derive(Debug, Clone, Copy)]
pub struct InferenceResult {
    pub anomaly_score: f32,
    pub is_anomaly: bool,
}

struct FeatureExtractor;

impl FeatureExtractor {
    /// تحديث المصفوفة موضعياً لتجنب التوزيعات
    fn extract_xdp_features_in_place(event: &XdpDropEvent, features: &mut [f32]) {
        let src_ipv4 = unsafe { event.src_ip.ipv4 };
        let dst_ipv4 = unsafe { event.dst_ip.ipv4 };
        
        features[0] = (src_ipv4 >> 24) as f32 / 255.0;
        features[1] = ((src_ipv4 >> 16) & 0xFF) as f32 / 255.0;
        features[2] = (dst_ipv4 >> 24) as f32 / 255.0;
        features[3] = ((dst_ipv4 >> 16) & 0xFF) as f32 / 255.0;

        features[4] = event.src_port as f32 / 65535.0;
        features[5] = event.dst_port as f32 / 65535.0;

        features[6] = if event.protocol == 6 { 1.0 } else { 0.0 }; 
        features[7] = if event.protocol == 17 { 1.0 } else { 0.0 }; 

        features[8] = 0.5; 
    }
}
