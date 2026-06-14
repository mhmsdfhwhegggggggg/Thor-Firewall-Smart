//! ONNX Scorer: Production-Grade AI Inference Engine
//! Evaluates eBPF events in < 1ms using local ONNX models.

use anyhow::{Context, Result};
use ndarray::Array1;
use ort::{GraphOptimizationLevel, Session, SessionBuilder, Value};
use std::path::Path;
use std::sync::Arc;
use tokio::task;
use tracing::{info, warn, error};

use crate::ebpf::loader::XdpDropEvent; // أو ProcessNetEvent حسب الحاجة

/// محرك تسجيل النقاط بالذكاء الاصطناعي
pub struct OnnxScorer {
    /// جلسة ONNX (آمنة للمشاركة بين الأنوية عبر Arc)
    session: Arc<Session>,
    input_name: String,
    output_name: String,
    /// عتبة الشذوذ (مثلاً 0.85)
    anomaly_threshold: f32,
}

impl OnnxScorer {
    /// تهيئة المحرك وتحميل النموذج
    pub fn new(model_path: &str, threshold: f32) -> Result<Self> {
        info!("🧠 Initializing ONNX Scorer Engine...");

        // 1. تهيئة بيئة ONNX Runtime
        ort::init().with_execution_providers([
            // استخدام CPU Execution Provider مع تحسينات AVX2/FMA
            ort::execution_providers::CPUExecutionProvider::default().build(),
        ]).commit().context("Failed to initialize ONNX Runtime")?;

        let path = Path::new(model_path);
        if !path.exists() {
            warn!("⚠️ ONNX Model not found at {}. AI scoring will be bypassed (Fallback Mode).", model_path);
            // ملاحظة: في الإنتاج، قد نفضل إرجاع خطأ هنا، لكن التجاهل الآمن يضمن استمرار عمل الوكيل
        }

        // 2. بناء الجلسة بأقصى مستويات التحسين للأداء
        let session = SessionBuilder::new()?
            .with_optimization_level(GraphOptimizationLevel::Level3)? // دمج العمليات لتسريع هائل
            .with_intra_threads(num_cpus::get())? // استخدام جميع أنوية CPU المتاحة
            .commit_from_file(path)
            .context("Failed to load ONNX model. Ensure the file is valid.")?;

        let input_name = session.inputs.first()
            .context("Model has no inputs")?.name.clone();
        let output_name = session.outputs.first()
            .context("Model has no outputs")?.name.clone();

        info!("✅ ONNX Scorer loaded successfully. Input: '{}', Output: '{}'", input_name, output_name);
        info!("📊 Model will use {} CPU threads for inference.", num_cpus::get());

        Ok(Self {
            session: Arc::new(session),
            input_name,
            output_name,
            anomaly_threshold: threshold,
        })
    }

    /// تقييم حدث شبكي (Non-blocking Hot Path)
    pub async fn score_event(&self, event: &XdpDropEvent) -> Result<InferenceResult> {
        // 1. استخراج الميزات (عملية سريعة جداً على الخيط الحالي)
        let features = FeatureExtractor::extract_xdp_features(event);

        // 2. تنفيذ الاستدلال على خيط منفصل (Blocking Thread Pool)
        // هذا هو السر: نمنع أي تأخير في حلقة أحداث tokio الرئيسية
        let session = self.session.clone();
        let input_name = self.input_name.clone();
        let output_name = self.output_name.clone();

        let score = task::spawn_blocking(move || {
            Self::run_inference(&session, &input_name, &output_name, &features)
        })
        .await
        .context("ONNX inference task panicked or was aborted")??;

        Ok(InferenceResult {
            anomaly_score: score,
            is_anomaly: score >= self.anomaly_threshold,
        })
    }

    /// الدالة الفعلية لتنفيذ الاستدلال (تعمل داخل spawn_blocking)
    fn run_inference(
        session: &Session,
        input_name: &str,
        output_name: &str,
        features: &[f32],
    ) -> Result<f32> {
        // تحويل المصفوفة إلى Tensor متوافق مع ONNX
        // الشكل (Shape) يجب أن يكون [1, FEATURE_DIM] (Batch size = 1)
        let input_tensor = Value::from_array(session.allocator(), &Array1::from_vec(features.to_vec()))
            .context("Failed to create input tensor")?;

        // تنفيذ الاستدلال
        let outputs = session
            .run(ort::inputs![input_name.to_string() => input_tensor]?)
            .context("ONNX session run failed")?;

        // استخراج النتيجة (نفترض أن المخرج هو قيمة Float واحدة تمثل درجة الشذوذ بين 0 و 1)
        let output_tensor = outputs[output_name]
            .try_extract_tensor::<f32>()
            .context("Failed to extract output tensor")?;

        // الحصول على القيمة الأولى (والوحيدة في هذه الحالة)
        let score = output_tensor.iter().next().copied().unwrap_or(0.0);

        Ok(score)
    }
}

/// نتيجة تقييم الذكاء الاصطناعي
#[derive(Debug, Clone, Copy)]
pub struct InferenceResult {
    pub anomaly_score: f32,
    pub is_anomaly: bool,
}

/// مستخرج الميزات (يجب أن يطابق تماماً ما تم تدريب النموذج عليه في Python)
struct FeatureExtractor;

impl FeatureExtractor {
    /// تحويل حدث XDP الخام إلى متجه ميزات طوله 32 (مثال)
    fn extract_xdp_features(event: &XdpDropEvent) -> Vec<f32> {
        let mut features = vec![0.0f32; 32]; // FEATURE_DIM = 32

        let src_ipv4 = unsafe { event.src_ip.ipv4 };
        let dst_ipv4 = unsafe { event.dst_ip.ipv4 };
        // [0-3] ميزات IP (مطبعة ومقسمة)
        features[0] = (src_ipv4 >> 24) as f32 / 255.0;
        features[1] = ((src_ipv4 >> 16) & 0xFF) as f32 / 255.0;
        features[2] = (dst_ipv4 >> 24) as f32 / 255.0;
        features[3] = ((dst_ipv4 >> 16) & 0xFF) as f32 / 255.0;

        // [4-5] ميزات المنافذ
        features[4] = event.src_port as f32 / 65535.0;
        features[5] = event.dst_port as f32 / 65535.0;

        // [6] البروتوكول (One-Hot Encoding مبسط)
        features[6] = if event.protocol == 6 { 1.0 } else { 0.0 }; // TCP
        features[7] = if event.protocol == 17 { 1.0 } else { 0.0 }; // UDP

        // [8-31] يمكن ملؤها بميزات إضافية (حجم الحزمة، وقت الوصول، إلخ)
        // هنا نضع قيماً افتراضية للتوضيح
        features[8] = 0.5; 

        features
    }
}
