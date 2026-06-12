//! GNN Attack Chain Detector 
//! Production-ready inference for multi-stage attack detection. 
use anyhow::{Context, Result}; 
use ndarray::Array2; 
use ort::{GraphOptimizationLevel, Session, SessionBuilder, Value}; 
use std::sync::Arc; 
use tokio::task; 
use tracing::{info, warn}; 
use crate::events::enrichment::EnrichedNetworkEvent; 

/// محرك كشف سلاسل الهجمات
pub struct GnnChainDetector { 
    session: Arc<Session>, 
    input_name: String, 
    output_name: String, 
} 

impl GnnChainDetector { 
    pub fn new(model_path: &str) -> Result<Self> { 
        info!(" Initializing GNN Chain Detector..."); 

        ort::init().with_execution_providers([ 
            ort::execution_providers::CPUExecutionProvider::default().build(), 
        ]).commit().context("Failed to init ONNX for GNN")?; 

        let session = SessionBuilder::new()? 
            .with_optimization_level(GraphOptimizationLevel::Level3)? 
            .with_intra_threads(2)? // GNN needs less threads, keep CPU free for agent 
            .commit_from_file(model_path) 
            .context("Failed to load GNN ONNX model")?; 

        let input_name = session.inputs.first().unwrap().name.clone(); 
        let output_name = session.outputs.first().unwrap().name.clone(); 

        Ok(Self { 
            session: Arc::new(session), 
            input_name, 
            output_name, 
        }) 
    } 

    /// تقييم سلسلة أحداث (مثلا : آخر 5 أحداث مرتبطة بنفس العملية) 
    pub async fn evaluate_chain(&self, events: &[EnrichedNetworkEvent]) -> Result<f32> { 
        // تبسيط للإنتاج: تحويل آخر 5 أحداث إلى مصفوفة مسطحة ( 160 = 32 * 5 ميزة) 
        // في النموذج المتقدم نمرر Graph Tensor حقيقي لكن هذا يضمن التوافق والسرعة القصوى الآن . 
        let mut flat_features = Vec::with_capacity(160); 
        for event in events.iter().take(5) { 
            let feats = super::features::FeatureExtractor::extract_network_features(event); 
            flat_features.extend_from_slice(&feats.vector); 
        } 

        // Pad to 160 if less than 5 events 
        while flat_features.len() < 160 { 
            flat_features.push(0.0); 
        } 

        let session = self.session.clone(); 
        let input_name = self.input_name.clone(); 
        let output_name = self.output_name.clone(); 

        let score = task::spawn_blocking(move || { 
            let input_tensor = Value::from_array(Array2::from_shape_vec((1, 160), flat_features)?)?; 
            let outputs = session.run(ort::inputs![input_name => input_tensor]?)?; 
            let output_tensor = outputs[&output_name].try_extract_tensor::<f32>()?; 
            Ok::<f32, anyhow::Error>(*output_tensor.iter().next().unwrap_or(&0.0)) 
        }).await.context("GNN inference task failed")??; 

        Ok(score) 
    } 
}
