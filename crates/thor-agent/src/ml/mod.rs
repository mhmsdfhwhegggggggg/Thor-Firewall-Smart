// Removed missing features and inference
pub mod gnn_detector; 
pub mod llm_reporter; 
pub mod ja4_analyzer;
pub mod l7_analyzer;
pub mod onnx_scorer;

use anyhow::Result; 
use std::sync::Arc; 
use tracing::info; 
use self::gnn_detector::GnnChainDetector; 
use self::llm_reporter::LlmReporter;
use self::l7_analyzer::L7Analyzer;

pub struct ThorAiCore { 
    pub gnn: Option<Arc<GnnChainDetector>>, 
    pub llm: Option<Arc<LlmReporter>>, 
} 

impl ThorAiCore { 
    pub fn new(gnn_path: Option<&str>) -> Result<Self> { 
        let mut gnn_engine = None; 
        if let Some(path) = gnn_path { 
            gnn_engine = Some(Arc::new(GnnChainDetector::new(path)?)); 
        } 

        // تشغيل Local LLM يفترض أن المستخدم شغل: (ollama run phi3) 
        let llm_reporter = Some(Arc::new(LlmReporter::new("http://localhost:11434", "phi3"))); 

        info!(" Thor AI Core initialized successfully."); 
        Ok(Self { 
            gnn: gnn_engine, 
            llm: llm_reporter, 
        }) 
    } 
}
