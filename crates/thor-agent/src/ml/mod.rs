pub mod features; 
pub mod inference; // الكود السابق ل UEBA
pub mod gnn_detector; 
pub mod llm_reporter; 
pub mod ja4_analyzer;
pub mod l7_analyzer;

use anyhow::Result; 
use std::sync::Arc; 
use tracing::info; 
use self::gnn_detector::GnnChainDetector; 
use self::inference::MlEngine; 
use self::llm_reporter::LlmReporter;
use self::l7_analyzer::L7Analyzer;

pub struct ThorAiCore { 
    pub ueba: Option<Arc<MlEngine>>, 
    pub gnn: Option<Arc<GnnChainDetector>>, 
    pub llm: Option<Arc<LlmReporter>>, 
} 

impl ThorAiCore { 
    pub fn new(ueba_path: Option<&str>, gnn_path: Option<&str>) -> Result<Self> { 
        let mut ueba_engine = None; 
        if let Some(path) = ueba_path { 
            ueba_engine = Some(Arc::new(MlEngine::new(path, 0.85)?)); 
        } 

        let mut gnn_engine = None; 
        if let Some(path) = gnn_path { 
            gnn_engine = Some(Arc::new(GnnChainDetector::new(path)?)); 
        } 

        // تشغيل Local LLM يفترض أن المستخدم شغل: (ollama run phi3) 
        let llm_reporter = Some(Arc::new(LlmReporter::new("http://localhost:11434", "phi3"))); 

        info!(" Thor AI Core initialized successfully."); 
        Ok(Self { 
            ueba: ueba_engine, 
            gnn: gnn_engine, 
            llm: llm_reporter, 
        }) 
    } 
}
