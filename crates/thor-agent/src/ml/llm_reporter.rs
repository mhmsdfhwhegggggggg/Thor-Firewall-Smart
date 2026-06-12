//! Local LLM Security Reporter 
//! Generates human-readable incident reports locally using a lightweight LLM. 
use anyhow::{Context, Result}; 
use reqwest::Client; 
use serde::{Deserialize, Serialize}; 
use std::time::Duration; 
use tracing::{info, warn}; 
use crate::detection::DetectionResult; 

#[derive(Serialize)] 
struct OllamaRequest { 
    model: String, 
    prompt: String, 
    stream: bool, 
} 

#[derive(Deserialize)] 
struct OllamaResponse { 
    response: String, 
} 

pub struct LlmReporter { 
    client: Client, 
    endpoint: String, 
    model: String, 
} 

impl LlmReporter { 
    /// يتصل بخادم Ollama المحلي (المعيار الذهبي لل Local LLM حاليا) 
    pub fn new(endpoint: &str, model: &str) -> Self { 
        info!(" Initializing Local LLM Reporter at {} (Model: {})", endpoint, model); 
        Self { 
            client: Client::builder() 
                .timeout(Duration::from_secs(5)) // Timeout صارم لمنع تعليق النظام
                .build() 
                .unwrap(), 
            endpoint: format!("{}/api/generate", endpoint.trim_end_matches('/')), 
            model: model.to_string(), 
        } 
    } 

    /// توليد تقرير ذكي عن الحادث
    pub async fn generate_report(&self, process: &str, destination: &str, detection: &DetectionResult) -> Result<String> { 
        let prompt = format!( 
            "You are an elite cybersecurity analyst. An incident was detected.\n\
            Process: {}\nDestination: {}\nThreat Level: {:?}\nML Score: {:.2}\n\
            Matched Rules: {:?}\n\
            Provide a 3-sentence executive summary in Arabic: 1) What happened, 2) Impact, 3) Action taken.", 
            process, destination, detection.threat_level, detection.confidence_score, 
            detection.matched_sigma_rules 
        ); 

        let req = OllamaRequest { 
            model: self.model.clone(), 
            prompt, 
            stream: false, 
        }; 

        // استخدام tokio::time::timeout لضمان عدم تعليق النظام أبدا
        let response = tokio::time::timeout( 
            Duration::from_secs(5), 
            self.client.post(&self.endpoint).json(&req).send() 
        ).await.context("LLM request timed out")??.json::<OllamaResponse>().await?; 

        Ok(response.response.trim().to_string()) 
    } 
}
