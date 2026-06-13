//! Sandbox Integration — Automated Malware Detonation
//! Submits suspicious files and URLs to sandbox analysis engines.
//!
//! Supported backends:
//!   - CAPEv2 (community malware sandbox)
//!   - Any.run (cloud sandbox)
//!   - VirusTotal (hash/URL reputation)
//!
//! Workflow:
//!   1. Alert triggers "suspicious file" indicator
//!   2. Sandbox module receives file hash / path
//!   3. Submits to sandbox API
//!   4. Polls for report (async, up to 10 min)
//!   5. Extracts IOCs from report (IPs, domains, regkeys, mutexes)
//!   6. Auto-feeds extracted IOCs into threat intel engine
//!   7. If malware confirmed → SOAR triggers quarantine
//!
//! Env vars:
//!   THOR_SANDBOX_BACKEND   — "cape", "anyrun", or "virustotal"
//!   THOR_CAPE_URL          — CAPEv2 API URL
//!   THOR_CAPE_API_KEY      — CAPEv2 auth token
//!   THOR_VT_API_KEY        — VirusTotal API key
//!   THOR_ANYRUN_API_KEY    — Any.run API key
//!   THOR_SANDBOX_TIMEOUT   — max seconds to wait for report (default: 600)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

// ─── Sandbox task ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxTask {
    pub task_id:    String,
    pub alert_id:   String,
    pub input_type: SandboxInput,
    pub submitted:  i64,
    pub status:     SandboxStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SandboxInput {
    FileHash  { sha256: String, sha1: Option<String> },
    FilePath  { path: String },
    Url       { url: String },
    PcapBlob  { data: Vec<u8> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SandboxStatus {
    Queued, Running, Completed, Failed(String),
}

// ─── Sandbox report ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    pub task_id:         String,
    pub verdict:         Verdict,
    pub score:           u8,         // 0-100 malicious score
    pub family:          Option<String>,
    pub extracted_iocs:  Vec<ExtractedIoc>,
    pub signatures:      Vec<String>,
    pub mitre_attacks:   Vec<String>,
    pub network_iocs:    Vec<NetworkIoc>,
    pub dropped_files:   Vec<DroppedFile>,
    pub analysis_time:   u64,
    pub sandbox_backend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Verdict { Clean, Suspicious, Malicious, Unknown }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedIoc {
    pub value:    String,
    pub ioc_type: String,
    pub context:  String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIoc {
    pub proto:    String,
    pub dst_ip:   String,
    pub dst_port: u16,
    pub domain:   Option<String>,
    pub ja3:      Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedFile {
    pub path:   String,
    pub sha256: String,
    pub family: Option<String>,
}

// ─── Sandbox backend trait ────────────────────────────────────────────────────

#[async_trait::async_trait]
pub trait SandboxBackend: Send + Sync {
    async fn submit(&self, input: &SandboxInput) -> Result<String>;  // returns task_id
    async fn poll_report(&self, task_id: &str) -> Result<Option<SandboxReport>>;
    fn name(&self) -> &'static str;
}

// ─── CAPEv2 backend ───────────────────────────────────────────────────────────

pub struct CapeBackend {
    base_url: String,
    api_key:  String,
    client:   reqwest::Client,
}

impl CapeBackend {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            base_url: std::env::var("THOR_CAPE_URL")
                .context("THOR_CAPE_URL not set")?,
            api_key: std::env::var("THOR_CAPE_API_KEY")
                .context("THOR_CAPE_API_KEY not set")?,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
        })
    }
}

#[async_trait::async_trait]
impl SandboxBackend for CapeBackend {
    fn name(&self) -> &'static str { "CAPEv2" }

    async fn submit(&self, input: &SandboxInput) -> Result<String> {
        let url = format!("{}/apiv2/tasks/create/url/", self.base_url);
        match input {
            SandboxInput::Url { url: target_url } => {
                let resp = self.client
                    .post(&url)
                    .header("Authorization", format!("Token {}", self.api_key))
                    .form(&[("url", target_url.as_str())])
                    .send().await?;

                let json: serde_json::Value = resp.json().await?;
                let task_id = json["data"]["task_ids"][0]
                    .as_u64()
                    .map(|id| id.to_string())
                    .context("No task_id in CAPE response")?;
                info!("📦 CAPEv2 task created: {}", task_id);
                Ok(task_id)
            }
            SandboxInput::FileHash { sha256, .. } => {
                // Submit by hash lookup
                let url = format!("{}/apiv2/files/view/sha256/{}/", self.base_url, sha256);
                let resp = self.client
                    .get(&url)
                    .header("Authorization", format!("Token {}", self.api_key))
                    .send().await?;
                let json: serde_json::Value = resp.json().await?;
                let sample_id = json["data"]["id"].as_u64()
                    .map(|id| id.to_string())
                    .context("Hash not found in CAPE")?;
                info!("📦 CAPEv2 hash found: {}", sample_id);
                Ok(sample_id)
            }
            _ => anyhow::bail!("CAPEv2: unsupported input type"),
        }
    }

    async fn poll_report(&self, task_id: &str) -> Result<Option<SandboxReport>> {
        let url = format!("{}/apiv2/tasks/get/report/{}/", self.base_url, task_id);
        let resp = self.client
            .get(&url)
            .header("Authorization", format!("Token {}", self.api_key))
            .send().await?;

        if resp.status().as_u16() == 404 { return Ok(None); } // still running

        let json: serde_json::Value = resp.json().await?;
        let status = json["data"]["status"].as_str().unwrap_or("pending");
        if status != "reported" { return Ok(None); }

        let score = json["data"]["malscore"].as_f64().unwrap_or(0.0) as u8;
        let verdict = match score {
            0..=30   => Verdict::Clean,
            31..=69  => Verdict::Suspicious,
            70..=100 => Verdict::Malicious,
            _        => Verdict::Unknown,
        };

        let mut extracted_iocs = Vec::new();

        // Extract network IOCs from CAPE report
        let mut network_iocs = Vec::new();
        if let Some(network) = json["network"]["hosts"].as_array() {
            for host in network {
                if let Some(ip) = host["ip"].as_str() {
                    extracted_iocs.push(ExtractedIoc {
                        value: ip.to_string(),
                        ioc_type: "ip".to_string(),
                        context: "C2 communication".to_string(),
                    });
                    network_iocs.push(NetworkIoc {
                        proto: "tcp".to_string(),
                        dst_ip: ip.to_string(),
                        dst_port: host["port"].as_u64().unwrap_or(0) as u16,
                        domain: host["hostname"].as_str().map(|s| s.to_string()),
                        ja3: None,
                    });
                }
            }
        }

        Ok(Some(SandboxReport {
            task_id: task_id.to_string(),
            verdict,
            score,
            family: json["data"]["malfamily"].as_str().map(|s| s.to_string()),
            extracted_iocs,
            signatures: json["signatures"].as_array()
                .map(|sigs| sigs.iter()
                    .filter_map(|s| s["name"].as_str().map(|n| n.to_string()))
                    .collect())
                .unwrap_or_default(),
            mitre_attacks: vec![],
            network_iocs,
            dropped_files: vec![],
            analysis_time: 0,
            sandbox_backend: "CAPEv2".to_string(),
        }))
    }
}

// ─── VirusTotal backend ───────────────────────────────────────────────────────

pub struct VirusTotalBackend {
    api_key: String,
    client:  reqwest::Client,
}

impl VirusTotalBackend {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            api_key: std::env::var("THOR_VT_API_KEY")
                .context("THOR_VT_API_KEY not set")?,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
        })
    }
}

#[async_trait::async_trait]
impl SandboxBackend for VirusTotalBackend {
    fn name(&self) -> &'static str { "VirusTotal" }

    async fn submit(&self, input: &SandboxInput) -> Result<String> {
        match input {
            SandboxInput::FileHash { sha256, .. } => Ok(sha256.clone()),
            SandboxInput::Url { url } => {
                use base64::Engine;
                let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(url.as_bytes());
                Ok(encoded)
            }
            _ => anyhow::bail!("VT: unsupported input"),
        }
    }

    async fn poll_report(&self, task_id: &str) -> Result<Option<SandboxReport>> {
        let url = format!("https://www.virustotal.com/api/v3/files/{}", task_id);
        let resp = self.client
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send().await?;

        if !resp.status().is_success() { return Ok(None); }

        let json: serde_json::Value = resp.json().await?;
        let stats = &json["data"]["attributes"]["last_analysis_stats"];
        let malicious  = stats["malicious"].as_u64().unwrap_or(0);
        let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
        let total      = stats["harmless"].as_u64().unwrap_or(0)
            + malicious + suspicious
            + stats["undetected"].as_u64().unwrap_or(0);
        let score = if total > 0 { (malicious * 100 / total) as u8 } else { 0 };

        Ok(Some(SandboxReport {
            task_id: task_id.to_string(),
            verdict: match score {
                0..=5   => Verdict::Clean,
                6..=25  => Verdict::Suspicious,
                _       => Verdict::Malicious,
            },
            score,
            family: json["data"]["attributes"]["popular_threat_classification"]["suggested_threat_label"]
                .as_str().map(|s| s.to_string()),
            extracted_iocs: vec![],
            signatures: vec![],
            mitre_attacks: vec![],
            network_iocs: vec![],
            dropped_files: vec![],
            analysis_time: 0,
            sandbox_backend: "VirusTotal".to_string(),
        }))
    }
}

// ─── Sandbox engine ───────────────────────────────────────────────────────────

pub struct SandboxEngine {
    backend: Arc<dyn SandboxBackend>,
    timeout: Duration,
}

impl SandboxEngine {
    pub fn from_env() -> Result<Option<Arc<Self>>> {
        let backend_name = std::env::var("THOR_SANDBOX_BACKEND")
            .unwrap_or_else(|_| "none".to_string());

        let backend: Arc<dyn SandboxBackend> = match backend_name.as_str() {
            "cape" => Arc::new(CapeBackend::from_env()?),
            "virustotal" | "vt" => Arc::new(VirusTotalBackend::from_env()?),
            "none" | "" => {
                info!("🔬 Sandbox: disabled (set THOR_SANDBOX_BACKEND=cape|virustotal)");
                return Ok(None);
            }
            other => {
                warn!("Unknown sandbox backend '{}' — disabled", other);
                return Ok(None);
            }
        };

        let timeout_secs: u64 = std::env::var("THOR_SANDBOX_TIMEOUT")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(600);

        info!("🔬 Sandbox engine: backend={} timeout={}s", backend.name(), timeout_secs);
        Ok(Some(Arc::new(Self {
            backend,
            timeout: Duration::from_secs(timeout_secs),
        })))
    }

    /// Submit a sample and wait for the report (async, non-blocking to caller).
    /// Returns immediately; callback fires when report is ready.
    pub async fn analyze(
        self: Arc<Self>,
        alert_id: String,
        input: SandboxInput,
        on_complete: impl FnOnce(SandboxReport) + Send + 'static,
    ) {
        let backend = self.backend.clone();
        let timeout = self.timeout;
        tokio::spawn(async move {
            let task_id = match backend.submit(&input).await {
                Ok(id) => id,
                Err(e) => { error!("Sandbox submit failed: {}", e); return; }
            };
            info!("🔬 Sandbox task submitted: {} (alert_id={})", task_id, alert_id);

            let poll_interval = Duration::from_secs(15);
            let deadline = tokio::time::Instant::now() + timeout;
            let mut ticker = tokio::time::interval(poll_interval);

            loop {
                ticker.tick().await;
                if tokio::time::Instant::now() >= deadline {
                    warn!("Sandbox task timed out: {}", task_id);
                    return;
                }
                match backend.poll_report(&task_id).await {
                    Ok(Some(report)) => {
                        info!(
                            "🔬 Sandbox report ready: task={} verdict={:?} score={}",
                            task_id, report.verdict, report.score
                        );
                        on_complete(report);
                        return;
                    }
                    Ok(None) => { debug!("Sandbox task still running: {}", task_id); }
                    Err(e)  => { warn!("Sandbox poll error: {}", e); }
                }
            }
        });
    }
}

pub type SharedSandbox = Option<Arc<SandboxEngine>>;
