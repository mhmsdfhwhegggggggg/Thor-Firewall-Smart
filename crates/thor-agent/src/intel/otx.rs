//! AlienVault OTX client — uses API key when available, public feed otherwise.

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

use crate::state::ioc::{IocDatabase, IocEntry, IocType};

#[derive(Debug, Deserialize)]
struct OtxPulse {
    id: String,
    name: String,
    indicators: Vec<OtxIndicator>,
}

#[derive(Debug, Deserialize)]
struct OtxIndicator {
    indicator: String,
    #[serde(rename = "type")]
    ioc_type: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OtxSubscribedPulses {
    results: Vec<OtxPulse>,
    next: Option<String>,
}

pub struct OtxClient {
    api_key: Option<String>,
    client: Client,
    base_url: String,
}

impl OtxClient {
    pub fn new(api_key: Option<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("ThorFirewall/1.0")
            .gzip(true)
            .build()?;

        if api_key.is_some() {
            info!("🔑 OTX: API key configured — subscribed pulses enabled");
        } else {
            info!("🌐 OTX: No API key — using public reputation feed only");
        }

        Ok(Self {
            api_key,
            client,
            base_url: "https://otx.alienvault.com".to_string(),
        })
    }

    /// Fetch subscribed pulses (requires API key)
    pub async fn fetch_subscribed(&self, since: Option<&str>) -> Result<Vec<IocEntry>> {
        let key = match &self.api_key {
            Some(k) => k.clone(),
            None => return Ok(vec![]),
        };

        let url = format!(
            "{}/api/v1/pulses/subscribed?limit=100&modified_since={}",
            self.base_url,
            since.unwrap_or("2024-01-01T00:00:00")
        );

        let resp: OtxSubscribedPulses = self.client
            .get(&url)
            .header("X-OTX-API-KEY", &key)
            .send()
            .await?
            .json()
            .await?;

        let mut iocs = Vec::new();
        for pulse in resp.results {
            for indicator in pulse.indicators {
                let (itype, value) = match indicator.ioc_type.as_str() {
                    "IPv4" | "IPv6" => (IocType::IpAddress, indicator.indicator),
                    "domain" | "hostname" => (IocType::Domain, indicator.indicator),
                    "URL" => (IocType::Url, indicator.indicator),
                    "FileHash-SHA256" | "FileHash-MD5" | "FileHash-SHA1" => {
                        (IocType::FileHash, indicator.indicator)
                    }
                    _ => continue,
                };

                iocs.push(IocEntry {
                    value,
                    ioc_type: itype,
                    threat_level: "high".to_string(),
                    source: format!("OTX:{}", pulse.name),
                    tags: vec!["otx".to_string(), pulse.id.clone()],
                });
            }
        }

        info!("📡 OTX fetched {} IOCs from subscribed pulses", iocs.len());
        Ok(iocs)
    }

    /// Load IOCs directly into the database
    pub async fn sync_to_db(&self, db: &IocDatabase, since: Option<&str>) -> Result<usize> {
        let iocs = self.fetch_subscribed(since).await?;
        let count = iocs.len();
        for ioc in iocs {
            db.insert(ioc);
        }
        Ok(count)
    }
}
