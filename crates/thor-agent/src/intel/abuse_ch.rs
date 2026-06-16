//! Abuse.ch feed integration — URLhaus, ThreatFox, Feodo, MalwareBazaar
//! All feeds are free and require no API key for basic access.

use anyhow::Result;
use reqwest::Client;
use std::time::Duration;
use tracing::info;

use crate::state::ioc::{IocDatabase, IocEntry, IocType};

pub struct AbuseCh {
    client: Client,
}

impl AbuseCh {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("ThorFirewall/1.0 (threat-intel)")
            .gzip(true)
            .build()?;
        Ok(Self { client })
    }

    /// Fetch and load all Abuse.ch feeds into the IOC database
    pub async fn sync_all(&self, db: &IocDatabase) -> usize {
        let mut total = 0;

        total += self.sync_feodo(db).await.unwrap_or_else(|e| { tracing::warn!("Feodo: {}", e); 0 });
        total += self.sync_threatfox_ips(db).await.unwrap_or_else(|e| { tracing::warn!("ThreatFox IPs: {}", e); 0 });
        total += self.sync_threatfox_domains(db).await.unwrap_or_else(|e| { tracing::warn!("ThreatFox domains: {}", e); 0 });
        total += self.sync_malwarebazaar_hashes(db).await.unwrap_or_else(|e| { tracing::warn!("MalwareBazaar: {}", e); 0 });

        info!("🦈 Abuse.ch total loaded: {} IOCs", total);
        total
    }

    async fn sync_feodo(&self, db: &IocDatabase) -> Result<usize> {
        let text = self.client
            .get("https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv")
            .send().await?.text().await?;

        let ips: Vec<String> = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .filter_map(|l| {
                let ip = l.split(',').nth(1)?.trim().to_string();
                if ip.parse::<std::net::IpAddr>().is_ok() { Some(ip) } else { None }
            })
            .collect();

        let count = ips.len();
        db.bulk_insert_ips(ips, "Feodo-C2");
        info!("🔴 Feodo C2 blocklist: {} IPs loaded", count);
        Ok(count)
    }

    async fn sync_threatfox_ips(&self, db: &IocDatabase) -> Result<usize> {
        // ThreatFox API: no key needed for CSV exports
        let resp = self.client
            .post("https://threatfox-api.abuse.ch/api/v1/")
            .json(&serde_json::json!({ "query": "get_iocs", "days": 7 }))
            .send().await?;

        let json: serde_json::Value = resp.json().await?;
        let mut count = 0;

        if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
            for item in data {
                let ioc_value = item.get("ioc_value").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let ioc_type_str = item.get("ioc_type").and_then(|v| v.as_str()).unwrap_or("");
                let malware = item.get("malware").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                let confidence = item.get("confidence_level").and_then(|v| v.as_u64()).unwrap_or(0);

                if confidence < 50 || ioc_value.is_empty() { continue; }

                let itype = match ioc_type_str {
                    "ip:port" => {
                        // Strip port
                        let ip = ioc_value.split(':').next().unwrap_or(&ioc_value).to_string();
                        db.insert(IocEntry {
                            value: ip,
                            ioc_type: IocType::IpAddress,
                            threat_level: "critical".to_string(),
                            source: "ThreatFox".to_string(),
                            tags: vec![malware, "c2".to_string()],
                        });
                        count += 1;
                        continue;
                    }
                    "domain" => IocType::Domain,
                    "url" => IocType::Url,
                    "md5_hash" | "sha256_hash" | "sha1_hash" => IocType::FileHash,
                    _ => continue,
                };

                db.insert(IocEntry {
                    value: ioc_value,
                    ioc_type: itype,
                    threat_level: "high".to_string(),
                    source: "ThreatFox".to_string(),
                    tags: vec![malware],
                });
                count += 1;
            }
        }

        info!("🦊 ThreatFox: {} IOCs loaded", count);
        Ok(count)
    }

    async fn sync_threatfox_domains(&self, db: &IocDatabase) -> Result<usize> {
        let resp = self.client
            .post("https://threatfox-api.abuse.ch/api/v1/")
            .json(&serde_json::json!({
                "query": "get_iocs",
                "days": 7,
                "ioc_type": "domain"
            }))
            .send().await?;

        let json: serde_json::Value = resp.json().await?;
        let mut count = 0;

        if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
            for item in data {
                let domain = item.get("ioc_value").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if domain.is_empty() { continue; }
                db.insert(IocEntry {
                    value: domain,
                    ioc_type: IocType::Domain,
                    threat_level: "high".to_string(),
                    source: "ThreatFox".to_string(),
                    tags: vec!["c2_domain".to_string()],
                });
                count += 1;
            }
        }

        info!("🌐 ThreatFox domains: {} loaded", count);
        Ok(count)
    }

    async fn sync_malwarebazaar_hashes(&self, db: &IocDatabase) -> Result<usize> {
        let resp = self.client
            .post("https://mb-api.abuse.ch/api/v1/")
            .form(&[("query", "get_recent"), ("selector", "time")])
            .send().await?;

        let json: serde_json::Value = resp.json().await?;
        let mut count = 0;

        if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
            for item in data.iter().take(500) {
                let sha256 = item.get("sha256_hash").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let malware = item.get("signature").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                if sha256.is_empty() { continue; }

                db.insert(IocEntry {
                    value: sha256,
                    ioc_type: IocType::FileHash,
                    threat_level: "critical".to_string(),
                    source: "MalwareBazaar".to_string(),
                    tags: vec![malware, "malware_sample".to_string()],
                });
                count += 1;
            }
        }

        info!("💀 MalwareBazaar: {} hashes loaded", count);
        Ok(count)
    }
}
