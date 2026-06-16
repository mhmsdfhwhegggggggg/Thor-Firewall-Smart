//! Emerging Threats feed integration — free IP/domain blocklists

use anyhow::Result;
use reqwest::Client;
use std::time::Duration;
use tracing::info;

use crate::state::ioc::{IocDatabase, IocEntry, IocType};

pub struct EmergingThreats {
    client: Client,
}

impl EmergingThreats {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("ThorFirewall/1.0")
            .gzip(true)
            .build()?;
        Ok(Self { client })
    }

    pub async fn sync_all(&self, db: &IocDatabase) -> usize {
        let mut total = 0usize;

        let feeds = vec![
            ("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "ET-Compromised"),
            ("https://rules.emergingthreats.net/blockrules/emerging-botcc.rules", "ET-BotCC"),
            ("https://www.spamhaus.org/drop/drop.txt", "Spamhaus-DROP"),
            ("https://www.spamhaus.org/drop/edrop.txt", "Spamhaus-EDROP"),
            ("https://check.torproject.org/torbulkexitlist", "Tor-Exit-Nodes"),
        ];

        for (url, source) in &feeds {
            match self.fetch_plain_ips(url).await {
                Ok(ips) => {
                    let count = ips.len();
                    db.bulk_insert_ips(ips, source);
                    info!("📋 {}: {} IPs loaded", source, count);
                    total += count;
                }
                Err(e) => tracing::warn!("ET feed {} failed: {}", source, e),
            }
        }

        total
    }

    async fn fetch_plain_ips(&self, url: &str) -> Result<Vec<String>> {
        let text = self.client.get(url).send().await?.text().await?;
        Ok(text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.starts_with(';') && !l.trim().is_empty())
            .filter_map(|l| {
                let ip = l.split_whitespace().next()?
                    .split(';').next()?
                    .trim().to_string();
                // Accept plain IPs and CIDRs
                if ip.contains('/') || ip.parse::<std::net::IpAddr>().is_ok() {
                    Some(ip)
                } else {
                    None
                }
            })
            .collect())
    }
}
