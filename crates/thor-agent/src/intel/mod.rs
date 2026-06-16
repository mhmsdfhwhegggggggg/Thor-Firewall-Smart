//! ThorIntelSync — Threat Intelligence Synchronization Engine
//!
//! Pulls IOCs from free public threat intel feeds with zero external API deps:
//!   - AlienVault OTX (reputation data)
//!   - Abuse.ch URLhaus (malicious URLs + domains)
//!   - Abuse.ch ThreatFox (IPs, domains, hashes)
//!   - Abuse.ch Feodo Tracker (C2 IP blocklist)
//!   - Abuse.ch MalwareBazaar (file hashes)
//!   - CIRCL (hash lookup)
//!   - Emerging Threats IP blocklists
//!   - Tor exit nodes
//!   - Spamhaus (public DROP lists)
//!
//! All data is loaded into Thor's Bloom + DashMap IOC database.
//! Supports configurable refresh intervals per feed.

pub mod abuse_ch;
pub mod emerging_threats;
pub mod feeds;
pub mod otx;
pub mod stix;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tracing::{error, info, warn};

use crate::state::ioc::{IocDatabase, IocEntry, IocType};

pub use feeds::{FeedConfig, FeedFormat, IntelFeed};

// ─── Feed Registry ────────────────────────────────────────────────────────────

/// All public threat intel feeds with zero API key requirement
pub fn default_feeds() -> Vec<FeedConfig> {
    vec![
        // Abuse.ch Feodo Tracker — C2 IP blocklist (no key needed)
        FeedConfig {
            name: "Feodo Tracker C2".to_string(),
            url: "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv".to_string(),
            format: FeedFormat::FeodoCsv,
            ioc_type: IocType::IpAddress,
            refresh_secs: 3600,
            enabled: true,
        },
        // Abuse.ch URLhaus — malicious URLs
        FeedConfig {
            name: "URLhaus".to_string(),
            url: "https://urlhaus.abuse.ch/downloads/csv_online/".to_string(),
            format: FeedFormat::UrlhausCsv,
            ioc_type: IocType::Url,
            refresh_secs: 3600,
            enabled: true,
        },
        // Abuse.ch ThreatFox — IPs + domains + hashes
        FeedConfig {
            name: "ThreatFox IPs".to_string(),
            url: "https://threatfox.abuse.ch/export/csv/ip-port/recent/".to_string(),
            format: FeedFormat::ThreatFoxCsv,
            ioc_type: IocType::IpAddress,
            refresh_secs: 1800,
            enabled: true,
        },
        FeedConfig {
            name: "ThreatFox Domains".to_string(),
            url: "https://threatfox.abuse.ch/export/csv/domains/recent/".to_string(),
            format: FeedFormat::ThreatFoxCsv,
            ioc_type: IocType::Domain,
            refresh_secs: 1800,
            enabled: true,
        },
        FeedConfig {
            name: "ThreatFox Hashes".to_string(),
            url: "https://threatfox.abuse.ch/export/csv/full/".to_string(),
            format: FeedFormat::ThreatFoxCsv,
            ioc_type: IocType::FileHash,
            refresh_secs: 7200,
            enabled: true,
        },
        // Emerging Threats IP blocklist
        FeedConfig {
            name: "ET Compromised IPs".to_string(),
            url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt".to_string(),
            format: FeedFormat::PlainIpList,
            ioc_type: IocType::IpAddress,
            refresh_secs: 3600,
            enabled: true,
        },
        // Tor exit nodes
        FeedConfig {
            name: "Tor Exit Nodes".to_string(),
            url: "https://check.torproject.org/torbulkexitlist".to_string(),
            format: FeedFormat::PlainIpList,
            ioc_type: IocType::IpAddress,
            refresh_secs: 7200,
            enabled: true,
        },
        // Spamhaus DROP (Don't Route Or Peer)
        FeedConfig {
            name: "Spamhaus DROP".to_string(),
            url: "https://www.spamhaus.org/drop/drop.txt".to_string(),
            format: FeedFormat::SpamhausDrop,
            ioc_type: IocType::IpAddress,
            refresh_secs: 43200,
            enabled: true,
        },
        // AlienVault OTX reputation (no key needed for basic feed)
        FeedConfig {
            name: "OTX Malicious IPs".to_string(),
            url: "https://reputation.alienvault.com/reputation.data".to_string(),
            format: FeedFormat::OtxReputation,
            ioc_type: IocType::IpAddress,
            refresh_secs: 3600,
            enabled: true,
        },
        // MISP OSINT feed (no auth required)
        FeedConfig {
            name: "CIRCL OSINT".to_string(),
            url: "https://www.circl.lu/doc/misp/feed-osint/".to_string(),
            format: FeedFormat::MispJson,
            ioc_type: IocType::IpAddress,
            refresh_secs: 7200,
            enabled: false, // requires verification
        },
    ]
}

// ─── Intel Sync Engine ────────────────────────────────────────────────────────

pub struct IntelSyncEngine {
    ioc_db: Arc<IocDatabase>,
    feeds: Vec<FeedConfig>,
    http_client: reqwest::Client,
}

impl IntelSyncEngine {
    pub fn new(ioc_db: Arc<IocDatabase>, custom_feeds: Option<Vec<FeedConfig>>) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("ThorFirewall/1.0 (threat-intel-sync)")
            .gzip(true)
            .deflate(true)
            .build()?;

        let feeds = custom_feeds.unwrap_or_else(default_feeds);
        let enabled_count = feeds.iter().filter(|f| f.enabled).count();

        info!("🌐 ThorIntelSync initialized: {} feeds ({} enabled)", feeds.len(), enabled_count);

        Ok(Self { ioc_db, feeds, http_client })
    }

    /// Run initial sync for all enabled feeds
    pub async fn initial_sync(&self) -> usize {
        info!("🔄 Starting initial threat intel sync...");
        let mut total = 0usize;

        for feed in self.feeds.iter().filter(|f| f.enabled) {
            match self.sync_feed(feed).await {
                Ok(count) => {
                    info!("✅ [{}] loaded {} IOCs", feed.name, count);
                    total += count;
                }
                Err(e) => warn!("⚠️  [{}] sync failed: {}", feed.name, e),
            }
        }

        info!("🎯 Initial intel sync complete: {} total IOCs loaded", total);
        total
    }

    /// Start scheduled background sync loop
    pub async fn run_forever(&self) {
        info!("⏰ ThorIntelSync background refresh started");

        // Start per-feed refresh loops
        for feed in self.feeds.iter().filter(|f| f.enabled) {
            let feed_clone = feed.clone();
            let db = self.ioc_db.clone();
            let client = self.http_client.clone();
            let interval = feed.refresh_secs;

            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(interval));
                ticker.tick().await; // skip first tick (initial sync done separately)

                loop {
                    ticker.tick().await;
                    let engine = IntelSyncEngine {
                        ioc_db: db.clone(),
                        feeds: vec![feed_clone.clone()],
                        http_client: client.clone(),
                    };
                    match engine.sync_feed(&feed_clone).await {
                        Ok(n) => info!("🔄 [{}] refreshed: {} IOCs", feed_clone.name, n),
                        Err(e) => warn!("⚠️  [{}] refresh failed: {}", feed_clone.name, e),
                    }
                }
            });
        }

        // Keep running
        std::future::pending::<()>().await
    }

    async fn sync_feed(&self, feed: &FeedConfig) -> Result<usize> {
        let response = self.http_client
            .get(&feed.url)
            .send()
            .await?
            .text()
            .await?;

        let iocs = feeds::parse_feed(&response, feed)?;

        if iocs.is_empty() {
            return Ok(0);
        }

        let count = iocs.len();

        match feed.ioc_type {
            IocType::IpAddress => {
                let ips: Vec<String> = iocs.iter().map(|e| e.value.clone()).collect();
                self.ioc_db.bulk_insert_ips(ips, &feed.name);
            }
            _ => {
                for ioc in iocs {
                    self.ioc_db.insert(ioc);
                }
            }
        }

        Ok(count)
    }

    pub fn total_iocs(&self) -> usize {
        self.ioc_db.len()
    }
}

impl IntelSyncEngine {
    pub fn ioc_db(&self) -> &Arc<IocDatabase> {
        &self.ioc_db
    }
}
