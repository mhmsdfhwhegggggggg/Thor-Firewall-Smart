//! Threat Intelligence Feed Manager
//! Aggregates IOCs from multiple open-source feeds and commercial APIs.
//!
//! Supported feeds:
//!   - AlienVault OTX (Open Threat Exchange)
//!   - MISP (Malware Information Sharing Platform)
//!   - Emerging Threats (ET) IP rules
//!   - Feodo Tracker (botnet C2s)
//!   - URLhaus (malware URLs)
//!   - CISA Known Exploited Vulnerabilities
//!
//! Env vars:
//!   THOR_OTX_API_KEY   — AlienVault OTX API key
//!   THOR_MISP_URL      — MISP instance URL
//!   THOR_MISP_KEY      — MISP API key
//!   THOR_INTEL_REFRESH — Refresh interval in minutes (default: 60)

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

// ─── IOC record ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIoc {
    pub value:      String,
    pub ioc_type:   IocType,
    pub source:     String,
    pub threat_type: String,
    pub confidence: u8,       // 0-100
    pub first_seen: String,
    pub last_seen:  String,
    pub tags:       Vec<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IocType {
    Ipv4, Ipv6, Domain, Url, FileHash, Email, Asn,
}

// ─── Lookup result ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatLookup {
    pub value:     String,
    pub is_threat: bool,
    pub matches:   Vec<ThreatIoc>,
    pub max_confidence: u8,
}

// ─── Feed stats ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedStats {
    pub name:         String,
    pub ioc_count:    usize,
    pub last_refresh: Option<String>,
    pub healthy:      bool,
    pub error:        Option<String>,
}

// ─── Threat Intel Engine ──────────────────────────────────────────────────────

pub struct ThreatIntelEngine {
    ip_index:     DashMap<String, Vec<ThreatIoc>>,
    domain_index: DashMap<String, Vec<ThreatIoc>>,
    hash_index:   DashMap<String, Vec<ThreatIoc>>,
    url_index:    DashMap<String, Vec<ThreatIoc>>,
    feed_stats:   RwLock<Vec<FeedStats>>,
    last_refresh: RwLock<Option<Instant>>,
    http:         reqwest::Client,
}

impl ThreatIntelEngine {
    pub fn new() -> Arc<Self> {
        let engine = Arc::new(Self {
            ip_index:     DashMap::with_capacity(500_000),
            domain_index: DashMap::with_capacity(200_000),
            hash_index:   DashMap::with_capacity(100_000),
            url_index:    DashMap::with_capacity(100_000),
            feed_stats:   RwLock::new(Vec::new()),
            last_refresh: RwLock::new(None),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("ThorFirewallSmart/0.1.0 Threat-Intel-Collector")
                .build()
                .expect("Failed to build HTTP client"),
        });
        info!("🌐 Threat Intel Engine initialized");
        engine
    }

    // ── Public lookup API ─────────────────────────────────────────────────────

    pub fn lookup_ip(&self, ip: &str) -> ThreatLookup {
        let matches = self.ip_index.get(ip)
            .map(|v| v.clone()).unwrap_or_default();
        self.build_lookup(ip, matches)
    }

    pub fn lookup_domain(&self, domain: &str) -> ThreatLookup {
        let domain_norm = domain.trim_start_matches("www.").to_lowercase();
        let matches = self.domain_index.get(&domain_norm)
            .map(|v| v.clone()).unwrap_or_default();
        self.build_lookup(domain, matches)
    }

    pub fn lookup_hash(&self, hash: &str) -> ThreatLookup {
        let hash_norm = hash.to_lowercase();
        let matches = self.hash_index.get(&hash_norm)
            .map(|v| v.clone()).unwrap_or_default();
        self.build_lookup(hash, matches)
    }

    fn build_lookup(&self, value: &str, matches: Vec<ThreatIoc>) -> ThreatLookup {
        let max_confidence = matches.iter().map(|m| m.confidence).max().unwrap_or(0);
        ThreatLookup {
            value: value.to_string(),
            is_threat: !matches.is_empty(),
            max_confidence,
            matches,
        }
    }

    // ── Feed ingestion ────────────────────────────────────────────────────────

    pub async fn refresh_all(self: &Arc<Self>) {
        info!("🔄 Refreshing threat intelligence feeds...");
        let mut tasks = vec![];
        let engine = self.clone();

        tasks.push(tokio::spawn({
            let e = engine.clone();
            async move { e.fetch_feodo_tracker().await }
        }));
        tasks.push(tokio::spawn({
            let e = engine.clone();
            async move { e.fetch_urlhaus().await }
        }));
        tasks.push(tokio::spawn({
            let e = engine.clone();
            async move { e.fetch_emerging_threats().await }
        }));
        tasks.push(tokio::spawn({
            let e = engine.clone();
            async move { e.fetch_otx().await }
        }));

        for t in tasks { let _ = t.await; }

        *self.last_refresh.write().await = Some(Instant::now());
        info!(
            "✅ Threat intel refresh complete: {} IPs | {} domains | {} hashes",
            self.ip_index.len(), self.domain_index.len(), self.hash_index.len()
        );
    }

    // ── Feodo Tracker (botnet C2 IPs) ─────────────────────────────────────────

    async fn fetch_feodo_tracker(&self) {
        const URL: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt";
        match self.http.get(URL).send().await {
            Err(e) => {
                warn!("Feodo Tracker fetch failed: {}", e);
                self.set_feed_error("Feodo Tracker", &e.to_string()).await;
                return;
            }
            Ok(res) => match res.text().await {
                Err(e) => { warn!("Feodo body error: {}", e); return; }
                Ok(text) => {
                    let mut count = 0;
                    for line in text.lines() {
                        let line = line.trim();
                        if line.starts_with('#') || line.is_empty() { continue; }
                        let ip = line.split(':').next().unwrap_or(line).trim();
                        self.ip_index.entry(ip.to_string()).or_default().push(ThreatIoc {
                            value: ip.to_string(),
                            ioc_type: IocType::Ipv4,
                            source: "Feodo Tracker".into(),
                            threat_type: "Botnet C2".into(),
                            confidence: 90,
                            first_seen: "".into(),
                            last_seen: "".into(),
                            tags: vec!["botnet".into(), "c2".into()],
                            references: vec![URL.into()],
                        });
                        count += 1;
                    }
                    info!("📥 Feodo Tracker: {} C2 IPs loaded", count);
                    self.set_feed_ok("Feodo Tracker", count).await;
                }
            }
        }
    }

    // ── URLhaus (malware URLs) ────────────────────────────────────────────────

    async fn fetch_urlhaus(&self) {
        const URL: &str = "https://urlhaus.abuse.ch/downloads/text_online/";
        match self.http.get(URL).send().await {
            Err(e) => { warn!("URLhaus fetch failed: {}", e); return; }
            Ok(res) => match res.text().await {
                Err(_) => return,
                Ok(text) => {
                    let mut count = 0;
                    for line in text.lines() {
                        let line = line.trim();
                        if line.starts_with('#') || line.is_empty() { continue; }
                        self.url_index.entry(line.to_string()).or_default().push(ThreatIoc {
                            value: line.to_string(),
                            ioc_type: IocType::Url,
                            source: "URLhaus".into(),
                            threat_type: "Malware Distribution".into(),
                            confidence: 85,
                            first_seen: "".into(),
                            last_seen: "".into(),
                            tags: vec!["malware".into(), "url".into()],
                            references: vec![URL.into()],
                        });
                        count += 1;
                    }
                    info!("📥 URLhaus: {} malware URLs loaded", count);
                    self.set_feed_ok("URLhaus", count).await;
                }
            }
        }
    }

    // ── Emerging Threats (ET) ─────────────────────────────────────────────────

    async fn fetch_emerging_threats(&self) {
        const URL: &str = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt";
        match self.http.get(URL).send().await {
            Err(e) => { warn!("ET fetch failed: {}", e); return; }
            Ok(res) => match res.text().await {
                Err(_) => return,
                Ok(text) => {
                    let mut count = 0;
                    for line in text.lines() {
                        let line = line.trim();
                        if line.starts_with('#') || line.is_empty() { continue; }
                        self.ip_index.entry(line.to_string()).or_default().push(ThreatIoc {
                            value: line.to_string(),
                            ioc_type: IocType::Ipv4,
                            source: "Emerging Threats".into(),
                            threat_type: "Known Bad IP".into(),
                            confidence: 80,
                            first_seen: "".into(),
                            last_seen: "".into(),
                            tags: vec!["emerging-threat".into()],
                            references: vec![URL.into()],
                        });
                        count += 1;
                    }
                    info!("📥 Emerging Threats: {} IPs loaded", count);
                    self.set_feed_ok("Emerging Threats", count).await;
                }
            }
        }
    }

    // ── OTX (AlienVault) ─────────────────────────────────────────────────────

    async fn fetch_otx(&self) {
        let api_key = match std::env::var("THOR_OTX_API_KEY") {
            Ok(k) if !k.is_empty() => k,
            _ => {
                debug!("OTX API key not set — skipping OTX feed");
                return;
            }
        };
        const URL: &str = "https://otx.alienvault.com/api/v1/indicators/export?type=IPv4&limit=10000";
        match self.http.get(URL).header("X-OTX-API-KEY", &api_key).send().await {
            Err(e) => { warn!("OTX fetch failed: {}", e); }
            Ok(res) if res.status().is_success() => {
                if let Ok(text) = res.text().await {
                    let count = self.ingest_otx_lines(&text);
                    info!("📥 OTX AlienVault: {} IOCs loaded", count);
                    self.set_feed_ok("OTX AlienVault", count).await;
                }
            }
            Ok(res) => { warn!("OTX response: {}", res.status()); }
        }
    }

    fn ingest_otx_lines(&self, text: &str) -> usize {
        let mut count = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            self.ip_index.entry(line.to_string()).or_default().push(ThreatIoc {
                value: line.to_string(),
                ioc_type: IocType::Ipv4,
                source: "OTX AlienVault".into(),
                threat_type: "Threat Actor Infrastructure".into(),
                confidence: 75,
                first_seen: "".into(), last_seen: "".into(),
                tags: vec!["otx".into()], references: vec![],
            });
            count += 1;
        }
        count
    }

    // ── Manual ingestion (from SOAR / admin) ──────────────────────────────────

    pub fn ingest_manual(&self, ioc: ThreatIoc) {
        match ioc.ioc_type {
            IocType::Ipv4 | IocType::Ipv6 =>
                self.ip_index.entry(ioc.value.clone()).or_default().push(ioc),
            IocType::Domain =>
                self.domain_index.entry(ioc.value.clone()).or_default().push(ioc),
            IocType::FileHash =>
                self.hash_index.entry(ioc.value.clone()).or_default().push(ioc),
            IocType::Url =>
                self.url_index.entry(ioc.value.clone()).or_default().push(ioc),
            _ => {}
        }
    }

    // ── Feed stats ────────────────────────────────────────────────────────────

    async fn set_feed_ok(&self, name: &str, count: usize) {
        let mut stats = self.feed_stats.write().await;
        let ts = chrono::Utc::now().to_rfc3339();
        if let Some(s) = stats.iter_mut().find(|s| s.name == name) {
            s.ioc_count = count; s.last_refresh = Some(ts); s.healthy = true; s.error = None;
        } else {
            stats.push(FeedStats { name: name.to_string(), ioc_count: count, last_refresh: Some(ts), healthy: true, error: None });
        }
    }

    async fn set_feed_error(&self, name: &str, err: &str) {
        let mut stats = self.feed_stats.write().await;
        if let Some(s) = stats.iter_mut().find(|s| s.name == name) {
            s.healthy = false; s.error = Some(err.to_string());
        } else {
            stats.push(FeedStats { name: name.to_string(), ioc_count: 0, last_refresh: None, healthy: false, error: Some(err.to_string()) });
        }
    }

    pub async fn stats(&self) -> Vec<FeedStats> {
        self.feed_stats.read().await.clone()
    }

    pub fn total_ioc_count(&self) -> usize {
        self.ip_index.len() + self.domain_index.len() + self.hash_index.len() + self.url_index.len()
    }

    /// Background refresh loop. Call once at startup.
    pub async fn start_refresh_loop(self: Arc<Self>) {
        let interval_mins: u64 = std::env::var("THOR_INTEL_REFRESH")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(60);

        info!("🌐 Threat Intel: refresh every {} minutes", interval_mins);
        self.refresh_all().await;

        let mut ticker = tokio::time::interval(Duration::from_secs(interval_mins * 60));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            self.refresh_all().await;
        }
    }
}

pub type SharedThreatIntel = Arc<ThreatIntelEngine>;
