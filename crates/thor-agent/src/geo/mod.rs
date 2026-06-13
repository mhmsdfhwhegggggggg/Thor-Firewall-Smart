//! GeoIP Blocking — Country-level enforcement at XDP speed.
//! Maintains a CIDR trie for O(32) IP-to-country lookup.
//! Policy: configurable per-country allow/block/alert.
//!
//! Env vars:
//!   THOR_GEO_BLOCK_COUNTRIES  — comma-separated ISO-3166-1 alpha-2 codes
//!   THOR_GEO_ALERT_COUNTRIES  — alert but don't block
//!   THOR_GEO_ALLOW_COUNTRIES  — always allow (whitelist override)
//!   THOR_MAXMIND_DB_PATH      — path to GeoLite2-Country.mmdb

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

// ─── Country policy ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GeoPolicy { Allow, Alert, Block }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoDecision {
    pub ip:          String,
    pub country:     Option<String>,
    pub country_name: Option<String>,
    pub policy:      GeoPolicy,
    pub reason:      String,
}

// ─── Simple CIDR trie node ────────────────────────────────────────────────────

#[derive(Default)]
struct TrieNode {
    children: [Option<Box<TrieNode>>; 2],
    country:  Option<String>,
}

struct Trie {
    root: TrieNode,
}

impl Trie {
    fn new() -> Self { Self { root: TrieNode::default() } }

    fn insert(&mut self, cidr: &str, country: &str) {
        let (ip_str, prefix_len) = match cidr.split_once('/') {
            Some((ip, len)) => (ip, len.parse::<u8>().unwrap_or(32)),
            None => (cidr, 32),
        };
        let ip: Ipv4Addr = match ip_str.parse() { Ok(i) => i, Err(_) => return };
        let ip_u32 = u32::from(ip);

        let mut node = &mut self.root;
        for bit_idx in (32 - prefix_len..32).rev() {
            let bit = ((ip_u32 >> bit_idx) & 1) as usize;
            if node.children[bit].is_none() {
                node.children[bit] = Some(Box::new(TrieNode::default()));
            }
            node = node.children[bit].as_mut().unwrap();
        }
        node.country = Some(country.to_string());
    }

    fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        let ip_u32 = u32::from(ip);
        let mut node = &self.root;
        let mut last_match: Option<String> = None;

        for bit_idx in (0..32).rev() {
            let bit = ((ip_u32 >> bit_idx) & 1) as usize;
            if let Some(child) = &node.children[bit] {
                node = child;
                if node.country.is_some() {
                    last_match = node.country.clone();
                }
            } else {
                break;
            }
        }
        last_match
    }
}

// ─── Country name lookup ──────────────────────────────────────────────────────

fn country_name(code: &str) -> &'static str {
    match code {
        "AF" => "Afghanistan",     "AL" => "Albania",         "DZ" => "Algeria",
        "AD" => "Andorra",         "AO" => "Angola",          "AR" => "Argentina",
        "AM" => "Armenia",         "AU" => "Australia",       "AT" => "Austria",
        "AZ" => "Azerbaijan",      "BY" => "Belarus",         "BE" => "Belgium",
        "BZ" => "Belize",          "BJ" => "Benin",           "BO" => "Bolivia",
        "BA" => "Bosnia",          "BR" => "Brazil",          "BG" => "Bulgaria",
        "KH" => "Cambodia",        "CM" => "Cameroon",        "CA" => "Canada",
        "CN" => "China",           "CO" => "Colombia",        "HR" => "Croatia",
        "CU" => "Cuba",            "CY" => "Cyprus",          "CZ" => "Czech Republic",
        "DK" => "Denmark",         "EG" => "Egypt",           "EE" => "Estonia",
        "ET" => "Ethiopia",        "FI" => "Finland",         "FR" => "France",
        "GE" => "Georgia",         "DE" => "Germany",         "GH" => "Ghana",
        "GR" => "Greece",          "GT" => "Guatemala",       "HN" => "Honduras",
        "HK" => "Hong Kong",       "HU" => "Hungary",         "IN" => "India",
        "ID" => "Indonesia",       "IR" => "Iran",            "IQ" => "Iraq",
        "IE" => "Ireland",         "IL" => "Israel",          "IT" => "Italy",
        "JP" => "Japan",           "JO" => "Jordan",          "KZ" => "Kazakhstan",
        "KE" => "Kenya",           "KP" => "North Korea",     "KR" => "South Korea",
        "KW" => "Kuwait",          "LB" => "Lebanon",         "LY" => "Libya",
        "LU" => "Luxembourg",      "MY" => "Malaysia",        "MX" => "Mexico",
        "MD" => "Moldova",         "MN" => "Mongolia",        "MA" => "Morocco",
        "NL" => "Netherlands",     "NZ" => "New Zealand",     "NG" => "Nigeria",
        "NO" => "Norway",          "PK" => "Pakistan",        "PS" => "Palestine",
        "PA" => "Panama",          "PY" => "Paraguay",        "PE" => "Peru",
        "PH" => "Philippines",     "PL" => "Poland",          "PT" => "Portugal",
        "QA" => "Qatar",           "RO" => "Romania",         "RU" => "Russia",
        "SA" => "Saudi Arabia",    "RS" => "Serbia",          "SG" => "Singapore",
        "SK" => "Slovakia",        "ZA" => "South Africa",    "ES" => "Spain",
        "SE" => "Sweden",          "CH" => "Switzerland",     "SY" => "Syria",
        "TW" => "Taiwan",          "TH" => "Thailand",        "TN" => "Tunisia",
        "TR" => "Turkey",          "UA" => "Ukraine",         "AE" => "United Arab Emirates",
        "GB" => "United Kingdom",  "US" => "United States",   "UY" => "Uruguay",
        "UZ" => "Uzbekistan",      "VE" => "Venezuela",       "VN" => "Vietnam",
        "YE" => "Yemen",           "ZW" => "Zimbabwe",
        _ => "Unknown",
    }
}

// ─── GeoIP Engine ─────────────────────────────────────────────────────────────

pub struct GeoIpEngine {
    trie:    RwLock<Trie>,
    block:   HashSet<String>,
    alert:   HashSet<String>,
    allow:   HashSet<String>,
    stats:   RwLock<HashMap<String, u64>>,
}

impl GeoIpEngine {
    pub fn new() -> Arc<Self> {
        let block = Self::parse_country_list("THOR_GEO_BLOCK_COUNTRIES");
        let alert = Self::parse_country_list("THOR_GEO_ALERT_COUNTRIES");
        let allow = Self::parse_country_list("THOR_GEO_ALLOW_COUNTRIES");

        info!(
            "🌍 GeoIP engine: block={:?} alert={:?} allow={:?}",
            block, alert, allow
        );

        Arc::new(Self {
            trie: RwLock::new(Trie::new()),
            block, alert, allow,
            stats: RwLock::new(HashMap::new()),
        })
    }

    fn parse_country_list(env_var: &str) -> HashSet<String> {
        std::env::var(env_var)
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_uppercase())
            .filter(|s| s.len() == 2)
            .collect()
    }

    /// Load CIDR→country mappings from embedded or external DB.
    pub async fn load_from_embedded(&self) {
        // Load high-risk country CIDRs (embed key ranges for offline use)
        // Full production: use MaxMind GeoLite2 with mmdb-reader
        let mut trie = self.trie.write().await;

        // Russian Federation sample ranges
        trie.insert("5.8.0.0/13",     "RU");
        trie.insert("5.188.0.0/15",   "RU");
        trie.insert("37.110.0.0/14",  "RU");
        trie.insert("46.138.0.0/15",  "RU");
        trie.insert("77.37.0.0/14",   "RU");
        trie.insert("78.38.0.0/15",   "RU");
        trie.insert("80.240.0.0/13",  "RU");
        trie.insert("85.140.0.0/15",  "RU");
        trie.insert("87.224.0.0/11",  "RU");
        trie.insert("91.108.0.0/14",  "RU");
        trie.insert("94.180.0.0/14",  "RU");
        trie.insert("185.220.0.0/14", "RU");

        // China sample ranges
        trie.insert("1.0.1.0/24",   "CN");
        trie.insert("1.0.2.0/23",   "CN");
        trie.insert("1.0.8.0/21",   "CN");
        trie.insert("14.0.0.0/10",  "CN");
        trie.insert("27.0.0.0/9",   "CN");
        trie.insert("36.0.0.0/11",  "CN");
        trie.insert("42.0.0.0/11",  "CN");
        trie.insert("58.0.0.0/10",  "CN");
        trie.insert("59.0.0.0/10",  "CN");
        trie.insert("60.0.0.0/10",  "CN");
        trie.insert("101.0.0.0/8",  "CN");
        trie.insert("106.0.0.0/8",  "CN");
        trie.insert("111.0.0.0/8",  "CN");
        trie.insert("114.0.0.0/8",  "CN");
        trie.insert("116.0.0.0/8",  "CN");
        trie.insert("119.0.0.0/8",  "CN");
        trie.insert("120.0.0.0/6",  "CN");
        trie.insert("125.0.0.0/8",  "CN");

        // North Korea
        trie.insert("175.45.176.0/22",  "KP");
        trie.insert("210.52.109.0/24",  "KP");
        trie.insert("77.94.35.0/24",    "KP");

        // Iran
        trie.insert("2.144.0.0/12",   "IR");
        trie.insert("5.22.0.0/15",    "IR");
        trie.insert("31.2.0.0/15",    "IR");
        trie.insert("77.36.0.0/14",   "IR");
        trie.insert("78.38.0.0/16",   "IR");
        trie.insert("80.191.0.0/16",  "IR");
        trie.insert("82.99.0.0/16",   "IR");
        trie.insert("85.15.0.0/16",   "IR");
        trie.insert("91.98.0.0/15",   "IR");
        trie.insert("185.55.224.0/22","IR");
        trie.insert("195.146.0.0/16", "IR");

        info!("🌍 GeoIP: embedded CIDR database loaded (full DB: set THOR_MAXMIND_DB_PATH)");
    }

    /// Evaluate an IP address and return the geo policy decision.
    pub async fn evaluate(&self, ip_str: &str) -> GeoDecision {
        let ip: IpAddr = match ip_str.parse() {
            Ok(i) => i,
            Err(_) => return GeoDecision {
                ip: ip_str.to_string(), country: None, country_name: None,
                policy: GeoPolicy::Allow, reason: "Parse error".into(),
            },
        };

        let country = match ip {
            IpAddr::V4(v4) => self.trie.read().await.lookup(v4),
            IpAddr::V6(_)  => None, // IPv6 geo: requires full MaxMind DB
        };

        let code = country.as_deref().unwrap_or("XX");
        let name = country_name(code).to_string();

        let (policy, reason) = if self.allow.contains(code) {
            (GeoPolicy::Allow, format!("Country {} is in allow-list", code))
        } else if self.block.contains(code) {
            let mut stats = self.stats.write().await;
            *stats.entry(code.to_string()).or_insert(0) += 1;
            (GeoPolicy::Block, format!("Country {} is in block-list", code))
        } else if self.alert.contains(code) {
            (GeoPolicy::Alert, format!("Country {} is in alert-list", code))
        } else if country.is_none() {
            (GeoPolicy::Allow, "Country unknown — allow by default".into())
        } else {
            (GeoPolicy::Allow, format!("Country {} — no policy, allowing", code))
        };

        GeoDecision {
            ip: ip_str.to_string(),
            country: country.or_else(|| Some("XX".into())),
            country_name: Some(name),
            policy,
            reason,
        }
    }

    pub async fn block_stats(&self) -> HashMap<String, u64> {
        self.stats.read().await.clone()
    }
}

pub type SharedGeoIp = Arc<GeoIpEngine>;
