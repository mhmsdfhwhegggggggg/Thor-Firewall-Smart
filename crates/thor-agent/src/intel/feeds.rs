//! Feed parsers for all supported threat intel formats

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::state::ioc::{IocEntry, IocType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedFormat {
    PlainIpList,      // One IP per line (Tor, ET)
    FeodoCsv,         // Feodo Tracker CSV
    UrlhausCsv,       // URLhaus CSV
    ThreatFoxCsv,     // ThreatFox CSV
    SpamhausDrop,     // Spamhaus DROP format (CIDR)
    OtxReputation,    // AlienVault OTX reputation.data
    MispJson,         // MISP JSON attribute export
    StixJson,         // STIX 2.1 bundle
    CsvColumn(usize), // Generic CSV, N-th column is the IOC
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    pub name: String,
    pub url: String,
    pub format: FeedFormat,
    pub ioc_type: IocType,
    pub refresh_secs: u64,
    pub enabled: bool,
}

pub struct IntelFeed;

/// Parse a raw feed response into IOC entries
pub fn parse_feed(content: &str, config: &FeedConfig) -> Result<Vec<IocEntry>> {
    match &config.format {
        FeedFormat::PlainIpList => parse_plain_ip_list(content, &config.name),
        FeedFormat::FeodoCsv => parse_feodo_csv(content, &config.name),
        FeedFormat::UrlhausCsv => parse_urlhaus_csv(content, &config.name),
        FeedFormat::ThreatFoxCsv => parse_threatfox_csv(content, &config.ioc_type, &config.name),
        FeedFormat::SpamhausDrop => parse_spamhaus_drop(content, &config.name),
        FeedFormat::OtxReputation => parse_otx_reputation(content, &config.name),
        FeedFormat::MispJson => parse_misp_json(content, &config.name),
        FeedFormat::StixJson => parse_stix_json(content, &config.ioc_type, &config.name),
        FeedFormat::CsvColumn(col) => parse_csv_column(content, *col, &config.ioc_type, &config.name),
    }
}

fn parse_plain_ip_list(content: &str, source: &str) -> Result<Vec<IocEntry>> {
    Ok(content
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let ip = l.trim().splitn(2, ' ').next()?.trim().to_string();
            if is_valid_ip(&ip) {
                Some(IocEntry {
                    value: ip,
                    ioc_type: IocType::IpAddress,
                    threat_level: "high".to_string(),
                    source: source.to_string(),
                    tags: vec!["blocklist".to_string()],
                })
            } else {
                None
            }
        })
        .collect())
}

fn parse_feodo_csv(content: &str, source: &str) -> Result<Vec<IocEntry>> {
    // Format: # first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
    Ok(content
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let parts: Vec<&str> = l.split(',').collect();
            if parts.len() < 6 { return None; }
            let ip = parts[1].trim().to_string();
            let malware = parts.get(5).unwrap_or(&"unknown").trim().to_string();
            if is_valid_ip(&ip) {
                Some(IocEntry {
                    value: ip,
                    ioc_type: IocType::IpAddress,
                    threat_level: "critical".to_string(),
                    source: source.to_string(),
                    tags: vec!["c2".to_string(), malware],
                })
            } else {
                None
            }
        })
        .collect())
}

fn parse_urlhaus_csv(content: &str, source: &str) -> Result<Vec<IocEntry>> {
    // Format: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
    Ok(content
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let parts: Vec<&str> = l.splitn(9, ',').collect();
            if parts.len() < 3 { return None; }
            let url = parts[2].trim().trim_matches('"').to_string();
            if url.starts_with("http://") || url.starts_with("https://") {
                let threat = parts.get(5).unwrap_or(&"malware").trim().trim_matches('"').to_string();
                Some(IocEntry {
                    value: url,
                    ioc_type: IocType::Url,
                    threat_level: "high".to_string(),
                    source: source.to_string(),
                    tags: vec!["malware_distribution".to_string(), threat],
                })
            } else {
                None
            }
        })
        .collect())
}

fn parse_threatfox_csv(content: &str, ioc_type: &IocType, source: &str) -> Result<Vec<IocEntry>> {
    // Format: first_seen_utc,ioc_value,ioc_type,threat_type,fk_malware,malware_alias,confidence_level,reference
    Ok(content
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let parts: Vec<&str> = l.splitn(8, ',').collect();
            if parts.len() < 7 { return None; }
            let value = parts[1].trim().trim_matches('"').to_string();
            let malware = parts[4].trim().trim_matches('"').to_string();
            let confidence = parts[6].trim().trim_matches('"').parse::<u32>().unwrap_or(0);

            if confidence < 50 { return None; }
            if value.is_empty() { return None; }

            let tl = if confidence >= 90 { "critical" } else if confidence >= 70 { "high" } else { "medium" };

            Some(IocEntry {
                value,
                ioc_type: ioc_type.clone(),
                threat_level: tl.to_string(),
                source: source.to_string(),
                tags: vec!["threatfox".to_string(), malware],
            })
        })
        .collect())
}

fn parse_spamhaus_drop(content: &str, source: &str) -> Result<Vec<IocEntry>> {
    // Format: 1.10.16.0/20 ; SBL...
    Ok(content
        .lines()
        .filter(|l| !l.starts_with(';') && !l.trim().is_empty())
        .filter_map(|l| {
            let cidr = l.split(';').next()?.trim().to_string();
            if cidr.contains('/') {
                Some(IocEntry {
                    value: cidr,
                    ioc_type: IocType::IpAddress,
                    threat_level: "high".to_string(),
                    source: source.to_string(),
                    tags: vec!["spam".to_string(), "spamhaus_drop".to_string()],
                })
            } else {
                None
            }
        })
        .collect())
}

fn parse_otx_reputation(content: &str, source: &str) -> Result<Vec<IocEntry>> {
    // Format: IP\tScore\tType\tCountry
    Ok(content
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let parts: Vec<&str> = l.split('\t').collect();
            let ip = parts[0].trim().to_string();
            let score = parts.get(1).and_then(|s| s.trim().parse::<u32>().ok()).unwrap_or(0);
            if score < 2 { return None; }
            if is_valid_ip(&ip) {
                let tl = if score >= 5 { "critical" } else if score >= 3 { "high" } else { "medium" };
                Some(IocEntry {
                    value: ip,
                    ioc_type: IocType::IpAddress,
                    threat_level: tl.to_string(),
                    source: source.to_string(),
                    tags: vec!["otx_reputation".to_string()],
                })
            } else {
                None
            }
        })
        .collect())
}

fn parse_misp_json(content: &str, source: &str) -> Result<Vec<IocEntry>> {
    use serde_json::Value;
    let json: Value = serde_json::from_str(content)
        .context("MISP JSON parse error")?;

    let mut result = Vec::new();

    if let Some(attributes) = json.get("Attribute").and_then(|a| a.as_array()) {
        for attr in attributes {
            let value = attr.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let attr_type = attr.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let category = attr.get("category").and_then(|v| v.as_str()).unwrap_or("");
            let to_ids = attr.get("to_ids").and_then(|v| v.as_bool()).unwrap_or(false);

            if !to_ids || value.is_empty() { continue; }

            let (ioc_type, tl) = match attr_type {
                "ip-dst" | "ip-src" | "ip-dst|port" => (IocType::IpAddress, "high"),
                "domain" | "hostname" => (IocType::Domain, "high"),
                "md5" | "sha1" | "sha256" => (IocType::FileHash, "critical"),
                "url" | "uri" => (IocType::Url, "medium"),
                _ => continue,
            };

            let val = if attr_type == "ip-dst|port" {
                value.split('|').next().unwrap_or(&value).to_string()
            } else {
                value
            };

            result.push(IocEntry {
                value: val,
                ioc_type,
                threat_level: tl.to_string(),
                source: source.to_string(),
                tags: vec![category.to_string(), "misp".to_string()],
            });
        }
    }

    Ok(result)
}

fn parse_stix_json(content: &str, ioc_type: &IocType, source: &str) -> Result<Vec<IocEntry>> {
    use serde_json::Value;
    let json: Value = serde_json::from_str(content)
        .context("STIX JSON parse error")?;

    let mut result = Vec::new();

    if let Some(objects) = json.get("objects").and_then(|o| o.as_array()) {
        for obj in objects {
            if obj.get("type").and_then(|t| t.as_str()) != Some("indicator") {
                continue;
            }
            let pattern = obj.get("pattern").and_then(|p| p.as_str()).unwrap_or("");
            // Parse STIX pattern: [ipv4-addr:value = '1.2.3.4']
            if let Some(value) = extract_stix_value(pattern) {
                result.push(IocEntry {
                    value,
                    ioc_type: ioc_type.clone(),
                    threat_level: "high".to_string(),
                    source: source.to_string(),
                    tags: vec!["stix".to_string()],
                });
            }
        }
    }

    Ok(result)
}

fn extract_stix_value(pattern: &str) -> Option<String> {
    // [ipv4-addr:value = '1.2.3.4']
    // [domain-name:value = 'evil.com']
    let start = pattern.find('\'')?;
    let end = pattern.rfind('\'')?;
    if end > start {
        Some(pattern[start + 1..end].to_string())
    } else {
        None
    }
}

fn parse_csv_column(content: &str, col: usize, ioc_type: &IocType, source: &str) -> Result<Vec<IocEntry>> {
    Ok(content
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let parts: Vec<&str> = l.split(',').collect();
            let value = parts.get(col)?.trim().trim_matches('"').to_string();
            if value.is_empty() { return None; }
            Some(IocEntry {
                value,
                ioc_type: ioc_type.clone(),
                threat_level: "medium".to_string(),
                source: source.to_string(),
                tags: vec![],
            })
        })
        .collect())
}

fn is_valid_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}
