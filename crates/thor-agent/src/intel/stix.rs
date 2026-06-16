//! STIX 2.1 parser for structured threat intelligence

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::state::ioc::{IocEntry, IocType};

#[derive(Debug, Deserialize)]
pub struct StixBundle {
    #[serde(rename = "type")]
    pub bundle_type: String,
    pub id: String,
    pub objects: Vec<StixObject>,
}

#[derive(Debug, Deserialize)]
pub struct StixObject {
    #[serde(rename = "type")]
    pub obj_type: String,
    pub id: Option<String>,
    pub name: Option<String>,
    pub pattern: Option<String>,
    pub pattern_type: Option<String>,
    pub indicator_types: Option<Vec<String>>,
    pub confidence: Option<u32>,
    pub labels: Option<Vec<String>>,
    pub description: Option<String>,
}

pub struct StixParser;

impl StixParser {
    /// Parse a STIX 2.1 JSON bundle into IOC entries
    pub fn parse(content: &str, source: &str) -> Result<Vec<IocEntry>> {
        let bundle: StixBundle = serde_json::from_str(content)
            .context("Invalid STIX bundle")?;

        let mut result = Vec::new();

        for obj in &bundle.objects {
            if obj.obj_type != "indicator" { continue; }

            let pattern = match &obj.pattern {
                Some(p) => p,
                None => continue,
            };

            let confidence = obj.confidence.unwrap_or(50);
            if confidence < 30 { continue; }

            let tl = if confidence >= 90 { "critical" }
                else if confidence >= 70 { "high" }
                else if confidence >= 50 { "medium" }
                else { "low" };

            let tags: Vec<String> = obj.labels.clone().unwrap_or_default();

            // Parse STIX pattern expressions
            // [ipv4-addr:value = '1.2.3.4']
            // [domain-name:value = 'evil.com']
            // [file:hashes.'SHA-256' = 'abc...']
            // [url:value = 'http://...']
            for extracted in extract_from_pattern(pattern) {
                result.push(IocEntry {
                    value: extracted.value,
                    ioc_type: extracted.ioc_type,
                    threat_level: tl.to_string(),
                    source: source.to_string(),
                    tags: tags.clone(),
                });
            }
        }

        Ok(result)
    }
}

struct PatternExtract {
    value: String,
    ioc_type: IocType,
}

fn extract_from_pattern(pattern: &str) -> Vec<PatternExtract> {
    let mut results = Vec::new();

    // Split by AND/OR and process each sub-expression
    for part in pattern.split(" AND ").flat_map(|p| p.split(" OR ")) {
        let part = part.trim().trim_start_matches('[').trim_end_matches(']');

        let (ioc_type, val_start) = if part.contains("ipv4-addr:value") || part.contains("ipv6-addr:value") {
            (IocType::IpAddress, part.find('\''))
        } else if part.contains("domain-name:value") || part.contains("hostname:value") {
            (IocType::Domain, part.find('\''))
        } else if part.contains("file:hashes") {
            (IocType::FileHash, part.find('\''))
        } else if part.contains("url:value") {
            (IocType::Url, part.find('\''))
        } else {
            continue;
        };

        if let Some(start) = val_start {
            let after = &part[start + 1..];
            if let Some(end) = after.find('\'') {
                let value = after[..end].to_string();
                if !value.is_empty() {
                    results.push(PatternExtract { value, ioc_type });
                }
            }
        }
    }

    results
}
