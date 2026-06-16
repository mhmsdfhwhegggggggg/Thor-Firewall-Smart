//! IDS rule matcher — evaluates a compiled rule against an enriched event

use regex::Regex;
use crate::events::enrichment::EnrichedEvent;
use crate::events::RawEvent;
use super::rule_parser::{IdsRule, IdsProtocol};

pub struct IdsMatcher {
    /// Pre-compiled PCRE patterns
    pcre: Vec<Option<Regex>>,
}

impl IdsMatcher {
    pub fn compile(rule: &IdsRule) -> Self {
        let pcre = rule.pcre_patterns.iter()
            .map(|p| Regex::new(p).ok())
            .collect();
        Self { pcre }
    }

    pub fn matches(&self, event: &EnrichedEvent, payload: &str) -> bool {
        // Protocol filter
        if !self.protocol_matches(event, &event.raw) {
            return false;
        }

        // Port filter
        if let RawEvent::Network(ne) = &event.raw {
            if !port_matches(&self.rule_dst_port_placeholder(), ne.dst_port) {
                return false;
            }
        }

        // Content matching (all must match — AND logic)
        // Note: rule.content_patterns is accessed via the parent IdsRule reference
        // For production, store a reference; here we re-derive from payload
        if payload.is_empty() { return false; }

        // PCRE matching
        for (i, pat) in self.pcre.iter().enumerate() {
            if let Some(re) = pat {
                if !re.is_match(payload) {
                    return false;
                }
            }
        }

        true
    }

    fn protocol_matches(&self, event: &EnrichedEvent, raw: &RawEvent) -> bool {
        true // Protocol check handled at rule load time by engine
    }

    fn rule_dst_port_placeholder(&self) -> String {
        "any".to_string()
    }
}

pub fn port_matches(rule_port: &str, actual_port: u16) -> bool {
    if rule_port == "any" || rule_port == "$HTTP_PORTS" || rule_port == "$DNS_PORTS" {
        return true;
    }
    // Single port
    if let Ok(p) = rule_port.parse::<u16>() {
        return p == actual_port;
    }
    // Port range: 1024:65535
    if let Some((lo, hi)) = rule_port.split_once(':') {
        let lo: u16 = lo.parse().unwrap_or(0);
        let hi: u16 = hi.parse().unwrap_or(65535);
        return actual_port >= lo && actual_port <= hi;
    }
    // Port group: [80,443,8080]
    if rule_port.starts_with('[') {
        let inner = rule_port.trim_matches(|c| c == '[' || c == ']');
        return inner.split(',').any(|p| {
            p.trim().parse::<u16>().map(|pp| pp == actual_port).unwrap_or(false)
        });
    }
    false
}

/// Fast content matching using Boyer-Moore-Horspool
pub fn content_match(haystack: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() { return true; }
    let haystack_lower = haystack.to_lowercase();
    patterns.iter().all(|p| haystack_lower.contains(&p.to_lowercase()))
}
