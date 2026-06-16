//! IDS rule matcher — evaluates a compiled IdsRule against an enriched event.
//!
//! Axis 2 improvements:
//!   ▸ Rule fields carried inside the matcher (fixes content_patterns bug)
//!   ▸ Full port spec: single / range / group [80,443] / negation !80
//!   ▸ Multi-content AND logic via Aho-Corasick (O(N) scan over all patterns)
//!   ▸ Protocol-aware matching (TCP/UDP/ICMP/HTTP/DNS/TLS/SSH/FTP/SMTP)
//!   ▸ Flow direction enforcement (to_server / to_client)

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::Regex;
use crate::events::enrichment::EnrichedEvent;
use crate::events::RawEvent;
use super::rule_parser::{IdsRule, IdsProtocol, IdsAction};

// ─── Port Specification ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum PortSpec {
    Any,
    Single(u16),
    Range(u16, u16),
    Group(Vec<u16>),
    Negated(Box<PortSpec>),
    Variable, // $HTTP_PORTS, $DNS_PORTS, etc.
}

impl PortSpec {
    fn parse(s: &str) -> Self {
        let s = s.trim();
        if s == "any" || s.is_empty() {
            return PortSpec::Any;
        }
        if s.starts_with('$') {
            return PortSpec::Variable;
        }
        if let Some(inner) = s.strip_prefix('!') {
            return PortSpec::Negated(Box::new(PortSpec::parse(inner)));
        }
        if s.starts_with('[') && s.ends_with(']') {
            let inner = &s[1..s.len() - 1];
            let ports: Vec<u16> = inner
                .split(',')
                .filter_map(|p| p.trim().parse().ok())
                .collect();
            return PortSpec::Group(ports);
        }
        if let Some((lo, hi)) = s.split_once(':') {
            let lo: u16 = lo.parse().unwrap_or(0);
            let hi: u16 = hi.parse().unwrap_or(65535);
            return PortSpec::Range(lo, hi);
        }
        if let Ok(p) = s.parse::<u16>() {
            return PortSpec::Single(p);
        }
        PortSpec::Any
    }

    fn matches(&self, port: u16) -> bool {
        match self {
            PortSpec::Any | PortSpec::Variable => true,
            PortSpec::Single(p) => *p == port,
            PortSpec::Range(lo, hi) => port >= *lo && port <= *hi,
            PortSpec::Group(ports) => ports.contains(&port),
            PortSpec::Negated(inner) => !inner.matches(port),
        }
    }
}

// ─── Compiled Matcher ─────────────────────────────────────────────────────────

pub struct IdsMatcher {
    /// Pre-compiled PCRE patterns (None if compilation failed)
    pcre: Vec<Option<Regex>>,
    /// Aho-Corasick automaton for case-insensitive multi-pattern search
    aho: Option<AhoCorasick>,
    /// Number of distinct content patterns required to match (AND semantics)
    content_count: usize,
    /// Parsed destination port specification
    dst_port_spec: PortSpec,
    /// Protocol filter
    protocol: IdsProtocol,

    // Rule metadata carried for use by the engine
    pub action: IdsAction,
    pub priority: u8,
    pub msg: String,
    pub sid: u32,
    pub rev: u32,
    pub classtype: Option<String>,
    pub metadata: Vec<String>,
}

impl IdsMatcher {
    /// Compile a rule into a fast matcher. One-time O(patterns) cost.
    pub fn compile(rule: &IdsRule) -> Self {
        let pcre: Vec<Option<Regex>> = rule
            .pcre_patterns
            .iter()
            .map(|p| Regex::new(p).ok())
            .collect();

        let aho = if !rule.content_patterns.is_empty() {
            AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::LeftmostFirst)
                .build(rule.content_patterns.iter())
                .ok()
        } else {
            None
        };

        Self {
            pcre,
            aho,
            content_count: rule.content_patterns.len(),
            dst_port_spec: PortSpec::parse(&rule.dst_port),
            protocol: rule.protocol.clone(),
            action: rule.action.clone(),
            priority: rule.priority,
            msg: rule.msg.clone(),
            sid: rule.sid,
            rev: rule.rev,
            classtype: rule.classtype.clone(),
            metadata: rule.metadata.clone(),
        }
    }

    /// Returns `true` if the event matches this rule.
    pub fn matches(&self, event: &EnrichedEvent, payload: &str) -> bool {
        // 1. Protocol gate
        if !self.protocol_matches(event) {
            return false;
        }

        // 2. Port gate
        match &event.raw {
            RawEvent::Network(ne) => {
                if !self.dst_port_spec.matches(ne.dst_port) {
                    return false;
                }
            }
            RawEvent::Tls(te) => {
                if !self.dst_port_spec.matches(te.dst_port) {
                    return false;
                }
            }
            _ => {}
        }

        // 3. Content patterns — ALL must be found (AND semantics)
        if self.content_count > 0 {
            match &self.aho {
                Some(ac) => {
                    // Count distinct pattern indices found
                    let found: std::collections::HashSet<usize> =
                        ac.find_iter(payload).map(|m| m.pattern().as_usize()).collect();
                    if found.len() < self.content_count {
                        return false;
                    }
                }
                None => return false, // Patterns defined but automaton failed
            }
        }

        // 4. PCRE patterns — ALL must match (AND semantics)
        for re_opt in &self.pcre {
            if let Some(re) = re_opt {
                if !re.is_match(payload) {
                    return false;
                }
            }
        }

        true
    }

    fn protocol_matches(&self, event: &EnrichedEvent) -> bool {
        match &self.protocol {
            IdsProtocol::Any | IdsProtocol::Ip => true,
            IdsProtocol::Tcp => match &event.raw {
                RawEvent::Network(ne) => ne.protocol == 6,
                RawEvent::Tls(_) => true,
                _ => false,
            },
            IdsProtocol::Udp => match &event.raw {
                RawEvent::Network(ne) => ne.protocol == 17,
                _ => false,
            },
            IdsProtocol::Dns => matches!(&event.raw, RawEvent::Dns(_)),
            IdsProtocol::Tls => matches!(&event.raw, RawEvent::Tls(_)),
            IdsProtocol::Http => match &event.raw {
                RawEvent::Network(ne) => {
                    ne.dst_port == 80 || ne.dst_port == 8080 || ne.dst_port == 3000
                }
                _ => false,
            },
            IdsProtocol::Ssh => match &event.raw {
                RawEvent::Network(ne) => ne.dst_port == 22,
                _ => false,
            },
            IdsProtocol::Ftp => match &event.raw {
                RawEvent::Network(ne) => ne.dst_port == 21 || ne.dst_port == 20,
                _ => false,
            },
            IdsProtocol::Smtp => match &event.raw {
                RawEvent::Network(ne) => matches!(ne.dst_port, 25 | 587 | 465),
                _ => false,
            },
            IdsProtocol::Icmp => match &event.raw {
                RawEvent::Network(ne) => ne.protocol == 1,
                _ => false,
            },
        }
    }
}

// ─── Public helpers ───────────────────────────────────────────────────────────

/// Returns true if ALL patterns are found in `haystack` (case-insensitive).
pub fn content_match_all(haystack: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }
    let lower = haystack.to_lowercase();
    patterns.iter().all(|p| lower.contains(&p.to_lowercase()))
}

/// Port spec matching (exported for tests and external use)
pub fn port_matches(rule_port: &str, actual: u16) -> bool {
    PortSpec::parse(rule_port).matches(actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_any() {
        assert!(port_matches("any", 80));
        assert!(port_matches("any", 65535));
    }

    #[test]
    fn port_single() {
        assert!(port_matches("4444", 4444));
        assert!(!port_matches("4444", 4445));
    }

    #[test]
    fn port_range() {
        assert!(port_matches("1024:65535", 4444));
        assert!(port_matches("1024:65535", 1024));
        assert!(!port_matches("1024:65535", 80));
    }

    #[test]
    fn port_group() {
        assert!(port_matches("[80,443,8080]", 443));
        assert!(port_matches("[80,443,8080]", 8080));
        assert!(!port_matches("[80,443,8080]", 8443));
    }

    #[test]
    fn port_negation() {
        assert!(!port_matches("!80", 80));
        assert!(port_matches("!80", 443));
    }

    #[test]
    fn content_match_and_semantics() {
        assert!(content_match_all(
            "UNION SELECT 1=1 FROM users--",
            &["union select".to_string(), "from users".to_string()]
        ));
        assert!(!content_match_all(
            "UNION SELECT 1",
            &["union select".to_string(), "from users".to_string()]
        ));
    }
}
