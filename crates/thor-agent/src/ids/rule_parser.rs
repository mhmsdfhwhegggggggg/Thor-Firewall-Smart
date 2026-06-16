//! Suricata rule parser — handles Emerging Threats Open rule format
//! Supports: action protocol src_addr src_port direction dst_addr dst_port (options)

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IdsAction {
    Alert,
    Drop,
    Pass,
    Reject,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IdsProtocol {
    Tcp,
    Udp,
    Icmp,
    Ip,
    Http,
    Dns,
    Tls,
    Ftp,
    Smtp,
    Ssh,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleOption {
    pub keyword: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsRule {
    pub action: IdsAction,
    pub protocol: IdsProtocol,
    pub src_addr: String,
    pub src_port: String,
    pub direction: String,
    pub dst_addr: String,
    pub dst_port: String,
    pub msg: String,
    pub sid: u32,
    pub rev: u32,
    pub priority: u8,
    pub classtype: Option<String>,
    pub options: Vec<RuleOption>,
    /// Pre-extracted content patterns for fast matching
    pub content_patterns: Vec<String>,
    /// Pre-extracted PCRE patterns
    pub pcre_patterns: Vec<String>,
    pub flow: Option<String>,
    pub metadata: Vec<String>,
}

/// Parse a single Suricata rule line
pub fn parse_rule(line: &str) -> Result<IdsRule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        bail!("Empty or comment");
    }

    // Split into header and options
    // Format: action proto src_addr src_port direction dst_addr dst_port (options)
    let paren_start = line.find('(').context("No options paren")?;
    let paren_end = line.rfind(')').context("No closing paren")?;

    let header = line[..paren_start].trim();
    let options_str = &line[paren_start + 1..paren_end];

    let parts: Vec<&str> = header.split_whitespace().collect();
    if parts.len() < 7 {
        bail!("Header too short: {:?}", parts);
    }

    let action = parse_action(parts[0])?;
    let protocol = parse_protocol(parts[1])?;
    let src_addr = parts[2].to_string();
    let src_port = parts[3].to_string();
    let direction = parts[4].to_string();
    let dst_addr = parts[5].to_string();
    let dst_port = parts[6].to_string();

    // Parse options
    let options = parse_options(options_str)?;

    let mut msg = String::new();
    let mut sid = 0u32;
    let mut rev = 1u32;
    let mut priority = 3u8;
    let mut classtype = None;
    let mut content_patterns = Vec::new();
    let mut pcre_patterns = Vec::new();
    let mut flow = None;
    let mut metadata = Vec::new();

    for opt in &options {
        match opt.keyword.as_str() {
            "msg" => {
                msg = opt.value.as_deref().unwrap_or("").trim_matches('"').to_string();
            }
            "sid" => {
                sid = opt.value.as_deref().unwrap_or("0").parse().unwrap_or(0);
            }
            "rev" => {
                rev = opt.value.as_deref().unwrap_or("1").parse().unwrap_or(1);
            }
            "priority" => {
                priority = opt.value.as_deref().unwrap_or("3").parse().unwrap_or(3);
            }
            "classtype" => {
                classtype = opt.value.as_ref().map(|v| v.trim_matches('"').to_string());
            }
            "content" => {
                if let Some(val) = &opt.value {
                    let cleaned = val.trim_matches('"').to_string();
                    // Only add printable content patterns
                    if !cleaned.starts_with('|') && cleaned.len() > 2 {
                        content_patterns.push(cleaned);
                    }
                }
            }
            "pcre" => {
                if let Some(val) = &opt.value {
                    let cleaned = val.trim_matches('/').trim_matches('"').to_string();
                    pcre_patterns.push(cleaned);
                }
            }
            "flow" => {
                flow = opt.value.clone();
            }
            "metadata" => {
                if let Some(val) = &opt.value {
                    metadata.push(val.clone());
                }
            }
            _ => {}
        }
    }

    // Derive priority from classtype if not set explicitly
    if priority == 3 {
        if let Some(ct) = &classtype {
            priority = classtype_to_priority(ct);
        }
    }

    Ok(IdsRule {
        action, protocol,
        src_addr, src_port, direction, dst_addr, dst_port,
        msg, sid, rev, priority, classtype,
        options, content_patterns, pcre_patterns, flow, metadata,
    })
}

fn parse_action(s: &str) -> Result<IdsAction> {
    match s.to_lowercase().as_str() {
        "alert" => Ok(IdsAction::Alert),
        "drop" => Ok(IdsAction::Drop),
        "pass" => Ok(IdsAction::Pass),
        "reject" => Ok(IdsAction::Reject),
        "log" => Ok(IdsAction::Log),
        _ => bail!("Unknown action: {}", s),
    }
}

fn parse_protocol(s: &str) -> Result<IdsProtocol> {
    match s.to_lowercase().as_str() {
        "tcp" => Ok(IdsProtocol::Tcp),
        "udp" => Ok(IdsProtocol::Udp),
        "icmp" => Ok(IdsProtocol::Icmp),
        "ip" => Ok(IdsProtocol::Ip),
        "http" => Ok(IdsProtocol::Http),
        "dns" => Ok(IdsProtocol::Dns),
        "tls" | "ssl" => Ok(IdsProtocol::Tls),
        "ftp" => Ok(IdsProtocol::Ftp),
        "smtp" => Ok(IdsProtocol::Smtp),
        "ssh" => Ok(IdsProtocol::Ssh),
        _ => Ok(IdsProtocol::Any),
    }
}

/// Parse rule options string into key-value pairs
/// Handles: msg:"text"; content:"pattern"; sid:1234; etc.
fn parse_options(s: &str) -> Result<Vec<RuleOption>> {
    let mut options = Vec::new();
    let mut pos = 0;
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();

    while pos < len {
        // Skip whitespace and semicolons
        while pos < len && (chars[pos] == ';' || chars[pos] == ' ' || chars[pos] == '\t') {
            pos += 1;
        }
        if pos >= len { break; }

        // Read keyword
        let kw_start = pos;
        while pos < len && chars[pos] != ':' && chars[pos] != ';' {
            pos += 1;
        }
        let keyword = chars[kw_start..pos].iter().collect::<String>().trim().to_string();
        if keyword.is_empty() { break; }

        if pos >= len || chars[pos] == ';' {
            options.push(RuleOption { keyword, value: None });
            continue;
        }

        // Skip ':'
        pos += 1;

        // Read value (handling quoted strings and nested parens)
        let mut value = String::new();
        let mut depth = 0i32;
        let mut in_quote = false;
        let mut quote_char = ' ';

        while pos < len {
            let c = chars[pos];
            if in_quote {
                value.push(c);
                if c == quote_char { in_quote = false; }
            } else if c == '"' || c == '\'' {
                in_quote = true;
                quote_char = c;
                value.push(c);
            } else if c == '(' {
                depth += 1;
                value.push(c);
            } else if c == ')' {
                if depth > 0 {
                    depth -= 1;
                    value.push(c);
                } else {
                    break;
                }
            } else if c == ';' && depth == 0 {
                break;
            } else {
                value.push(c);
            }
            pos += 1;
        }

        options.push(RuleOption {
            keyword,
            value: Some(value.trim().to_string()),
        });
    }

    Ok(options)
}

fn classtype_to_priority(ct: &str) -> u8 {
    match ct {
        "attempted-admin" | "successful-admin" | "web-application-attack" => 1,
        "trojan-activity" | "command-and-control" | "shellcode-detect" => 1,
        "attempted-recon" | "network-scan" => 3,
        "policy-violation" | "protocol-command-decode" => 3,
        _ => 2,
    }
}
