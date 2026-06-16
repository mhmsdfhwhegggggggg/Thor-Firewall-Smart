//! Enhanced Sigma Compiler — full condition parsing (AND/OR/NOT/1of/allof)
//! Converts Sigma YAML rules into compiled AhoCorasick DFA patterns with
//! proper boolean condition logic.

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use walkdir::WalkDir;
use tracing::{info, warn};

use crate::events::enrichment::EnrichedEvent;
use crate::events::RawEvent;

// ─── Sigma Rule schema ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct SigmaRuleFile {
    pub title: String,
    pub id: Option<String>,
    pub status: Option<String>,
    pub description: Option<String>,
    pub level: Option<String>,
    pub detection: SigmaDetectionBlock,
    pub logsource: Option<SigmaLogsource>,
    pub tags: Option<Vec<String>>,
    pub falsepositives: Option<Vec<String>>,
    pub author: Option<String>,
    pub date: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SigmaDetectionBlock {
    pub condition: Option<String>,
    #[serde(flatten)]
    pub selections: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SigmaLogsource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

// ─── Condition AST ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ConditionNode {
    Selection(String),          // named selection (e.g., "selection_main")
    Not(Box<ConditionNode>),
    And(Vec<ConditionNode>),
    Or(Vec<ConditionNode>),
    OneOf(String),              // 1of(selection*)
    AllOf(String),              // allof(selection*)
    Keywords,
}

// ─── Compiled Rule ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct CompiledSigmaRule {
    pub title: String,
    pub id: String,
    pub level: thor_common::ThreatLevel,
    pub tags: Vec<String>,
    pub logsource: Option<SigmaLogsource>,
    pub description: String,
    pub condition: ConditionNode,
    /// Named selection → list of AhoCorasick automata (each AC must match for AND within selection)
    pub selections: HashMap<String, Vec<SelectionMatcher>>,
    /// Flat keyword patterns (legacy support)
    pub keywords: Vec<String>,
    pub keywords_ac: Option<AhoCorasick>,
}

#[derive(Clone)]
pub struct SelectionMatcher {
    /// Field name (e.g., "CommandLine", "Image") — None means match anywhere
    pub field: Option<String>,
    pub ac: AhoCorasick,
    pub patterns: Vec<String>,
    pub negate: bool,
}

// ─── Compiler ─────────────────────────────────────────────────────────────────

pub struct SigmaCompiler;

impl SigmaCompiler {
    pub fn compile_file(content: &str) -> Result<CompiledSigmaRule> {
        let rule: SigmaRuleFile = serde_yaml::from_str(content)
            .context("YAML parse error")?;

        let level = rule.level.as_deref().map(|l| match l {
            "critical" => thor_common::ThreatLevel::Critical,
            "high"     => thor_common::ThreatLevel::High,
            "medium"   => thor_common::ThreatLevel::Medium,
            _          => thor_common::ThreatLevel::Low,
        }).unwrap_or(thor_common::ThreatLevel::Low);

        let id = rule.id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let tags = rule.tags.clone().unwrap_or_default();
        let description = rule.description.clone().unwrap_or_default();

        // Parse condition
        let raw_condition = rule.detection.condition.as_deref().unwrap_or("selection");
        let condition = parse_condition(raw_condition)?;

        // Compile each selection into matchers
        let mut selections: HashMap<String, Vec<SelectionMatcher>> = HashMap::new();
        let mut keywords: Vec<String> = Vec::new();

        for (key, val) in &rule.detection.selections {
            if key == "condition" { continue; }
            if key == "keywords" {
                keywords = extract_strings_from_yaml(val);
                continue;
            }
            let matchers = compile_selection(&key, val)?;
            if !matchers.is_empty() {
                selections.insert(key.clone(), matchers);
            }
        }

        let keywords_ac = if !keywords.is_empty() {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&keywords)
                .ok()
        } else {
            None
        };

        Ok(CompiledSigmaRule {
            title: rule.title,
            id,
            level,
            tags,
            logsource: rule.logsource,
            description,
            condition,
            selections,
            keywords,
            keywords_ac,
        })
    }

    pub fn load_directory(dir: &std::path::Path) -> Vec<CompiledSigmaRule> {
        let mut rules = Vec::new();
        if !dir.exists() { return rules; }

        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("yml") { continue; }
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    match Self::compile_file(&content) {
                        Ok(rule) => rules.push(rule),
                        Err(e) => warn!("Sigma compile failed {:?}: {}", path, e),
                    }
                }
                Err(e) => warn!("Cannot read {:?}: {}", path, e),
            }
        }
        info!("📚 Sigma compiler: {} rules compiled from {:?}", rules.len(), dir);
        rules
    }
}

// ─── Evaluation ──────────────────────────────────────────────────────────────

impl CompiledSigmaRule {
    /// Evaluate rule against a text payload (event serialized to string)
    pub fn evaluate(&self, event: &EnrichedEvent) -> bool {
        let text = event_to_string(event);
        self.eval_condition(&self.condition, &text)
    }

    fn eval_condition(&self, node: &ConditionNode, text: &str) -> bool {
        match node {
            ConditionNode::Selection(name) => self.eval_selection(name, text),
            ConditionNode::Not(inner) => !self.eval_condition(inner, text),
            ConditionNode::And(children) => children.iter().all(|c| self.eval_condition(c, text)),
            ConditionNode::Or(children) => children.iter().any(|c| self.eval_condition(c, text)),
            ConditionNode::Keywords => {
                self.keywords_ac.as_ref().map(|ac| ac.is_match(text)).unwrap_or(false)
            }
            ConditionNode::OneOf(prefix) => {
                // 1of(prefix*) → any selection starting with prefix must match
                self.selections.keys()
                    .filter(|k| k.starts_with(prefix.trim_end_matches('*')))
                    .any(|k| self.eval_selection(k, text))
            }
            ConditionNode::AllOf(prefix) => {
                self.selections.keys()
                    .filter(|k| k.starts_with(prefix.trim_end_matches('*')))
                    .all(|k| self.eval_selection(k, text))
            }
        }
    }

    fn eval_selection(&self, name: &str, text: &str) -> bool {
        let matchers = match self.selections.get(name) {
            Some(m) => m,
            None => return false,
        };
        // All matchers in a selection must match (AND within selection)
        matchers.iter().all(|m| {
            let matched = m.ac.is_match(text);
            if m.negate { !matched } else { matched }
        })
    }
}

// ─── Condition parser ─────────────────────────────────────────────────────────

fn parse_condition(s: &str) -> Result<ConditionNode> {
    let s = s.trim();

    // Handle "1of(...)" and "all of (...)" / "allof(...)"
    if s.starts_with("1of(") || s.starts_with("1 of (") {
        let inner = extract_paren_content(s)?;
        return Ok(ConditionNode::OneOf(inner));
    }
    if s.starts_with("all of (") || s.starts_with("allof(") {
        let inner = extract_paren_content(s)?;
        return Ok(ConditionNode::AllOf(inner));
    }

    // Handle NOT
    if s.starts_with("not ") || s.starts_with("NOT ") {
        let inner = parse_condition(&s[4..])?;
        return Ok(ConditionNode::Not(Box::new(inner)));
    }

    // Handle OR (lower precedence than AND)
    if let Some(parts) = split_top_level(s, " or ") {
        if parts.len() > 1 {
            let children: Result<Vec<_>> = parts.iter().map(|p| parse_condition(p)).collect();
            return Ok(ConditionNode::Or(children?));
        }
    }

    // Handle AND
    if let Some(parts) = split_top_level(s, " and ") {
        if parts.len() > 1 {
            let children: Result<Vec<_>> = parts.iter().map(|p| parse_condition(p)).collect();
            return Ok(ConditionNode::And(children?));
        }
    }

    // Parenthesized expression
    if s.starts_with('(') && s.ends_with(')') {
        return parse_condition(&s[1..s.len()-1]);
    }

    // Keywords special case
    if s == "keywords" {
        return Ok(ConditionNode::Keywords);
    }

    // Single selection name (most common case)
    Ok(ConditionNode::Selection(s.to_string()))
}

fn extract_paren_content(s: &str) -> Result<String> {
    let start = s.find('(').context("No (")?;
    let end = s.rfind(')').context("No )")?;
    Ok(s[start + 1..end].to_string())
}

fn split_top_level<'a>(s: &'a str, sep: &str) -> Option<Vec<&'a str>> {
    // Split on separator only at depth 0
    let sep_lower = sep.to_lowercase();
    let s_lower = s.to_lowercase();
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut last = 0;

    let chars: Vec<char> = s_lower.chars().collect();
    let sep_chars: Vec<char> = sep_lower.chars().collect();
    let slen = sep_chars.len();

    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '(' { depth += 1; }
        else if chars[i] == ')' { depth -= 1; }
        else if depth == 0 && i + slen <= chars.len() {
            if chars[i..i+slen] == sep_chars[..] {
                parts.push(s[last..i].trim());
                last = i + slen;
                i += slen;
                continue;
            }
        }
        i += 1;
    }
    parts.push(s[last..].trim());

    if parts.len() > 1 { Some(parts) } else { None }
}

// ─── Selection compilation ────────────────────────────────────────────────────

fn compile_selection(name: &str, val: &serde_yaml::Value) -> Result<Vec<SelectionMatcher>> {
    let mut matchers = Vec::new();

    match val {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                let field_name = k.as_str().unwrap_or("").to_string();
                let negate = field_name.ends_with("|not");
                let field_clean = field_name.replace("|contains|all", "")
                    .replace("|contains", "")
                    .replace("|startswith", "")
                    .replace("|endswith", "")
                    .replace("|not", "")
                    .replace("|all", "");

                let patterns = extract_strings_from_yaml(v);
                if patterns.is_empty() { continue; }

                match AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(&patterns)
                {
                    Ok(ac) => {
                        matchers.push(SelectionMatcher {
                            field: if field_clean == "*" || field_clean.is_empty() {
                                None
                            } else {
                                Some(field_clean)
                            },
                            ac,
                            patterns,
                            negate,
                        });
                    }
                    Err(e) => warn!("AC build failed for selection '{}' field '{}': {}", name, field_name, e),
                }
            }
        }
        // Sequence at top level → OR of patterns
        serde_yaml::Value::Sequence(_) => {
            let patterns = extract_strings_from_yaml(val);
            if !patterns.is_empty() {
                if let Ok(ac) = AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(&patterns)
                {
                    matchers.push(SelectionMatcher {
                        field: None,
                        ac,
                        patterns,
                        negate: false,
                    });
                }
            }
        }
        _ => {}
    }

    Ok(matchers)
}

pub fn extract_strings_from_yaml(val: &serde_yaml::Value) -> Vec<String> {
    let mut out = Vec::new();
    match val {
        serde_yaml::Value::String(s) => {
            let cleaned = s.replace("*", "").replace("?", "");
            if cleaned.len() >= 3 { out.push(cleaned); }
        }
        serde_yaml::Value::Sequence(seq) => {
            for v in seq { out.extend(extract_strings_from_yaml(v)); }
        }
        serde_yaml::Value::Mapping(map) => {
            for (_, v) in map { out.extend(extract_strings_from_yaml(v)); }
        }
        serde_yaml::Value::Bool(b) => out.push(b.to_string()),
        serde_yaml::Value::Number(n) => out.push(n.to_string()),
        _ => {}
    }
    out
}

fn event_to_string(event: &EnrichedEvent) -> String {
    match &event.raw {
        RawEvent::Process(e) => format!(
            "{} {} {} {} {}",
            e.process_name, e.cmdline,
            e.parent_name.as_deref().unwrap_or(""),
            event.hostname.as_deref().unwrap_or(""),
            event.src_ip_str.as_deref().unwrap_or(""),
        ),
        RawEvent::Network(e) => format!(
            "{} {} {} {} {}",
            event.src_ip_str.as_deref().unwrap_or(""),
            event.dst_ip_str.as_deref().unwrap_or(""),
            e.dst_port,
            e.protocol,
            event.hostname.as_deref().unwrap_or(""),
        ),
        RawEvent::Dns(e) => format!("{} {}", e.query, e.record_type),
        RawEvent::Tls(e) => format!(
            "{} {} {}",
            e.sni.as_deref().unwrap_or(""),
            e.ja4_hash.as_deref().unwrap_or(""),
            e.issuer.as_deref().unwrap_or(""),
        ),
        RawEvent::Fim(e) => format!("{} {:?}", e.path, e.operation),
        _ => String::new(),
    }
}
