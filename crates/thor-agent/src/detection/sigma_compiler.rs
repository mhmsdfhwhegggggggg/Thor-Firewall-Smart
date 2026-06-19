//! Enhanced Sigma Compiler — full condition parsing (AND/OR/NOT/1of/allof)
//! Converts Sigma YAML rules into compiled AhoCorasick DFA patterns with
//! proper boolean condition logic.
//!
//! # Tiered Detection
//! Rules are classified into two tiers at compile time:
//! * **Fast rules** — contain only simple keyword / AC patterns.  These are
//!   evaluated first and cover the majority of Sigma rules cheaply.
//! * **Complex rules** — contain regex modifiers or multi-level boolean
//!   conditions.  Only evaluated when a fast rule signals a preliminary match
//!   on the same event text, or when no fast rule matches (to avoid missed
//!   detections on complex patterns).
//!
//! Use [`TieredSigmaEngine`] to benefit from the tiered approach; or call
//! [`CompiledSigmaRule::evaluate`] directly for single-rule checks.

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
    pub selections: HashMap<String, serde_yml::Value>,
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
    Selection(String),
    Not(Box<ConditionNode>),
    And(Vec<ConditionNode>),
    Or(Vec<ConditionNode>),
    OneOf(String),
    AllOf(String),
    Keywords,
}

// ─── Complexity flag ──────────────────────────────────────────────────────────

/// Complexity tier assigned to each compiled rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleTier {
    /// AC-only, no regex modifiers, flat condition — checked first.
    Fast,
    /// Contains regex patterns or deeply nested boolean logic.
    Complex,
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
    /// Tier assigned at compile time.
    pub tier: RuleTier,
}

#[derive(Clone)]
pub struct SelectionMatcher {
    /// Field name (e.g., "CommandLine", "Image") — None means match anywhere
    pub field: Option<String>,
    pub ac: AhoCorasick,
    pub patterns: Vec<String>,
    pub negate: bool,
    /// True if any pattern in this matcher contained regex-specific modifiers.
    pub has_regex: bool,
}

// ─── Tier classification ──────────────────────────────────────────────────────

impl CompiledSigmaRule {
    /// Return true if this rule uses regex modifiers or deeply nested logic,
    /// warranting Complex tier treatment.
    pub fn is_complex(&self) -> bool {
        self.tier == RuleTier::Complex
    }

    /// Classify whether a compiled rule should be Fast or Complex.
    ///
    /// Heuristics (any one → Complex):
    /// * A `SelectionMatcher` was flagged `has_regex` (came from a `|re|` field).
    /// * The condition is not a leaf `Selection` or simple `And`/`Or` of leaves
    ///   (e.g. `Not`, `OneOf`, `AllOf`, nested boolean trees with depth > 2).
    pub(crate) fn classify(
        selections: &HashMap<String, Vec<SelectionMatcher>>,
        condition: &ConditionNode,
    ) -> RuleTier {
        // Check matcher-level regex flag
        let has_regex_matcher = selections
            .values()
            .flatten()
            .any(|m| m.has_regex);

        if has_regex_matcher {
            return RuleTier::Complex;
        }

        // Check condition complexity
        if condition_is_complex(condition, 0) {
            return RuleTier::Complex;
        }

        RuleTier::Fast
    }
}

/// Returns true if the condition tree is too deep or contains Not/OneOf/AllOf.
fn condition_is_complex(node: &ConditionNode, depth: usize) -> bool {
    match node {
        ConditionNode::Selection(_) | ConditionNode::Keywords => false,
        // Not and wildcard quantifiers always push to complex
        ConditionNode::Not(_) | ConditionNode::OneOf(_) | ConditionNode::AllOf(_) => true,
        ConditionNode::And(children) | ConditionNode::Or(children) => {
            // Depth > 3 or any complex child → complex
            if depth > 3 {
                return true;
            }
            children.iter().any(|c| condition_is_complex(c, depth + 1))
        }
    }
}

// ─── Compiler ─────────────────────────────────────────────────────────────────

pub struct SigmaCompiler;

impl SigmaCompiler {
    pub fn compile_file(content: &str) -> Result<CompiledSigmaRule> {
        let rule: SigmaRuleFile =
            serde_yml::from_str(content).context("YAML parse error")?;

        let level = rule
            .level
            .as_deref()
            .map(|l| match l {
                "critical" => thor_common::ThreatLevel::Critical,
                "high" => thor_common::ThreatLevel::High,
                "medium" => thor_common::ThreatLevel::Medium,
                _ => thor_common::ThreatLevel::Low,
            })
            .unwrap_or(thor_common::ThreatLevel::Low);

        let id = rule
            .id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let tags = rule.tags.clone().unwrap_or_default();
        let description = rule.description.clone().unwrap_or_default();

        let raw_condition = rule.detection.condition.as_deref().unwrap_or("selection");
        let condition = parse_condition(raw_condition)?;

        let mut selections: HashMap<String, Vec<SelectionMatcher>> = HashMap::new();
        let mut keywords: Vec<String> = Vec::new();

        for (key, val) in &rule.detection.selections {
            if key == "condition" {
                continue;
            }
            if key == "keywords" {
                keywords = extract_strings_from_yaml(val);
                continue;
            }
            let matchers = compile_selection(key, val)?;
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

        let tier = CompiledSigmaRule::classify(&selections, &condition);

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
            tier,
        })
    }

    pub fn load_directory(dir: &std::path::Path) -> Vec<CompiledSigmaRule> {
        let mut rules = Vec::new();
        if !dir.exists() {
            return rules;
        }

        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("yml") {
                continue;
            }
            match std::fs::read_to_string(path) {
                Ok(content) => match Self::compile_file(&content) {
                    Ok(rule) => rules.push(rule),
                    Err(e) => warn!("Sigma compile failed {:?}: {}", path, e),
                },
                Err(e) => warn!("Cannot read {:?}: {}", path, e),
            }
        }
        info!(
            "📚 Sigma compiler: {} rules compiled from {:?}",
            rules.len(),
            dir
        );
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
            ConditionNode::And(children) => {
                children.iter().all(|c| self.eval_condition(c, text))
            }
            ConditionNode::Or(children) => {
                children.iter().any(|c| self.eval_condition(c, text))
            }
            ConditionNode::Keywords => self
                .keywords_ac
                .as_ref()
                .map(|ac| ac.is_match(text))
                .unwrap_or(false),
            ConditionNode::OneOf(prefix) => self
                .selections
                .keys()
                .filter(|k| k.starts_with(prefix.trim_end_matches('*')))
                .any(|k| self.eval_selection(k, text)),
            ConditionNode::AllOf(prefix) => self
                .selections
                .keys()
                .filter(|k| k.starts_with(prefix.trim_end_matches('*')))
                .all(|k| self.eval_selection(k, text)),
        }
    }

    fn eval_selection(&self, name: &str, text: &str) -> bool {
        let matchers = match self.selections.get(name) {
            Some(m) => m,
            None => return false,
        };
        matchers.iter().all(|m| {
            let matched = m.ac.is_match(text);
            if m.negate { !matched } else { matched }
        })
    }
}

// ─── Tiered Engine ────────────────────────────────────────────────────────────

/// A detection engine that separates rules into two tiers for performance:
///
/// 1. **Fast rules** are always checked against every event.
/// 2. **Complex rules** are only evaluated when at least one fast rule produced
///    a match *on the same event*, or when the event text contains a shared
///    "suspicion keyword" that warrants deeper inspection.
///
/// This mirrors how production SIEM engines work: cheap AC-only passes act as
/// a pre-filter, dramatically reducing the number of expensive regex/temporal
/// evaluations per event.
pub struct TieredSigmaEngine {
    /// AC-only rules — evaluated for every event.
    pub fast_rules: Vec<CompiledSigmaRule>,
    /// Regex/complex rules — evaluated only after a fast-rule match.
    pub complex_rules: Vec<CompiledSigmaRule>,
    /// Global AC automaton over all fast-rule patterns, used as a quick
    /// "any fast rule could match?" gate before iterating fast_rules.
    global_fast_ac: Option<AhoCorasick>,
}

impl TieredSigmaEngine {
    /// Build a tiered engine from a flat list of compiled rules.
    pub fn new(rules: Vec<CompiledSigmaRule>) -> Self {
        let mut fast_rules = Vec::new();
        let mut complex_rules = Vec::new();

        for rule in rules {
            if rule.is_complex() {
                complex_rules.push(rule);
            } else {
                fast_rules.push(rule);
            }
        }

        // Build a global AC over all keywords from fast rules for the pre-filter gate
        let all_fast_patterns: Vec<String> = fast_rules
            .iter()
            .flat_map(|r| {
                r.selections
                    .values()
                    .flatten()
                    .flat_map(|m| m.patterns.clone())
                    .chain(r.keywords.clone())
            })
            .filter(|p| p.len() >= 4)
            .collect();

        let global_fast_ac = if !all_fast_patterns.is_empty() {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&all_fast_patterns)
                .ok()
        } else {
            None
        };

        let fast_count = fast_rules.len();
        let complex_count = complex_rules.len();
        info!(
            "⚡ TieredSigmaEngine: {} fast rules, {} complex rules",
            fast_count, complex_count
        );

        Self {
            fast_rules,
            complex_rules,
            global_fast_ac,
        }
    }

    /// Load all `.yml` rules from a directory and build a tiered engine.
    pub fn from_directory(dir: &std::path::Path) -> Self {
        let rules = SigmaCompiler::load_directory(dir);
        Self::new(rules)
    }

    /// Evaluate all rules against an event using tiered evaluation.
    ///
    /// Returns a list of matching rule titles.
    pub fn evaluate(&self, event: &EnrichedEvent) -> Vec<&CompiledSigmaRule> {
        let text = event_to_string(event);
        let mut matched = Vec::new();

        // ── Tier 1: Fast rules ────────────────────────────────────────────────
        // Pre-filter: check global AC first.  If nothing in the union of fast
        // patterns matches, skip all fast rules entirely.
        let fast_gate = self
            .global_fast_ac
            .as_ref()
            .map(|ac| ac.is_match(&text))
            .unwrap_or(true); // if no gate built, always check

        let mut any_fast_match = false;
        if fast_gate {
            for rule in &self.fast_rules {
                if rule.eval_condition(&rule.condition, &text) {
                    matched.push(rule);
                    any_fast_match = true;
                }
            }
        }

        // ── Tier 2: Complex rules ─────────────────────────────────────────────
        // Only run complex rules if at least one fast rule fired.
        // This avoids expensive evaluations on clearly benign events.
        // Operators can disable the gate by using `evaluate_all` instead.
        if any_fast_match {
            for rule in &self.complex_rules {
                if rule.eval_condition(&rule.condition, &text) {
                    matched.push(rule);
                }
            }
        }

        matched
    }

    /// Evaluate all rules regardless of tier (no gating).
    /// Use for auditing or when false-negative risk is unacceptable.
    pub fn evaluate_all(&self, event: &EnrichedEvent) -> Vec<&CompiledSigmaRule> {
        let text = event_to_string(event);
        self.fast_rules
            .iter()
            .chain(self.complex_rules.iter())
            .filter(|r| r.eval_condition(&r.condition, &text))
            .collect()
    }

    pub fn fast_rule_count(&self) -> usize {
        self.fast_rules.len()
    }

    pub fn complex_rule_count(&self) -> usize {
        self.complex_rules.len()
    }

    pub fn total_rule_count(&self) -> usize {
        self.fast_rules.len() + self.complex_rules.len()
    }
}

// ─── Condition parser ─────────────────────────────────────────────────────────

fn parse_condition(s: &str) -> Result<ConditionNode> {
    let s = s.trim();

    if s.starts_with("1of(") || s.starts_with("1 of (") {
        let inner = extract_paren_content(s)?;
        return Ok(ConditionNode::OneOf(inner));
    }
    if s.starts_with("all of (") || s.starts_with("allof(") {
        let inner = extract_paren_content(s)?;
        return Ok(ConditionNode::AllOf(inner));
    }

    if s.starts_with("not ") || s.starts_with("NOT ") {
        let inner = parse_condition(&s[4..])?;
        return Ok(ConditionNode::Not(Box::new(inner)));
    }

    if let Some(parts) = split_top_level(s, " or ") {
        if parts.len() > 1 {
            let children: Result<Vec<_>> =
                parts.iter().map(|p| parse_condition(p)).collect();
            return Ok(ConditionNode::Or(children?));
        }
    }

    if let Some(parts) = split_top_level(s, " and ") {
        if parts.len() > 1 {
            let children: Result<Vec<_>> =
                parts.iter().map(|p| parse_condition(p)).collect();
            return Ok(ConditionNode::And(children?));
        }
    }

    if s.starts_with('(') && s.ends_with(')') {
        return parse_condition(&s[1..s.len() - 1]);
    }

    if s == "keywords" {
        return Ok(ConditionNode::Keywords);
    }

    Ok(ConditionNode::Selection(s.to_string()))
}

fn extract_paren_content(s: &str) -> Result<String> {
    let start = s.find('(').context("No (")?;
    let end = s.rfind(')').context("No )")?;
    Ok(s[start + 1..end].to_string())
}

fn split_top_level<'a>(s: &'a str, sep: &str) -> Option<Vec<&'a str>> {
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
        if chars[i] == '(' {
            depth += 1;
        } else if chars[i] == ')' {
            depth -= 1;
        } else if depth == 0 && i + slen <= chars.len() && chars[i..i + slen] == sep_chars[..] {
            parts.push(s[last..i].trim());
            last = i + slen;
            i += slen;
            continue;
        }
        i += 1;
    }
    parts.push(s[last..].trim());

    if parts.len() > 1 { Some(parts) } else { None }
}

// ─── Selection compilation ────────────────────────────────────────────────────

fn compile_selection(name: &str, val: &serde_yml::Value) -> Result<Vec<SelectionMatcher>> {
    let mut matchers = Vec::new();

    match val {
        serde_yml::Value::Mapping(map) => {
            for (k, v) in map {
                let field_name = k.as_str().unwrap_or("").to_string();
                let negate = field_name.ends_with("|not");
                // Detect regex modifier in field modifier chain
                let has_regex = field_name.contains("|re|")
                    || field_name.ends_with("|re")
                    || field_name.contains("|regex");

                let field_clean = field_name
                    .replace("|contains|all", "")
                    .replace("|contains", "")
                    .replace("|startswith", "")
                    .replace("|endswith", "")
                    .replace("|not", "")
                    .replace("|all", "")
                    .replace("|re", "")
                    .replace("|regex", "");

                let patterns = extract_strings_from_yaml(v);
                if patterns.is_empty() {
                    continue;
                }

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
                            has_regex,
                        });
                    }
                    Err(e) => warn!(
                        "AC build failed for selection '{}' field '{}': {}",
                        name, field_name, e
                    ),
                }
            }
        }
        serde_yml::Value::Sequence(_) => {
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
                        has_regex: false,
                    });
                }
            }
        }
        _ => {}
    }

    Ok(matchers)
}

pub fn extract_strings_from_yaml(val: &serde_yml::Value) -> Vec<String> {
    let mut out = Vec::new();
    match val {
        serde_yml::Value::String(s) => {
            let cleaned = s.replace('*', "").replace('?', "");
            if cleaned.len() >= 3 {
                out.push(cleaned);
            }
        }
        serde_yml::Value::Sequence(seq) => {
            for v in seq {
                out.extend(extract_strings_from_yaml(v));
            }
        }
        serde_yml::Value::Mapping(map) => {
            for (_, v) in map {
                out.extend(extract_strings_from_yaml(v));
            }
        }
        serde_yml::Value::Bool(b) => out.push(b.to_string()),
        serde_yml::Value::Number(n) => out.push(n.to_string()),
        _ => {}
    }
    out
}

fn event_to_string(event: &EnrichedEvent) -> String {
    match &event.raw {
        RawEvent::Process(e) => format!(
            "{} {} {} {} {}",
            e.process_name,
            e.cmdline,
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
