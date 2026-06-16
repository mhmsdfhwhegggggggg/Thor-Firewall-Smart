//! ThorScript Runtime — Script evaluation engine
//!
//! Evaluates parsed Rule ASTs against an ExecutionContext.
//! Sandboxed: no I/O, no recursion, bounded execution time,
//! no external access.

use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use dashmap::DashMap;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::parser::{Rule, Condition, Action, Operator, Value, EventType};

// ─── Execution Context ────────────────────────────────────────────────────────

/// Variables available to a ThorScript rule during evaluation.
#[derive(Debug, Default, Clone)]
pub struct ExecutionContext {
    str_vars: HashMap<String, String>,
    int_vars: HashMap<String, i64>,
    bool_vars: HashMap<String, bool>,
    payload:   Vec<u8>,
    event_type: String,
}

impl ExecutionContext {
    pub fn new() -> Self { Self::default() }

    pub fn set_str(&mut self, k: &str, v: &str) {
        self.str_vars.insert(k.to_string(), v.to_string());
    }
    pub fn set_i64(&mut self, k: &str, v: i64) {
        self.int_vars.insert(k.to_string(), v);
    }
    pub fn set_bool(&mut self, k: &str, v: bool) {
        self.bool_vars.insert(k.to_string(), v);
    }
    pub fn set_payload(&mut self, data: &[u8]) {
        self.payload = data.to_vec();
    }
    pub fn set_event_type(&mut self, t: &str) {
        self.event_type = t.to_string();
    }

    pub fn get_str(&self, k: &str) -> Option<&str> {
        self.str_vars.get(k).map(|s| s.as_str())
    }
    pub fn get_i64(&self, k: &str) -> Option<i64> {
        self.int_vars.get(k).copied()
            .or_else(|| self.str_vars.get(k)?.parse().ok())
    }
    pub fn get_bool(&self, k: &str) -> Option<bool> {
        self.bool_vars.get(k).copied()
    }
}

// ─── Script Result ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ScriptAlert {
    pub rule_name: String,
    pub severity:  String,
    pub msg:       String,
    pub drop:      bool,
}

#[derive(Debug, Clone)]
pub struct ScriptResult {
    pub rule_name: String,
    pub severity:  String,
    pub msg:       String,
    pub drop:      bool,
    pub logs:      Vec<String>,
}

// ─── Script Engine ────────────────────────────────────────────────────────────

pub struct ScriptEngine {
    rules: Vec<CompiledRule>,
}

struct CompiledRule {
    rule:       Rule,
    regex_cache: HashMap<String, Regex>,
}

impl CompiledRule {
    fn new(rule: Rule) -> Self {
        // Pre-compile regexes from all PayloadMatch conditions
        let mut cache = HashMap::new();
        collect_regexes(&rule.condition, &mut cache);
        Self { rule, regex_cache: cache }
    }
}

fn collect_regexes(cond: &Condition, cache: &mut HashMap<String, Regex>) {
    match cond {
        Condition::PayloadMatch { pattern, case_insensitive } => {
            let re_str = if *case_insensitive {
                format!("(?i){}", pattern)
            } else {
                pattern.clone()
            };
            if !cache.contains_key(&re_str) {
                if let Ok(re) = Regex::new(&re_str) {
                    cache.insert(re_str, re);
                }
            }
        }
        Condition::And(a, b) | Condition::Or(a, b) => {
            collect_regexes(a, cache);
            collect_regexes(b, cache);
        }
        Condition::Not(inner) => collect_regexes(inner, cache),
        _ => {}
    }
}

impl ScriptEngine {
    pub fn new() -> Self { Self { rules: Vec::new() } }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(CompiledRule::new(rule));
    }

    pub fn rule_count(&self) -> usize { self.rules.len() }

    /// Evaluate all rules against the context. Returns fired alerts.
    pub fn evaluate_all(&self, ctx: &ExecutionContext) -> Vec<ScriptResult> {
        let mut results = Vec::new();

        for cr in &self.rules {
            if !cr.rule.enabled { continue; }

            // Event type filter
            let matches_event = match &cr.rule.event_type {
                EventType::Any => true,
                EventType::Network => ctx.event_type.is_empty() || ctx.event_type == "network",
                EventType::Dns     => ctx.event_type == "dns",
                EventType::Http    => ctx.event_type == "http",
                EventType::Tls     => ctx.event_type == "tls",
                EventType::Process => ctx.event_type == "process",
                EventType::File    => ctx.event_type == "file",
            };
            if !matches_event { continue; }

            if self.eval_condition(&cr.rule.condition, ctx, &cr.regex_cache) {
                let mut logs = Vec::new();
                let mut severity = "medium".to_string();
                let mut msg = cr.rule.name.clone();
                let mut drop = false;

                for action in &cr.rule.actions {
                    match action {
                        Action::Alert { severity: s, msg: m } => {
                            severity = s.clone();
                            msg = m.clone();
                        }
                        Action::Log { message } => {
                            let expanded = self.expand_string(message, ctx);
                            debug!("[ThorScript] {}", expanded);
                            logs.push(expanded);
                        }
                        Action::Drop => { drop = true; }
                    }
                }

                results.push(ScriptResult {
                    rule_name: cr.rule.name.clone(),
                    severity,
                    msg,
                    drop,
                    logs,
                });
            }
        }

        results
    }

    // ── Condition evaluator ──────────────────────────────────────────────────

    fn eval_condition(
        &self,
        cond: &Condition,
        ctx: &ExecutionContext,
        regex_cache: &HashMap<String, Regex>,
    ) -> bool {
        match cond {
            Condition::True => true,

            Condition::And(a, b) =>
                self.eval_condition(a, ctx, regex_cache) && self.eval_condition(b, ctx, regex_cache),

            Condition::Or(a, b) =>
                self.eval_condition(a, ctx, regex_cache) || self.eval_condition(b, ctx, regex_cache),

            Condition::Not(inner) =>
                !self.eval_condition(inner, ctx, regex_cache),

            Condition::PayloadMatch { pattern, case_insensitive } => {
                let key = if *case_insensitive {
                    format!("(?i){}", pattern)
                } else {
                    pattern.clone()
                };
                if let Some(re) = regex_cache.get(&key) {
                    let text = std::str::from_utf8(&ctx.payload).unwrap_or("");
                    re.is_match(text)
                } else {
                    false
                }
            }

            Condition::Compare { field, op, value } => {
                self.eval_compare(field, op, value, ctx)
            }
        }
    }

    fn eval_compare(&self, field: &str, op: &Operator, value: &Value, ctx: &ExecutionContext) -> bool {
        match op {
            Operator::In | Operator::NotIn => {
                if let Value::List(items) = value {
                    let found = items.iter().any(|item| {
                        match item {
                            Value::Int(n) => ctx.get_i64(field).map(|v| v == *n).unwrap_or(false),
                            Value::Str(s) => ctx.get_str(field).map(|v| v == s).unwrap_or(false),
                            _ => false,
                        }
                    });
                    match op { Operator::In => found, _ => !found }
                } else { false }
            }

            Operator::Match => {
                let text = ctx.get_str(field).unwrap_or("");
                if let Value::Regex(pat) = value {
                    Regex::new(pat).map(|re| re.is_match(text)).unwrap_or(false)
                } else { false }
            }

            Operator::Contains => {
                let text = ctx.get_str(field).unwrap_or("");
                if let Value::Str(s) = value { text.contains(s.as_str()) } else { false }
            }

            // Numeric / string comparison
            _ => {
                // Try numeric first
                if let (Some(lhs), Value::Int(rhs)) = (ctx.get_i64(field), value) {
                    return match op {
                        Operator::Eq => lhs == *rhs,
                        Operator::Ne => lhs != *rhs,
                        Operator::Lt => lhs < *rhs,
                        Operator::Gt => lhs > *rhs,
                        Operator::Le => lhs <= *rhs,
                        Operator::Ge => lhs >= *rhs,
                        _ => false,
                    };
                }
                // String comparison
                if let (Some(lhs), Value::Str(rhs)) = (ctx.get_str(field), value) {
                    return match op {
                        Operator::Eq => lhs == rhs,
                        Operator::Ne => lhs != rhs,
                        _ => false,
                    };
                }
                // Bool
                if let (Some(lhs), Value::Bool(rhs)) = (ctx.get_bool(field), value) {
                    return match op {
                        Operator::Eq => lhs == *rhs,
                        Operator::Ne => lhs != *rhs,
                        _ => false,
                    };
                }
                false
            }
        }
    }

    fn expand_string(&self, template: &str, ctx: &ExecutionContext) -> String {
        // Very basic: replace ${field} with its value
        let mut result = template.to_string();
        for (k, v) in &ctx.str_vars {
            result = result.replace(&format!("${{{}}}", k), v);
        }
        for (k, v) in &ctx.int_vars {
            result = result.replace(&format!("${{{}}}", k), &v.to_string());
        }
        result
    }
}

impl Default for ScriptEngine {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{Rule, Condition, Action, EventType, Operator, Value};

    fn make_rule(name: &str, cond: Condition, actions: Vec<Action>) -> Rule {
        Rule {
            name: name.to_string(),
            event_type: EventType::Any,
            condition: cond,
            actions,
            enabled: true,
        }
    }

    #[test]
    fn eval_eq_int_matches() {
        let mut engine = ScriptEngine::new();
        engine.add_rule(make_rule(
            "Port 4444",
            Condition::Compare { field: "dst_port".into(), op: Operator::Eq, value: Value::Int(4444) },
            vec![Action::Alert { severity: "high".into(), msg: "hit".into() }],
        ));

        let mut ctx = ExecutionContext::new();
        ctx.set_i64("dst_port", 4444);

        let results = engine.evaluate_all(&ctx);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, "high");
    }

    #[test]
    fn eval_in_list_matches() {
        let mut engine = ScriptEngine::new();
        engine.add_rule(make_rule(
            "Bad Ports",
            Condition::Compare {
                field: "dst_port".into(),
                op: Operator::In,
                value: Value::List(vec![Value::Int(4444), Value::Int(8080), Value::Int(9999)]),
            },
            vec![Action::Alert { severity: "medium".into(), msg: "bad port".into() }],
        ));

        let mut ctx = ExecutionContext::new();
        ctx.set_i64("dst_port", 8080);
        let r = engine.evaluate_all(&ctx);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn eval_and_condition() {
        let mut engine = ScriptEngine::new();
        engine.add_rule(make_rule(
            "Both",
            Condition::And(
                Box::new(Condition::Compare { field: "dst_port".into(), op: Operator::Eq, value: Value::Int(80) }),
                Box::new(Condition::Compare { field: "src_ip".into(), op: Operator::Eq, value: Value::Str("1.2.3.4".into()) }),
            ),
            vec![Action::Drop],
        ));

        let mut ctx = ExecutionContext::new();
        ctx.set_i64("dst_port", 80);
        ctx.set_str("src_ip", "1.2.3.4");

        let r = engine.evaluate_all(&ctx);
        assert_eq!(r.len(), 1);
        assert!(r[0].drop);
    }

    #[test]
    fn eval_payload_match() {
        let mut engine = ScriptEngine::new();
        engine.add_rule(make_rule(
            "Shellcode",
            Condition::PayloadMatch { pattern: "METERPRETER".into(), case_insensitive: true },
            vec![Action::Alert { severity: "critical".into(), msg: "shellcode".into() }],
        ));

        let mut ctx = ExecutionContext::new();
        ctx.set_payload(b"some data meterpreter payload here");

        let r = engine.evaluate_all(&ctx);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, "critical");
    }

    #[test]
    fn eval_not_condition() {
        let mut engine = ScriptEngine::new();
        engine.add_rule(make_rule(
            "Not 80",
            Condition::Not(Box::new(
                Condition::Compare { field: "dst_port".into(), op: Operator::Eq, value: Value::Int(80) }
            )),
            vec![Action::Log { message: "not port 80".into() }],
        ));

        let mut ctx = ExecutionContext::new();
        ctx.set_i64("dst_port", 443);

        let r = engine.evaluate_all(&ctx);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn disabled_rule_skipped() {
        let mut engine = ScriptEngine::new();
        let mut rule = make_rule(
            "Disabled",
            Condition::True,
            vec![Action::Alert { severity: "low".into(), msg: "disabled".into() }],
        );
        rule.enabled = false;
        engine.add_rule(rule);

        let ctx = ExecutionContext::new();
        let r = engine.evaluate_all(&ctx);
        assert!(r.is_empty());
    }

    #[test]
    fn multiple_rules_all_fire() {
        let mut engine = ScriptEngine::new();
        for i in 0..3 {
            engine.add_rule(make_rule(
                &format!("Rule {}", i),
                Condition::True,
                vec![Action::Alert { severity: "low".into(), msg: format!("rule {}", i) }],
            ));
        }
        let ctx = ExecutionContext::new();
        let r = engine.evaluate_all(&ctx);
        assert_eq!(r.len(), 3);
    }
}
