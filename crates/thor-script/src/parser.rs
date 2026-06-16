//! ThorScript Parser
//!
//! Parses `.thor` script files into an AST (Abstract Syntax Tree).
//!
//! Grammar (simplified):
//! ```text
//! script    := rule*
//! rule      := "rule" STRING "{" rule_body "}"
//! rule_body := event_decl condition_block action_block
//! event_decl:= "on" EVENT_TYPE
//! condition_block := "if" "{" condition+ "}"
//! action_block    := "then" "{" action+ "}"
//! condition := expr ("and" | "or") condition | expr
//! expr      := IDENT OP value | "payload" "match" REGEX
//! action    := "alert" "(" kv_list ")"
//!            | "log" "(" string_expr ")"
//!            | "drop" "()"
//! ```

use anyhow::{bail, Result};
use regex::Regex;
use once_cell::sync::OnceCell;

// ─── AST ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    Network,
    Dns,
    Http,
    Tls,
    Process,
    File,
    Any,
}

impl EventType {
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "network" => Ok(Self::Network),
            "dns"     => Ok(Self::Dns),
            "http"    => Ok(Self::Http),
            "tls"     => Ok(Self::Tls),
            "process" => Ok(Self::Process),
            "file"    => Ok(Self::File),
            "any"     => Ok(Self::Any),
            other     => bail!("Unknown event type: {}", other),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Operator {
    Eq,   Ne,   Lt,   Gt,   Le,   Ge,
    In,   NotIn,
    Match,        // regex match
    NotMatch,
    Contains,
}

#[derive(Debug, Clone)]
pub enum Value {
    Str(String),
    Int(i64),
    List(Vec<Value>),
    Regex(String),
    Bool(bool),
}

#[derive(Debug, Clone)]
pub enum Condition {
    /// field op value
    Compare { field: String, op: Operator, value: Value },
    /// payload match /regex/flags
    PayloadMatch { pattern: String, case_insensitive: bool },
    /// condition AND condition
    And(Box<Condition>, Box<Condition>),
    /// condition OR condition
    Or(Box<Condition>, Box<Condition>),
    /// NOT condition
    Not(Box<Condition>),
    /// Always true (for testing)
    True,
}

#[derive(Debug, Clone)]
pub enum Action {
    /// alert(severity: "high", msg: "...")
    Alert { severity: String, msg: String },
    /// log("message")
    Log { message: String },
    /// drop()
    Drop,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name:       String,
    pub event_type: EventType,
    pub condition:  Condition,
    pub actions:    Vec<Action>,
    pub enabled:    bool,
}

// ─── Tokenizer ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ScriptToken {
    Keyword(String),
    Identifier(String),
    StringLit(String),
    IntLit(i64),
    RegexLit(String, String), // pattern, flags
    LBrace, RBrace, LParen, RParen, LBracket, RBracket,
    Colon, Comma, Plus,
    OpEq, OpNe, OpLt, OpGt, OpLe, OpGe,
    Eof,
}

const KEYWORDS: &[&str] = &[
    "rule", "on", "if", "then", "and", "or", "not", "in",
    "match", "alert", "log", "drop", "payload", "true", "false",
];

pub fn tokenize(src: &str) -> Result<Vec<ScriptToken>> {
    let mut tokens = Vec::new();
    let mut chars = src.chars().peekable();

    while let Some(&c) = chars.peek() {
        match c {
            // Skip whitespace and comments
            ' ' | '\t' | '\r' | '\n' => { chars.next(); }
            '#' => { while chars.next().map(|c| c != '\n').unwrap_or(false) {} }
            '/' => {
                chars.next();
                if chars.peek() == Some(&'/') {
                    // line comment
                    while chars.next().map(|c| c != '\n').unwrap_or(false) {}
                } else {
                    // regex literal /pattern/flags
                    let mut pat = String::new();
                    while let Some(&rc) = chars.peek() {
                        if rc == '/' { chars.next(); break; }
                        if rc == '\\' {
                            chars.next();
                            if let Some(ec) = chars.next() { pat.push('\\'); pat.push(ec); }
                        } else {
                            pat.push(rc); chars.next();
                        }
                    }
                    let mut flags = String::new();
                    while chars.peek().map(|&c| c.is_ascii_alphabetic()).unwrap_or(false) {
                        flags.push(chars.next().unwrap());
                    }
                    tokens.push(ScriptToken::RegexLit(pat, flags));
                }
            }
            '"' => {
                chars.next();
                let mut s = String::new();
                while let Some(&sc) = chars.peek() {
                    chars.next();
                    if sc == '"' { break; }
                    if sc == '\\' {
                        if let Some(esc) = chars.next() {
                            match esc { 'n' => s.push('\n'), 't' => s.push('\t'), other => s.push(other) }
                        }
                    } else {
                        s.push(sc);
                    }
                }
                tokens.push(ScriptToken::StringLit(s));
            }
            '{' => { chars.next(); tokens.push(ScriptToken::LBrace); }
            '}' => { chars.next(); tokens.push(ScriptToken::RBrace); }
            '(' => { chars.next(); tokens.push(ScriptToken::LParen); }
            ')' => { chars.next(); tokens.push(ScriptToken::RParen); }
            '[' => { chars.next(); tokens.push(ScriptToken::LBracket); }
            ']' => { chars.next(); tokens.push(ScriptToken::RBracket); }
            ':' => { chars.next(); tokens.push(ScriptToken::Colon); }
            ',' => { chars.next(); tokens.push(ScriptToken::Comma); }
            '+' => { chars.next(); tokens.push(ScriptToken::Plus); }
            '=' => {
                chars.next();
                if chars.peek() == Some(&'=') { chars.next(); tokens.push(ScriptToken::OpEq); }
                else { tokens.push(ScriptToken::OpEq); } // single = treated as ==
            }
            '!' => {
                chars.next();
                if chars.peek() == Some(&'=') { chars.next(); tokens.push(ScriptToken::OpNe); }
            }
            '<' => {
                chars.next();
                if chars.peek() == Some(&'=') { chars.next(); tokens.push(ScriptToken::OpLe); }
                else { tokens.push(ScriptToken::OpLt); }
            }
            '>' => {
                chars.next();
                if chars.peek() == Some(&'=') { chars.next(); tokens.push(ScriptToken::OpGe); }
                else { tokens.push(ScriptToken::OpGt); }
            }
            c if c.is_ascii_digit() || (c == '-' && chars.clone().nth(1).map(|n| n.is_ascii_digit()).unwrap_or(false)) => {
                let mut n = String::new();
                if c == '-' { n.push('-'); chars.next(); }
                while chars.peek().map(|&d| d.is_ascii_digit()).unwrap_or(false) {
                    n.push(chars.next().unwrap());
                }
                tokens.push(ScriptToken::IntLit(n.parse().unwrap_or(0)));
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let mut ident = String::new();
                while chars.peek().map(|&c| c.is_ascii_alphanumeric() || c == '_').unwrap_or(false) {
                    ident.push(chars.next().unwrap());
                }
                if KEYWORDS.contains(&ident.as_str()) {
                    tokens.push(ScriptToken::Keyword(ident));
                } else {
                    tokens.push(ScriptToken::Identifier(ident));
                }
            }
            other => { chars.next(); } // skip unknown
        }
    }
    tokens.push(ScriptToken::Eof);
    Ok(tokens)
}

// ─── Parser ───────────────────────────────────────────────────────────────────

struct Parser {
    tokens: Vec<ScriptToken>,
    pos:    usize,
}

impl Parser {
    fn new(tokens: Vec<ScriptToken>) -> Self { Self { tokens, pos: 0 } }

    fn peek(&self) -> &ScriptToken {
        self.tokens.get(self.pos).unwrap_or(&ScriptToken::Eof)
    }

    fn advance(&mut self) -> &ScriptToken {
        let t = &self.tokens[self.pos];
        if self.pos + 1 < self.tokens.len() { self.pos += 1; }
        t
    }

    fn expect_keyword(&mut self, kw: &str) -> Result<()> {
        match self.peek().clone() {
            ScriptToken::Keyword(k) if k == kw => { self.advance(); Ok(()) }
            other => bail!("Expected keyword '{}', got {:?}", kw, other),
        }
    }

    fn expect_lbrace(&mut self) -> Result<()> {
        if *self.peek() == ScriptToken::LBrace { self.advance(); Ok(()) }
        else { bail!("Expected '{{', got {:?}", self.peek()) }
    }

    fn expect_rbrace(&mut self) -> Result<()> {
        if *self.peek() == ScriptToken::RBrace { self.advance(); Ok(()) }
        else { bail!("Expected '}}', got {:?}", self.peek()) }
    }

    fn parse_all(&mut self) -> Result<Vec<Rule>> {
        let mut rules = Vec::new();
        while *self.peek() != ScriptToken::Eof {
            if let ScriptToken::Keyword(k) = self.peek().clone() {
                if k == "rule" {
                    rules.push(self.parse_rule()?);
                    continue;
                }
            }
            self.advance(); // skip unexpected tokens
        }
        Ok(rules)
    }

    fn parse_rule(&mut self) -> Result<Rule> {
        self.expect_keyword("rule")?;

        let name = match self.advance().clone() {
            ScriptToken::StringLit(s) => s,
            ScriptToken::Identifier(s) => s,
            other => bail!("Expected rule name string, got {:?}", other),
        };

        self.expect_lbrace()?;

        // on EVENT
        self.expect_keyword("on")?;
        let event_type = match self.advance().clone() {
            ScriptToken::Keyword(s) | ScriptToken::Identifier(s) => EventType::from_str(&s)?,
            other => bail!("Expected event type, got {:?}", other),
        };

        // if { ... }
        self.expect_keyword("if")?;
        self.expect_lbrace()?;
        let condition = self.parse_conditions()?;
        self.expect_rbrace()?;

        // then { ... }
        self.expect_keyword("then")?;
        self.expect_lbrace()?;
        let actions = self.parse_actions()?;
        self.expect_rbrace()?;

        self.expect_rbrace()?; // end of rule

        Ok(Rule { name, event_type, condition, actions, enabled: true })
    }

    fn parse_conditions(&mut self) -> Result<Condition> {
        let mut cond = self.parse_single_condition()?;

        loop {
            match self.peek().clone() {
                ScriptToken::Keyword(k) if k == "and" => {
                    self.advance();
                    let right = self.parse_single_condition()?;
                    cond = Condition::And(Box::new(cond), Box::new(right));
                }
                ScriptToken::Keyword(k) if k == "or" => {
                    self.advance();
                    let right = self.parse_single_condition()?;
                    cond = Condition::Or(Box::new(cond), Box::new(right));
                }
                _ => break,
            }
        }
        Ok(cond)
    }

    fn parse_single_condition(&mut self) -> Result<Condition> {
        // NOT condition
        if let ScriptToken::Keyword(k) = self.peek().clone() {
            if k == "not" {
                self.advance();
                let inner = self.parse_single_condition()?;
                return Ok(Condition::Not(Box::new(inner)));
            }
        }

        // "payload" "match" /regex/flags
        if let ScriptToken::Keyword(k) = self.peek().clone() {
            if k == "payload" {
                self.advance();
                match self.peek().clone() {
                    ScriptToken::Keyword(m) if m == "match" => {
                        self.advance();
                        if let ScriptToken::RegexLit(pat, flags) = self.advance().clone() {
                            let ci = flags.contains('i');
                            return Ok(Condition::PayloadMatch { pattern: pat, case_insensitive: ci });
                        }
                        bail!("Expected regex after payload match");
                    }
                    _ => bail!("Expected 'match' after payload"),
                }
            }
        }

        // FIELD OP VALUE
        let field = match self.advance().clone() {
            ScriptToken::Identifier(s) | ScriptToken::Keyword(s) => s,
            other => bail!("Expected field name, got {:?}", other),
        };

        let op = self.parse_operator()?;
        let value = self.parse_value()?;

        Ok(Condition::Compare { field, op, value })
    }

    fn parse_operator(&mut self) -> Result<Operator> {
        match self.advance().clone() {
            ScriptToken::OpEq => Ok(Operator::Eq),
            ScriptToken::OpNe => Ok(Operator::Ne),
            ScriptToken::OpLt => Ok(Operator::Lt),
            ScriptToken::OpGt => Ok(Operator::Gt),
            ScriptToken::OpLe => Ok(Operator::Le),
            ScriptToken::OpGe => Ok(Operator::Ge),
            ScriptToken::Keyword(k) if k == "in"    => Ok(Operator::In),
            ScriptToken::Keyword(k) if k == "match" => Ok(Operator::Match),
            other => bail!("Expected operator, got {:?}", other),
        }
    }

    fn parse_value(&mut self) -> Result<Value> {
        match self.advance().clone() {
            ScriptToken::StringLit(s) => Ok(Value::Str(s)),
            ScriptToken::IntLit(n)    => Ok(Value::Int(n)),
            ScriptToken::Keyword(k) if k == "true"  => Ok(Value::Bool(true)),
            ScriptToken::Keyword(k) if k == "false" => Ok(Value::Bool(false)),
            ScriptToken::RegexLit(p, _) => Ok(Value::Regex(p)),
            ScriptToken::LBracket => {
                let mut list = Vec::new();
                while *self.peek() != ScriptToken::RBracket && *self.peek() != ScriptToken::Eof {
                    list.push(self.parse_value()?);
                    if *self.peek() == ScriptToken::Comma { self.advance(); }
                }
                if *self.peek() == ScriptToken::RBracket { self.advance(); }
                Ok(Value::List(list))
            }
            other => bail!("Expected value, got {:?}", other),
        }
    }

    fn parse_actions(&mut self) -> Result<Vec<Action>> {
        let mut actions = Vec::new();
        while *self.peek() != ScriptToken::RBrace && *self.peek() != ScriptToken::Eof {
            actions.push(self.parse_action()?);
        }
        Ok(actions)
    }

    fn parse_action(&mut self) -> Result<Action> {
        match self.advance().clone() {
            ScriptToken::Keyword(k) if k == "alert" => {
                // alert(severity: "high", msg: "...")
                if *self.peek() == ScriptToken::LParen { self.advance(); }
                let mut severity = "medium".to_string();
                let mut msg = String::new();

                while *self.peek() != ScriptToken::RParen && *self.peek() != ScriptToken::Eof {
                    let key = match self.advance().clone() {
                        ScriptToken::Identifier(s) | ScriptToken::Keyword(s) => s,
                        _ => break,
                    };
                    if *self.peek() == ScriptToken::Colon { self.advance(); }
                    let val = match self.advance().clone() {
                        ScriptToken::StringLit(s) => s,
                        ScriptToken::IntLit(n) => n.to_string(),
                        _ => String::new(),
                    };
                    match key.as_str() {
                        "severity" => severity = val,
                        "msg"      => msg = val,
                        _ => {}
                    }
                    if *self.peek() == ScriptToken::Comma { self.advance(); }
                }
                if *self.peek() == ScriptToken::RParen { self.advance(); }
                Ok(Action::Alert { severity, msg })
            }
            ScriptToken::Keyword(k) if k == "log" => {
                if *self.peek() == ScriptToken::LParen { self.advance(); }
                let msg = match self.advance().clone() {
                    ScriptToken::StringLit(s) => s,
                    _ => String::new(),
                };
                if *self.peek() == ScriptToken::RParen { self.advance(); }
                Ok(Action::Log { message: msg })
            }
            ScriptToken::Keyword(k) if k == "drop" => {
                if *self.peek() == ScriptToken::LParen { self.advance(); }
                if *self.peek() == ScriptToken::RParen { self.advance(); }
                Ok(Action::Drop)
            }
            other => bail!("Expected action keyword, got {:?}", other),
        }
    }
}

/// Parse a ThorScript source string into a list of rules.
pub fn parse_script(src: &str) -> Result<Vec<Rule>> {
    let tokens = tokenize(src)?;
    let mut parser = Parser::new(tokens);
    parser.parse_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_basic() {
        let src = r#"rule "test" { on network if { port == 80 } then { drop() } }"#;
        let tokens = tokenize(src).unwrap();
        assert!(tokens.len() > 5);
    }

    #[test]
    fn parse_simple_rule() {
        let src = r#"
rule "Port 4444 Alert" {
    on network
    if { dst_port == 4444 }
    then { alert(severity: "critical", msg: "Meterpreter port") }
}
"#;
        let rules = parse_script(src).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "Port 4444 Alert");
        assert!(matches!(rules[0].event_type, EventType::Network));
        assert_eq!(rules[0].actions.len(), 1);
    }

    #[test]
    fn parse_and_condition() {
        let src = r#"
rule "C2 Check" {
    on network
    if { dst_port == 4444 and src_ip == "1.2.3.4" }
    then { drop() }
}
"#;
        let rules = parse_script(src).unwrap();
        assert!(matches!(rules[0].condition, Condition::And(_, _)));
    }

    #[test]
    fn parse_in_list() {
        let src = r#"
rule "Bad Ports" {
    on network
    if { dst_port in [4444, 8080, 9999] }
    then { alert(severity: "high", msg: "bad port") }
}
"#;
        let rules = parse_script(src).unwrap();
        assert!(matches!(rules[0].condition,
            Condition::Compare { op: Operator::In, .. }));
    }

    #[test]
    fn parse_payload_match() {
        let src = r#"
rule "Meterpreter Payload" {
    on network
    if { payload match /METERPRETER/i }
    then { alert(severity: "critical", msg: "Shellcode detected") }
}
"#;
        let rules = parse_script(src).unwrap();
        assert!(matches!(rules[0].condition,
            Condition::PayloadMatch { case_insensitive: true, .. }));
    }

    #[test]
    fn parse_multiple_rules() {
        let src = r#"
rule "Rule A" {
    on network
    if { dst_port == 80 }
    then { log("port 80") }
}
rule "Rule B" {
    on dns
    if { dst_port == 53 }
    then { log("dns query") }
}
"#;
        let rules = parse_script(src).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn regex_tokenized_correctly() {
        let tokens = tokenize(r#"payload match /EVIL/i"#).unwrap();
        let has_regex = tokens.iter().any(|t| matches!(t, ScriptToken::RegexLit(_, _)));
        assert!(has_regex);
    }
}
