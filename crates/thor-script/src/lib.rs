//! ThorScript — Lightweight Sandboxed Detection Scripting Engine
//!
//! A domain-specific language for writing custom network detection rules.
//! Designed as a simple, safe, non-Turing-complete scripting engine.
//!
//! Syntax example (detect_custom_c2.thor):
//! ```thor
//! rule "Custom C2 Beacon" {
//!     on network
//!     if {
//!         dst_port in [4444, 8080, 8443]
//!         and payload match /METERP|COBALT/i
//!     }
//!     then {
//!         alert(severity: "critical", msg: "Custom C2 detected")
//!         log("C2 beacon on " + str(dst_ip) + ":" + str(dst_port))
//!     }
//! }
//! ```
//!
//! Built-in functions:
//!   match(pattern)  — regex match against payload
//!   log(msg)        — append to Thor event log
//!   alert(...)      — fire a Thor alert
//!   str(val)        — convert value to string
//!   len(val)        — length of string/bytes
//!   entropy(s)      — Shannon entropy of a string

pub mod parser;
pub mod runtime;

use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};

pub use parser::{Rule, Condition, Action, ScriptToken};
pub use runtime::{ScriptEngine, ExecutionContext, ScriptAlert, ScriptResult};

/// Load and compile all `.thor` scripts from a directory.
pub fn load_scripts_from_dir(dir: &Path) -> Result<ScriptEngine> {
    let mut engine = ScriptEngine::new();
    let mut loaded = 0;

    if !dir.exists() {
        warn!("ThorScript dir not found: {:?} — no custom rules loaded", dir);
        return Ok(engine);
    }

    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("thor") {
            continue;
        }

        match std::fs::read_to_string(path) {
            Ok(src) => {
                match parser::parse_script(&src) {
                    Ok(rules) => {
                        let count = rules.len();
                        for rule in rules {
                            engine.add_rule(rule);
                        }
                        info!("ThorScript: loaded {} rules from {:?}", count, path);
                        loaded += 1;
                    }
                    Err(e) => warn!("ThorScript parse error in {:?}: {}", path, e),
                }
            }
            Err(e) => warn!("Cannot read ThorScript file {:?}: {}", path, e),
        }
    }

    info!("ThorScript: {} script files loaded, {} total rules", loaded, engine.rule_count());
    Ok(engine)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::ExecutionContext;

    #[test]
    fn empty_engine_has_zero_rules() {
        let engine = ScriptEngine::new();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn simple_rule_fires_alert() {
        let src = r#"
rule "Test Alert" {
    on network
    if {
        dst_port == 4444
    }
    then {
        alert(severity: "high", msg: "Port 4444 detected")
    }
}
"#;
        let rules = parser::parse_script(src).expect("Should parse");
        let mut engine = ScriptEngine::new();
        for r in rules { engine.add_rule(r); }

        let mut ctx = ExecutionContext::new();
        ctx.set_i64("dst_port", 4444);
        ctx.set_str("src_ip", "1.2.3.4");
        ctx.set_str("dst_ip", "5.6.7.8");

        let results = engine.evaluate_all(&ctx);
        assert!(!results.is_empty(), "Alert must fire on port 4444");
        assert_eq!(results[0].severity, "high");
    }

    #[test]
    fn rule_does_not_fire_on_mismatch() {
        let src = r#"
rule "Port 4444 Only" {
    on network
    if { dst_port == 4444 }
    then { alert(severity: "low", msg: "nope") }
}
"#;
        let rules = parser::parse_script(src).unwrap();
        let mut engine = ScriptEngine::new();
        for r in rules { engine.add_rule(r); }

        let mut ctx = ExecutionContext::new();
        ctx.set_i64("dst_port", 80);

        let results = engine.evaluate_all(&ctx);
        assert!(results.is_empty(), "No alert on port 80");
    }
}
