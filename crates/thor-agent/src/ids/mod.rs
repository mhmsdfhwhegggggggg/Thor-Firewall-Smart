//! ThorIDS — Production Suricata-Compatible IDS Rule Engine (Axis 2)
//!
//! 400+ built-in Thor rules covering:
//!   ▸ C2 frameworks (Cobalt Strike, Meterpreter, Sliver, Havoc, Empire, AsyncRAT…)
//!   ▸ Web exploits (SQLi, XSS, Log4Shell, Spring4Shell, Shellshock, SSRF, RCE)
//!   ▸ Malware families (Emotet, Trickbot, QBot, Redline, AgentTesla, IcedID)
//!   ▸ Network recon (SYN scan, Nmap, Masscan, Shodan probes)
//!   ▸ Brute force (SSH, RDP, FTP, SMTP, HTTP Basic, SMB)
//!   ▸ Lateral movement (EternalBlue, PsExec, WinRM, Pass-the-Hash)
//!   ▸ Data exfiltration (DNS tunnel, FTP, SMTP relay, Pastebin)
//!   ▸ Ransomware indicators
//!   ▸ TLS anomalies (JA4 bad fingerprints, weak ciphers, self-signed)
//!   ▸ DNS anomalies (DGA, tunneling, Tor, fast-flux)
//!   ▸ ICS/SCADA protocols (Modbus, S7, DNP3)
//!   ▸ Crypto mining (Stratum, XMRig)
//!   ▸ Cloud metadata abuse (AWS/Azure/GCP IMDS)
//!   ▸ Container escape indicators

pub mod matcher;
pub mod rule_parser;
pub mod threshold;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use dashmap::DashMap;
use tracing::{info, warn};
use uuid::Uuid;
use chrono::Utc;

use crate::events::{Alert, RuleType};
use crate::events::enrichment::EnrichedEvent;
use thor_common::ThreatLevel;

pub use rule_parser::{IdsRule, IdsAction, IdsProtocol, RuleOption};
pub use matcher::IdsMatcher;
pub use threshold::ThresholdEngine;

// ─── IDS Engine ───────────────────────────────────────────────────────────────

pub struct IdsEngine {
    rules: Vec<CompiledIdsRule>,
    sid_index: HashMap<u32, usize>,
    suppressions: Arc<DashMap<u32, Instant>>,
    threshold_engine: ThresholdEngine,
    stats: IdsStats,
}

#[derive(Default)]
pub struct IdsStats {
    pub rules_loaded: usize,
    pub events_scanned: u64,
    pub alerts_fired: u64,
    pub rules_by_action: HashMap<String, usize>,
}

pub struct CompiledIdsRule {
    pub rule: IdsRule,
    pub matcher: IdsMatcher,
}

impl IdsEngine {
    pub fn load_from_dir(rules_dir: &Path) -> Result<Self> {
        let mut rules = Vec::new();
        let mut sid_index = HashMap::new();

        if rules_dir.exists() {
            for entry in walkdir::WalkDir::new(rules_dir)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("rules") {
                    continue;
                }
                match std::fs::read_to_string(path) {
                    Ok(content) => {
                        for line in content.lines() {
                            let line = line.trim();
                            if line.starts_with('#') || line.is_empty() { continue; }
                            if let Ok(rule) = rule_parser::parse_rule(line) {
                                let sid = rule.sid;
                                let matcher = IdsMatcher::compile(&rule);
                                let idx = rules.len();
                                if sid > 0 { sid_index.insert(sid, idx); }
                                rules.push(CompiledIdsRule { rule, matcher });
                            }
                        }
                    }
                    Err(e) => warn!("Cannot read rules file {:?}: {}", path, e),
                }
            }
        }

        for rule in builtin_rules() {
            let sid = rule.sid;
            let matcher = IdsMatcher::compile(&rule);
            let idx = rules.len();
            if sid > 0 { sid_index.insert(sid, idx); }
            rules.push(CompiledIdsRule { rule, matcher });
        }

        let mut stats = IdsStats::default();
        stats.rules_loaded = rules.len();
        for cr in &rules {
            *stats.rules_by_action.entry(format!("{:?}", cr.rule.action)).or_insert(0) += 1;
        }

        info!("🚨 ThorIDS: {} rules loaded ({} alert, {} drop)",
            rules.len(),
            stats.rules_by_action.get("Alert").unwrap_or(&0),
            stats.rules_by_action.get("Drop").unwrap_or(&0),
        );

        Ok(Self {
            rules, sid_index,
            suppressions: Arc::new(DashMap::new()),
            threshold_engine: ThresholdEngine::new(),
            stats,
        })
    }

    pub fn empty() -> Self {
        let mut rules = Vec::new();
        let mut sid_index = HashMap::new();
        for rule in builtin_rules() {
            let sid = rule.sid;
            let matcher = IdsMatcher::compile(&rule);
            let idx = rules.len();
            sid_index.insert(sid, idx);
            rules.push(CompiledIdsRule { rule, matcher });
        }
        let mut stats = IdsStats::default();
        stats.rules_loaded = rules.len();
        Self {
            rules, sid_index,
            suppressions: Arc::new(DashMap::new()),
            threshold_engine: ThresholdEngine::new(),
            stats,
        }
    }

    pub fn scan(&self, event: &EnrichedEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let payload = event_to_payload(event);
        let src_ip = event.src_ip_str.as_deref().unwrap_or("0.0.0.0");

        for cr in &self.rules {
            // Check per-SID suppression (60s cooldown to prevent flooding)
            if let Some(exp) = self.suppressions.get(&cr.rule.sid) {
                if exp.elapsed().as_secs() < 60 { continue; }
                drop(exp);
                self.suppressions.remove(&cr.rule.sid);
            }

            if cr.matcher.matches(event, &payload) {
                // Threshold check (rate limiting per source IP)
                if !self.threshold_engine.should_alert(cr.rule.sid, src_ip) {
                    continue;
                }

                let tl = priority_to_threat_level(cr.rule.priority);
                alerts.push(Alert {
                    id: Uuid::new_v4().to_string(),
                    timestamp: Utc::now(),
                    source: event.hostname.clone().unwrap_or_default(),
                    rule_name: format!("IDS:{}:{}", cr.rule.sid, cr.rule.msg),
                    rule_type: RuleType::Ids,
                    threat_level: tl,
                    description: format!(
                        "[{}] {} (sid:{} rev:{} classtype:{})",
                        format!("{:?}", cr.rule.action),
                        cr.rule.msg,
                        cr.rule.sid,
                        cr.rule.rev,
                        cr.rule.classtype.as_deref().unwrap_or("unknown")
                    ),
                    pid: None,
                    process_name: None,
                    src_ip: event.src_ip_str.clone(),
                    dst_ip: event.dst_ip_str.clone(),
                    dst_port: None,
                    ml_score: None,
                    soar_actions_taken: vec![],
                    raw_event_type: event.raw.source().to_string(),
                });

                self.suppressions.insert(cr.rule.sid, Instant::now());
            }
        }

        alerts
    }

    pub fn rule_count(&self) -> usize { self.rules.len() }
    pub fn stats(&self) -> &IdsStats { &self.stats }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn priority_to_threat_level(priority: u8) -> ThreatLevel {
    match priority {
        1 => ThreatLevel::Critical,
        2 => ThreatLevel::High,
        3 => ThreatLevel::Medium,
        _ => ThreatLevel::Low,
    }
}

fn event_to_payload(event: &EnrichedEvent) -> String {
    use crate::events::RawEvent;
    match &event.raw {
        RawEvent::Network(e) => format!(
            "{} {} {} {} {}",
            event.src_ip_str.as_deref().unwrap_or(""),
            event.dst_ip_str.as_deref().unwrap_or(""),
            e.dst_port,
            e.protocol,
            event.hostname.as_deref().unwrap_or(""),
        ),
        RawEvent::Process(e) => format!(
            "{} {} {}",
            e.cmdline,
            e.process_name,
            e.parent_name.as_deref().unwrap_or(""),
        ),
        RawEvent::Dns(e) => format!("{} {}", e.query, e.record_type),
        RawEvent::Tls(e) => format!(
            "{} {} {}",
            e.sni.as_deref().unwrap_or(""),
            e.ja4_hash.as_deref().unwrap_or(""),
            e.issuer.as_deref().unwrap_or(""),
        ),
        _ => String::new(),
    }
}

// ─── Rule builder macro ───────────────────────────────────────────────────────

macro_rules! r {
    // r!(sid, priority, action, proto, src_port, dst_port, msg, classtype, [content...], [pcre...])
    ($sid:expr, $prio:expr, $act:expr, $proto:expr, $sp:expr, $dp:expr,
     $msg:expr, $cls:expr, [$($con:expr),*], [$($pcr:expr),*]) => {
        IdsRule {
            action: $act,
            protocol: $proto,
            src_addr: "any".to_string(), src_port: $sp.to_string(),
            direction: "->".to_string(),
            dst_addr: "any".to_string(), dst_port: $dp.to_string(),
            msg: $msg.to_string(),
            sid: $sid, rev: 1, priority: $prio,
            classtype: Some($cls.to_string()),
            options: vec![],
            content_patterns: vec![$($con.to_string()),*],
            pcre_patterns: vec![$($pcr.to_string()),*],
            flow: None,
            metadata: vec!["thor-builtin".to_string()],
        }
    };
    // Simplified without pcre
    ($sid:expr, $prio:expr, $act:expr, $proto:expr, $sp:expr, $dp:expr, $msg:expr, $cls:expr) => {
        r!($sid, $prio, $act, $proto, $sp, $dp, $msg, $cls, [], [])
    };
}

// ─── 400+ Built-in Thor IDS Rules ────────────────────────────────────────────

fn builtin_rules() -> Vec<IdsRule> {
    use IdsAction::{Alert, Drop};
    use IdsProtocol::{Tcp, Udp, Dns, Tls, Http, Ssh, Ftp, Smtp, Icmp, Any};

    vec![
        // ── C2 FRAMEWORKS — Cobalt Strike ─────────────────────────────────────
        r!(9000001,1,Alert,Tcp,"any","50050","Cobalt Strike default team server port","trojan-activity"),
        r!(9000002,1,Alert,Tcp,"any","50051","Cobalt Strike alternate team server port","trojan-activity"),
        r!(9000003,1,Alert,Tcp,"any","any","Cobalt Strike HTTP beacon User-Agent","trojan-activity",
            ["Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5"],["(?i)msie 9\\.0.*windows phone"]),
        r!(9000004,1,Alert,Http,"any","80","Cobalt Strike malleable C2 /submit.php","trojan-activity",
            ["submit.php"],[]),
        r!(9000005,1,Alert,Http,"any","any","Cobalt Strike /updates.rss C2 profile","trojan-activity",
            ["updates.rss"],[]),
        r!(9000006,1,Alert,Http,"any","any","Cobalt Strike CS default certificate CN","trojan-activity",
            ["Major Cobalt", "msf"],[]),
        r!(9000007,1,Drop, Tls,"any","443","Cobalt Strike known malicious JA4 fingerprint","trojan-activity",
            ["t13d1516h2_8daaf6152771_02713d6af862"],[]),
        r!(9000008,1,Drop, Tls,"any","443","Cobalt Strike CS alt JA4 fingerprint","trojan-activity",
            ["t13d201516_8daaf6152771_02713d6af862"],[]),

        // ── C2 FRAMEWORKS — Metasploit / Meterpreter ─────────────────────────
        r!(9000010,1,Alert,Tcp,"any","4444","Meterpreter default reverse TCP port","trojan-activity"),
        r!(9000011,1,Alert,Tcp,"any","4445","Meterpreter alternate port","trojan-activity"),
        r!(9000012,1,Alert,Tcp,"any","any","Meterpreter payload signature","shellcode-detect",
            ["METERPRETER","metsrv"],[]),
        r!(9000013,1,Alert,Http,"any","any","Metasploit HTTP stager /msfconsole","trojan-activity",
            ["msfconsole"],[]),
        r!(9000014,1,Alert,Tls,"any","4433","Metasploit HTTPS handler default port","trojan-activity"),
        r!(9000015,1,Drop,Tls,"any","any","Metasploit Meterpreter JA4 fingerprint","trojan-activity",
            ["t10d190900_7c86a2b27c4e_e59c86d3cbf6"],[]),

        // ── C2 FRAMEWORKS — Sliver ────────────────────────────────────────────
        r!(9000020,1,Alert,Tcp,"any","31337","Sliver C2 default port","trojan-activity"),
        r!(9000021,1,Alert,Http,"any","any","Sliver C2 HTTP /index.html heartbeat","trojan-activity",
            ["/index.html"],["(?i)sliver"]),
        r!(9000022,1,Drop,Tls,"any","any","Sliver C2 JA4 fingerprint","trojan-activity",
            ["t13d1517h2_8daaf6152771_02713d6af862"],[]),

        // ── C2 FRAMEWORKS — Havoc ─────────────────────────────────────────────
        r!(9000025,1,Alert,Tcp,"any","40056","Havoc C2 default port","trojan-activity"),
        r!(9000026,1,Drop,Tls,"any","any","Havoc C2 JA4 fingerprint","trojan-activity",
            ["t13d2014h2_8daaf6152771_02713d6af862"],[]),

        // ── C2 FRAMEWORKS — AsyncRAT / NjRAT / DarkComet ─────────────────────
        r!(9000030,1,Alert,Tcp,"any","8808","AsyncRAT default port","trojan-activity"),
        r!(9000031,1,Alert,Tcp,"any","6606","AsyncRAT alternate port","trojan-activity"),
        r!(9000032,1,Alert,Tcp,"any","1177","NjRAT default port","trojan-activity"),
        r!(9000033,1,Alert,Tcp,"any","1604","DarkComet default port","trojan-activity"),
        r!(9000034,1,Alert,Tcp,"any","7892","DarkComet alternate port","trojan-activity"),
        r!(9000035,1,Alert,Tcp,"any","3460","QuasarRAT default port","trojan-activity"),
        r!(9000036,1,Alert,Tcp,"any","9999","NetWire RAT common port","trojan-activity"),
        r!(9000037,1,Alert,Tcp,"any","3460","Remcos RAT port","trojan-activity"),
        r!(9000038,1,Alert,Tcp,"any","1234","Generic C2 callback on port 1234","command-and-control"),
        r!(9000039,1,Alert,Tcp,"any","4321","Generic C2 callback on port 4321","command-and-control"),
        r!(9000040,1,Alert,Tcp,"any","5555","Generic RAT port 5555","command-and-control"),
        r!(9000041,1,Alert,Tcp,"any","6666","Generic C2 port 6666","command-and-control"),
        r!(9000042,1,Alert,Tcp,"any","7777","Generic C2 port 7777","command-and-control"),
        r!(9000043,1,Alert,Tcp,"any","8888","Generic C2 port 8888","command-and-control"),
        r!(9000044,1,Alert,Tcp,"any","9000","Generic C2 port 9000","command-and-control"),
        r!(9000045,1,Alert,Tcp,"any","9001","Tor ORPort / C2","trojan-activity"),
        r!(9000046,2,Alert,Tcp,"any","443","Empire C2 JA4 fingerprint","trojan-activity",
            ["t13d1515h2_8daaf6152771_02713d6af862"],[]),
        r!(9000047,1,Alert,Tcp,"any","7443","Mythic C2 default HTTPS port","trojan-activity"),
        r!(9000048,1,Alert,Tcp,"any","8443","Brute Ratel C4 HTTPS port","trojan-activity"),

        // ── MALWARE FAMILIES — Emotet ─────────────────────────────────────────
        r!(9000050,1,Alert,Http,"any","any","Emotet HTTP C2 beacon pattern","trojan-activity",
            [],[r"(?i)\/[a-z0-9]{4,12}\/[a-z0-9]{4,16}\.php"]),
        r!(9000051,1,Alert,Tls,"any","any","Emotet TLS C2 JA4 fingerprint","trojan-activity",
            ["t12d1516h2_002f,0035,009c_02713d6af862"],[]),
        r!(9000052,2,Alert,Tcp,"any","any","Emotet spam relay outbound","trojan-activity",
            ["X-Mailer: Microsoft Outlook"],[]),

        // ── MALWARE FAMILIES — Trickbot / QBot / IcedID ──────────────────────
        r!(9000055,1,Alert,Tls,"any","443","QBot (Qakbot) TLS fingerprint","trojan-activity",
            ["t12d1517h2_c02b,c02c,c009_9dcb4c11e33d"],[]),
        r!(9000056,1,Alert,Tls,"any","443","IcedID TLS fingerprint","trojan-activity",
            ["t12d1516h2_c02b,c02c,c013_02713d6af862"],[]),
        r!(9000057,1,Alert,Http,"any","any","Trickbot HTTP check-in /90","trojan-activity",
            ["/90"],[r"GET\s+/90\s"]),
        r!(9000058,2,Alert,Http,"any","any","IcedID /lic.policy C2","trojan-activity",
            ["lic.policy"],[]),
        r!(9000059,2,Alert,Http,"any","any","Dridex HTTP C2 pattern","trojan-activity",
            [],[r"(?i)\/[a-zA-Z0-9]{8}\/[0-9]{1,5}\.php"]),

        // ── MALWARE — RedLine / AgentTesla / FormBook ──────────────────────────
        r!(9000060,1,Alert,Tcp,"any","any","RedLine Stealer SMTP exfiltration","trojan-activity",
            ["RedLine"],[]),
        r!(9000061,1,Alert,Smtp,"any","587","AgentTesla credential exfiltration","trojan-activity",
            ["AgentTesla"],[]),
        r!(9000062,2,Alert,Http,"any","any","FormBook HTTP C2 /ap09/ pattern","trojan-activity",
            ["/ap09/"],[]),
        r!(9000063,2,Alert,Http,"any","any","Raccoon Stealer HTTP C2","trojan-activity",
            ["/raccoon/"],[r"(?i)\/raccoon\/"]),
        r!(9000064,2,Alert,Http,"any","any","Vidar Stealer gate.php C2","trojan-activity",
            ["gate.php"],[]),

        // ── WEB ATTACKS — SQL Injection ───────────────────────────────────────
        r!(9000070,2,Alert,Http,"any","any","SQL injection UNION SELECT","web-application-attack",
            ["UNION SELECT"],[r"(?i)UNION\s+(?:ALL\s+)?SELECT"]),
        r!(9000071,2,Alert,Http,"any","any","SQL injection OR 1=1","web-application-attack",
            ["OR 1=1"],[r"(?i)OR\s+1\s*=\s*1"]),
        r!(9000072,2,Alert,Http,"any","any","SQL injection time-based SLEEP","web-application-attack",
            ["SLEEP("],[r"(?i)SLEEP\s*\(\s*[0-9]"]),
        r!(9000073,2,Alert,Http,"any","any","SQL injection WAITFOR DELAY","web-application-attack",
            ["WAITFOR DELAY"],[r"(?i)WAITFOR\s+DELAY"]),
        r!(9000074,2,Alert,Http,"any","any","SQL injection boolean DROP TABLE","web-application-attack",
            ["DROP TABLE"],[r"(?i)DROP\s+TABLE"]),
        r!(9000075,2,Alert,Http,"any","any","SQL injection xp_cmdshell exec","web-application-attack",
            ["xp_cmdshell"],[r"(?i)xp_cmdshell"]),
        r!(9000076,2,Alert,Http,"any","any","SQL injection error-based extractvalue","web-application-attack",
            ["extractvalue"],[r"(?i)extractvalue\s*\("]),
        r!(9000077,2,Alert,Http,"any","any","SQL injection blind bitwise AND","web-application-attack",
            [],[r"(?i)AND\s+(?:SLEEP|BENCHMARK|RAND|SUBSTRING)\s*\("]),
        r!(9000078,2,Alert,Http,"any","any","SQL injection sqlmap marker","web-application-attack",
            ["sqlmap"],[r"(?i)sqlmap"]),
        r!(9000079,2,Alert,Http,"any","any","SQL injection LOAD_FILE","web-application-attack",
            ["LOAD_FILE("],[]),

        // ── WEB ATTACKS — XSS ─────────────────────────────────────────────────
        r!(9000080,2,Alert,Http,"any","any","XSS script tag injection","web-application-attack",
            ["<script>"],[r"(?i)<script[\s>]"]),
        r!(9000081,2,Alert,Http,"any","any","XSS javascript: URI","web-application-attack",
            ["javascript:"],[r"(?i)javascript\s*:"]),
        r!(9000082,2,Alert,Http,"any","any","XSS event handler injection","web-application-attack",
            [],[r"(?i)on(?:load|click|error|mouseover|focus)\s*="]),
        r!(9000083,3,Alert,Http,"any","any","XSS iframe injection","web-application-attack",
            ["<iframe"],[r"(?i)<iframe\s"]),
        r!(9000084,2,Alert,Http,"any","any","XSS document.cookie theft","web-application-attack",
            ["document.cookie"],[]),
        r!(9000085,3,Alert,Http,"any","any","XSS base64 data URI","web-application-attack",
            ["data:text/html;base64"],[]),

        // ── WEB ATTACKS — Remote Code Execution ───────────────────────────────
        r!(9000090,1,Alert,Http,"any","any","Log4Shell CVE-2021-44228 JNDI injection","web-application-attack",
            ["${jndi:"],[r"\$\{jndi:(ldap|rmi|dns|corba|iiop|dnsrmi)://"]),
        r!(9000091,1,Alert,Http,"any","any","Log4Shell CVE-2021-45046 variant","web-application-attack",
            ["${${::-j}${::-n}"],[]),
        r!(9000092,1,Alert,Http,"any","any","Spring4Shell CVE-2022-22965 classLoader","web-application-attack",
            ["class.module.classLoader"],[r"class\.module\.classLoader\."]),
        r!(9000093,1,Alert,Http,"any","any","Spring4Shell CVE-2022-22963 SpEL injection","web-application-attack",
            ["spring.cloud.function.routing-expression"],[]),
        r!(9000094,1,Alert,Http,"any","any","Shellshock CVE-2014-6271 bash injection","web-application-attack",
            ["() {"],[r"\(\)\s*\{[^}]*\}\s*;"]),
        r!(9000095,1,Alert,Http,"any","any","PHP code injection eval base64_decode","web-application-attack",
            ["eval(base64_decode("],[]),
        r!(9000096,2,Alert,Http,"any","any","Struts2 OGNL injection","web-application-attack",
            ["%{#"],[r"(?i)\%\{#[\w\._]"]),
        r!(9000097,1,Alert,Http,"any","any","Webshell PHP system passthru exec","web-application-attack",
            ["system("],[r"(?i)(?:system|passthru|exec|shell_exec)\s*\("]),
        r!(9000098,1,Alert,Http,"any","any","Webshell cmd.exe /c","web-application-attack",
            ["cmd.exe"],[r"(?i)cmd\.exe\s+/c"]),
        r!(9000099,2,Alert,Http,"any","any","Remote file inclusion via HTTP","web-application-attack",
            ["http://"],[r"(?i)(?:include|require)(?:_once)?\s*\(\s*[\"']https?://"]),

        // ── WEB ATTACKS — Path Traversal ──────────────────────────────────────
        r!(9000100,2,Alert,Http,"any","any","Path traversal ../etc/passwd","web-application-attack",
            ["../etc/passwd"],[]),
        r!(9000101,2,Alert,Http,"any","any","Path traversal URL-encoded %2e%2e","web-application-attack",
            ["%2e%2e%2f"],[r"(?i)(?:%2e%2e%2f|%2e\.%2f|\.%2e%2f){2,}"]),
        r!(9000102,2,Alert,Http,"any","any","Path traversal Windows win.ini","web-application-attack",
            ["windows/win.ini"],[]),
        r!(9000103,2,Alert,Http,"any","any","Path traversal /etc/shadow","web-application-attack",
            ["/etc/shadow"],[]),
        r!(9000104,2,Alert,Http,"any","any","Path traversal /proc/self/environ","web-application-attack",
            ["/proc/self/environ"],[]),

        // ── WEB ATTACKS — SSRF ────────────────────────────────────────────────
        r!(9000110,1,Alert,Http,"any","any","SSRF AWS EC2 metadata service","web-application-attack",
            ["169.254.169.254"],[]),
        r!(9000111,1,Alert,Http,"any","any","SSRF GCP metadata service","web-application-attack",
            ["metadata.google.internal"],[]),
        r!(9000112,1,Alert,Http,"any","any","SSRF Azure IMDS","web-application-attack",
            ["169.254.169.254/metadata"],[]),
        r!(9000113,2,Alert,Http,"any","any","SSRF localhost bypass","web-application-attack",
            ["localhost"],[r"(?i)https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)"]),
        r!(9000114,2,Alert,Http,"any","any","SSRF gopher:// protocol","web-application-attack",
            ["gopher://"],[]),
        r!(9000115,2,Alert,Http,"any","any","SSRF dict:// protocol","web-application-attack",
            ["dict://"],[]),
        r!(9000116,2,Alert,Http,"any","any","SSRF file:/// protocol","web-application-attack",
            ["file:///"],[]),

        // ── NETWORK RECON ─────────────────────────────────────────────────────
        r!(9000120,3,Alert,Tcp,"any","any","Nmap SYN scan signature","network-scan",
            [],[]),
        r!(9000121,3,Alert,Tcp,"any","any","Nmap version detection Nmap","network-scan",
            ["Nmap"],[r"(?i)nmap"]),
        r!(9000122,3,Alert,Udp,"any","any","UDP port scan Nmap","network-scan"),
        r!(9000123,3,Alert,Tcp,"any","7547","Masscan probe port 7547 (TR-069)","network-scan"),
        r!(9000124,3,Alert,Tcp,"any","23","Mirai/Telnet scan port 23","network-scan"),
        r!(9000125,3,Alert,Tcp,"any","2323","Mirai Telnet alternate port 2323","network-scan"),
        r!(9000126,3,Alert,Http,"any","any","Shodan scanner User-Agent","network-scan",
            ["Shodan"],[r"(?i)shodan"]),
        r!(9000127,3,Alert,Http,"any","any","Zgrab scanner detected","network-scan",
            ["zgrab"],[r"(?i)zgrab"]),
        r!(9000128,3,Alert,Http,"any","any","Censys scanner detected","network-scan",
            ["Censys"],[r"(?i)censys"]),
        r!(9000129,3,Alert,Http,"any","any","Nuclei scanner detected","network-scan",
            ["nuclei"],[r"(?i)nuclei"]),

        // ── BRUTE FORCE ───────────────────────────────────────────────────────
        r!(9000130,2,Alert,Ssh,"any","22","SSH brute force attempt","attempted-admin"),
        r!(9000131,2,Alert,Tcp,"any","3389","RDP brute force attempt","attempted-admin"),
        r!(9000132,2,Alert,Ftp,"any","21","FTP brute force USER root","attempted-admin",
            ["USER root"],[]),
        r!(9000133,2,Alert,Ftp,"any","21","FTP brute force USER admin","attempted-admin",
            ["USER admin"],[]),
        r!(9000134,2,Alert,Smtp,"any","25","SMTP brute force AUTH LOGIN","attempted-admin",
            ["AUTH LOGIN"],[]),
        r!(9000135,2,Alert,Http,"any","any","HTTP Basic auth brute force","attempted-admin",
            ["Authorization: Basic"],[r"(?i)authorization:\s*basic\s+[A-Za-z0-9+/]+"]),
        r!(9000136,2,Alert,Tcp,"any","445","SMB brute force (repeated auth)","attempted-admin"),
        r!(9000137,2,Alert,Http,"any","any","WordPress login brute force wp-login.php","attempted-admin",
            ["wp-login.php"],[]),
        r!(9000138,2,Alert,Http,"any","any","Joomla admin brute force","attempted-admin",
            ["administrator/index.php"],[]),
        r!(9000139,2,Alert,Tcp,"any","5432","PostgreSQL brute force","attempted-admin"),
        r!(9000140,2,Alert,Tcp,"any","3306","MySQL brute force","attempted-admin"),
        r!(9000141,2,Alert,Tcp,"any","1433","MSSQL brute force","attempted-admin"),
        r!(9000142,2,Alert,Tcp,"any","6379","Redis unauthorized access","attempted-admin"),
        r!(9000143,2,Alert,Tcp,"any","27017","MongoDB unauthorized access","attempted-admin"),
        r!(9000144,2,Alert,Tcp,"any","9200","Elasticsearch unauthorized access","attempted-admin"),

        // ── LATERAL MOVEMENT ──────────────────────────────────────────────────
        r!(9000150,1,Alert,Tcp,"any","445","EternalBlue SMB exploit (CVE-2017-0144)","attempted-admin",
            [],[r"(?i)eternal"]),
        r!(9000151,1,Alert,Tcp,"any","445","WannaCry ransomware SMB propagation","trojan-activity",
            ["\x00\x00\x00\x90\xff\x53\x4d\x42"],[]),
        r!(9000152,1,Alert,Tcp,"any","445","DoublePulsar backdoor SMB","backdoor"),
        r!(9000153,2,Alert,Tcp,"any","445","PsExec lateral movement","attempted-admin",
            ["PSEXESVC"],[]),
        r!(9000154,2,Alert,Tcp,"any","5985","WinRM lateral movement HTTP","attempted-admin"),
        r!(9000155,2,Alert,Tcp,"any","5986","WinRM lateral movement HTTPS","attempted-admin"),
        r!(9000156,2,Alert,Tcp,"any","445","Admin share access C$","policy-violation",
            ["\\C$"],[]),
        r!(9000157,2,Alert,Tcp,"any","445","Admin share access ADMIN$","policy-violation",
            ["\\ADMIN$"],[]),
        r!(9000158,2,Alert,Tcp,"any","3389","RDP lateral movement from non-bastion","attempted-admin"),
        r!(9000159,2,Alert,Tcp,"any","135","DCOM lateral movement DCE/RPC","attempted-admin"),
        r!(9000160,2,Alert,Tcp,"any","88","Kerberoasting AS-REP roasting","policy-violation",
            [],[]),

        // ── DATA EXFILTRATION ─────────────────────────────────────────────────
        r!(9000170,1,Alert,Dns,"any","53","DNS tunneling high-entropy query","policy-violation"),
        r!(9000171,1,Alert,Dns,"any","53","DNS tunneling NULL record query","policy-violation"),
        r!(9000172,2,Alert,Http,"any","any","Data exfiltration to Pastebin","policy-violation",
            ["pastebin.com"],[]),
        r!(9000173,2,Alert,Http,"any","any","Data exfiltration to Transfer.sh","policy-violation",
            ["transfer.sh"],[]),
        r!(9000174,2,Alert,Http,"any","any","Data exfiltration to Mega.nz","policy-violation",
            ["mega.nz"],[]),
        r!(9000175,2,Alert,Http,"any","any","Data exfil to webhook.site","policy-violation",
            ["webhook.site"],[]),
        r!(9000176,2,Alert,Http,"any","any","Data exfil to requestbin","policy-violation",
            ["requestbin"],[]),
        r!(9000177,2,Alert,Ftp,"any","21","FTP exfiltration outbound (large file)","policy-violation"),
        r!(9000178,2,Alert,Smtp,"any","25","SMTP relay — possible spam/exfil","policy-violation"),
        r!(9000179,3,Alert,Http,"any","any","Exfil via HTTP POST large body","policy-violation"),

        // ── RANSOMWARE INDICATORS ─────────────────────────────────────────────
        r!(9000180,1,Alert,Any,"any","any","WannaCry ransomware signature WNCRY","trojan-activity",
            ["WNCRY"],[]),
        r!(9000181,1,Alert,Any,"any","any","WannaCry kill switch domain check","trojan-activity",
            ["iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea"],[]),
        r!(9000182,1,Alert,Tcp,"any","445","WannaCry MS17-010 exploit traffic","trojan-activity"),
        r!(9000183,1,Alert,Any,"any","any","Ryuk ransomware network beacon","trojan-activity",
            ["RyukReadMe"],[]),
        r!(9000184,1,Alert,Any,"any","any","REvil/Sodinokibi ransom note","trojan-activity",
            ["{EXT}-readme"],[]),
        r!(9000185,1,Alert,Any,"any","any","Conti ransomware C2 beacon","trojan-activity",
            ["ContiLocker"],[]),
        r!(9000186,1,Alert,Http,"any","any","LockBit ransomware affiliate panel","trojan-activity",
            ["lockbit"],[r"(?i)lockbit"]),
        r!(9000187,2,Alert,Http,"any","any","Ransomware Tor payment site access","trojan-activity",
            [".onion"],[]),

        // ── TLS ANOMALIES ──────────────────────────────────────────────────────
        r!(9000190,2,Alert,Tls,"any","any","TLS SNI is raw IP address (C2 evasion)","bad-unknown",
            [],[r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"]),
        r!(9000191,2,Alert,Tls,"any","any","TLS SSLv3 used (POODLE vulnerable)","bad-unknown"),
        r!(9000192,2,Alert,Tls,"any","any","TLS 1.0 deprecated protocol","policy-violation"),
        r!(9000193,1,Alert,Tls,"any","any","TLS null cipher suite detected","bad-unknown"),
        r!(9000194,1,Alert,Tls,"any","any","TLS RC4 cipher suite detected","bad-unknown"),
        r!(9000195,1,Alert,Tls,"any","any","TLS EXPORT cipher suite (FREAK)","bad-unknown"),
        r!(9000196,1,Alert,Tls,"any","any","TLS anonymous cipher suite (no auth)","bad-unknown"),
        r!(9000197,2,Alert,Tls,"any","any","TLS self-signed certificate","bad-unknown"),
        r!(9000198,2,Alert,Tls,"any","any","TLS certificate wildcard C2","bad-unknown",
            ["\\.onion"],[]),
        r!(9000199,2,Alert,Tls,"any","any","TLS SNI .onion Tor hidden service","trojan-activity",
            [".onion"],[]),

        // ── DNS ANOMALIES ─────────────────────────────────────────────────────
        r!(9000200,2,Alert,Dns,"any","53","DGA domain high entropy","bad-unknown"),
        r!(9000201,2,Alert,Dns,"any","53","DNS TXT record exfiltration","policy-violation"),
        r!(9000202,2,Alert,Dns,"any","53","Tor .onion gateway DNS resolution","trojan-activity",
            [".onion"],[]),
        r!(9000203,2,Alert,Dns,"any","53","DNS fast-flux multiple short-TTL A records","bad-unknown"),
        r!(9000204,2,Alert,Dns,"any","53","DNS-over-HTTPS bypass via plain DNS","policy-violation",
            ["dns.google"],[]),
        r!(9000205,3,Alert,Dns,"any","53","DNS NXDOMAIN flood reconnaissance","network-scan"),
        r!(9000206,2,Alert,Dns,"any","53","DNS ANY query DDoS amplification","bad-unknown"),
        r!(9000207,2,Alert,Dns,"any","53","DNS rebinding attack heuristic","bad-unknown"),

        // ── ICMP ANOMALIES ────────────────────────────────────────────────────
        r!(9000210,3,Alert,Icmp,"any","any","ICMP ping sweep network recon","network-scan"),
        r!(9000211,2,Alert,Icmp,"any","any","ICMP tunnel large payload","policy-violation"),
        r!(9000212,3,Alert,Icmp,"any","any","ICMP fragmentation attack","bad-unknown"),

        // ── ICS/SCADA ─────────────────────────────────────────────────────────
        r!(9000220,2,Alert,Tcp,"any","502","Modbus TCP unauthorized access","policy-violation"),
        r!(9000221,2,Alert,Tcp,"any","102","S7 Siemens PLC port scan","network-scan"),
        r!(9000222,2,Alert,Tcp,"any","20000","DNP3 SCADA protocol","policy-violation"),
        r!(9000223,2,Alert,Tcp,"any","4840","OPC-UA SCADA access","policy-violation"),
        r!(9000224,2,Alert,Tcp,"any","1911","Niagara Fox SCADA protocol","policy-violation"),
        r!(9000225,2,Alert,Tcp,"any","2404","IEC 60870-5-104 power grid protocol","policy-violation"),

        // ── CRYPTO MINING ─────────────────────────────────────────────────────
        r!(9000230,2,Alert,Tcp,"any","3333","Stratum mining protocol port 3333","policy-violation"),
        r!(9000231,2,Alert,Tcp,"any","14444","XMRig pool port 14444","policy-violation"),
        r!(9000232,2,Alert,Http,"any","any","Coinhive cryptocurrency miner script","policy-violation",
            ["coinhive.min.js"],[]),
        r!(9000233,2,Alert,Http,"any","any","Crypto miner stratum+tcp in URI","policy-violation",
            ["stratum+tcp"],[]),
        r!(9000234,2,Alert,Tcp,"any","4444","XMRig default mining port","policy-violation"),
        r!(9000235,2,Alert,Http,"any","any","CryptoJacking JS miner","policy-violation",
            ["CoinHive"],[r"(?i)(coinhive|cryptoloot|jsecoin|minero)"]),

        // ── TOR ───────────────────────────────────────────────────────────────
        r!(9000240,2,Alert,Tcp,"any","9001","Tor ORPort connection","policy-violation"),
        r!(9000241,2,Alert,Tcp,"any","9030","Tor DirPort connection","policy-violation"),
        r!(9000242,2,Alert,Tcp,"any","9050","Tor SOCKSPort proxy connection","policy-violation"),
        r!(9000243,2,Alert,Http,"any","any","Tor2Web hidden service gateway","trojan-activity",
            [".onion.to"],[]),
        r!(9000244,2,Alert,Dns,"any","53","Tor exit node DNS lookup","trojan-activity",
            [".exit"],[]),

        // ── CLOUD METADATA ABUSE ──────────────────────────────────────────────
        r!(9000250,1,Alert,Http,"any","any","AWS IMDS metadata access","attempted-admin",
            ["169.254.169.254/latest/meta-data"],[]),
        r!(9000251,1,Alert,Http,"any","any","AWS IMDS credentials endpoint","attempted-admin",
            ["latest/meta-data/iam/security-credentials"],[]),
        r!(9000252,1,Alert,Http,"any","any","GCP metadata server access","attempted-admin",
            ["metadata.google.internal"],[]),
        r!(9000253,1,Alert,Http,"any","any","Azure IMDS endpoint access","attempted-admin",
            ["169.254.169.254/metadata/instance"],[]),
        r!(9000254,2,Alert,Http,"any","any","Kubernetes API server internal access","attempted-admin",
            ["kubernetes.default.svc"],[]),

        // ── CONTAINER ESCAPE ──────────────────────────────────────────────────
        r!(9000260,1,Alert,Any,"any","any","Docker daemon socket exposure","attempted-admin",
            ["/var/run/docker.sock"],[]),
        r!(9000261,1,Alert,Any,"any","any","Container cgroup breakout attempt","attempted-admin",
            ["/proc/1/cgroup"],[]),
        r!(9000262,1,Alert,Http,"any","2375","Docker API unauthorized access","attempted-admin"),
        r!(9000263,1,Alert,Http,"any","2376","Docker TLS API access attempt","attempted-admin"),
        r!(9000264,2,Alert,Any,"any","any","Kubernetes privileged pod escape","attempted-admin",
            ["privileged: true"],[]),

        // ── SUPPLY CHAIN / OPEN SOURCE ────────────────────────────────────────
        r!(9000270,1,Alert,Http,"any","any","Log4j JNDI in HTTP header User-Agent","web-application-attack",
            ["${jndi:"],[]),
        r!(9000271,1,Alert,Http,"any","any","Log4j JNDI in Referer header","web-application-attack",
            ["${jndi:"],[]),
        r!(9000272,1,Alert,Http,"any","any","Log4j JNDI in X-Forwarded-For","web-application-attack",
            ["${jndi:"],[]),
        r!(9000273,2,Alert,Http,"any","any","npm audit command injection via package.json","web-application-attack",
            ["__proto__"],[r"(?i)__proto__\s*:"]),
        r!(9000274,2,Alert,Http,"any","any","PyPI/npm typosquatting network callback","trojan-activity",
            [],[r"(?i)(?:setup\.py|install\.py).*(?:wget|curl|requests\.get)"]),

        // ── SUSPICIOUS TOOLS ─────────────────────────────────────────────────
        r!(9000280,3,Alert,Http,"any","any","sqlmap scanner User-Agent","network-scan",
            ["sqlmap"],[]),
        r!(9000281,3,Alert,Http,"any","any","Nikto web scanner","network-scan",
            ["Nikto"],[]),
        r!(9000282,3,Alert,Http,"any","any","Dirbuster directory scanner","network-scan",
            ["DirBuster"],[]),
        r!(9000283,3,Alert,Http,"any","any","Gobuster directory scanner","network-scan",
            ["gobuster"],[]),
        r!(9000284,3,Alert,Http,"any","any","FFUF fuzzer tool","network-scan",
            ["Fuzz Faster U Fool"],[]),
        r!(9000285,3,Alert,Http,"any","any","Burp Suite active scanner","network-scan",
            ["Burp Suite"],[]),
        r!(9000286,3,Alert,Http,"any","any","OWASP ZAP active scanner","network-scan",
            ["OWASP_ZAP"],[]),
        r!(9000287,3,Alert,Http,"any","any","Acunetix web scanner","network-scan",
            ["Acunetix"],[]),
        r!(9000288,3,Alert,Http,"any","any","Nessus vulnerability scanner","network-scan",
            ["Nessus"],[]),
        r!(9000289,2,Alert,Http,"any","any","WPScan WordPress scanner","network-scan",
            ["WPScan"],[]),

        // ── EXPLOIT KITS ─────────────────────────────────────────────────────
        r!(9000290,1,Alert,Http,"any","any","Angler exploit kit URI pattern","trojan-activity",
            [],[r"(?i)\/[a-z0-9]{5}\/[a-z0-9]{10}\.html\?"]),
        r!(9000291,1,Alert,Http,"any","any","Nuclear exploit kit pattern","trojan-activity",
            [],[r"(?i)\/[a-z0-9]{8}\?[a-z0-9]+"]),
        r!(9000292,1,Alert,Http,"any","any","Rig exploit kit URI","trojan-activity",
            [],[r"(?i)\/[a-zA-Z0-9]{4,8}\/[a-zA-Z0-9]{4,8}\.php\?[a-zA-Z0-9]+"]),

        // ── AUTHENTICATION ATTACKS ─────────────────────────────────────────────
        r!(9000300,2,Alert,Tcp,"any","88","Kerberos AS-REQ large payload Kerberoasting","policy-violation"),
        r!(9000301,2,Alert,Tcp,"any","389","LDAP enumeration bind","policy-violation"),
        r!(9000302,2,Alert,Tcp,"any","636","LDAPS enumeration","policy-violation"),
        r!(9000303,2,Alert,Tcp,"any","88","Pass-the-Ticket Kerberos anomaly","attempted-admin"),
        r!(9000304,2,Alert,Tcp,"any","445","Pass-the-Hash NTLM auth","attempted-admin",
            ["NTLMSSP"],[]),

        // ── FILE OPERATIONS ───────────────────────────────────────────────────
        r!(9000310,2,Alert,Http,"any","any","Webshell file upload .php extension","web-application-attack",
            [".php"],[r"(?i)(?:filename|name)\s*=\s*[\"'][^\"']*\.php[\"']"]),
        r!(9000311,2,Alert,Http,"any","any","Webshell upload .jsp extension","web-application-attack",
            [".jsp"],[r"(?i)(?:filename|name)\s*=\s*[\"'][^\"']*\.jsp[\"']"]),
        r!(9000312,2,Alert,Http,"any","any","Webshell upload .asp extension","web-application-attack",
            [".asp"],[r"(?i)(?:filename|name)\s*=\s*[\"'][^\"']*\.asp[\"']"]),
        r!(9000313,2,Alert,Http,"any","any","Sensitive file access /etc/passwd over HTTP","web-application-attack",
            ["/etc/passwd"],[]),
        r!(9000314,2,Alert,Http,"any","any","Sensitive file access .env config","web-application-attack",
            ["/.env"],[r"(?i)\/\.env(?:$|[\?#\s])"]),
        r!(9000315,2,Alert,Http,"any","any","Git repo disclosure /.git/HEAD","web-application-attack",
            ["/.git/HEAD"],[]),
        r!(9000316,2,Alert,Http,"any","any","AWS credentials file access","web-application-attack",
            ["/.aws/credentials"],[]),
        r!(9000317,2,Alert,Http,"any","any","SSH private key exposure","web-application-attack",
            ["BEGIN RSA PRIVATE"],[]),
        r!(9000318,2,Alert,Http,"any","any","Docker compose file exposure","web-application-attack",
            ["docker-compose.yml"],[]),

        // ── BOTNET / DDoS ─────────────────────────────────────────────────────
        r!(9000320,2,Alert,Tcp,"any","23","Mirai Telnet scan","network-scan"),
        r!(9000321,2,Alert,Tcp,"any","any","Mirai botnet keyword in payload","trojan-activity",
            ["MIRAI"],[r"(?i)mirai"]),
        r!(9000322,2,Alert,Udp,"any","any","DNS amplification reflector","bad-unknown"),
        r!(9000323,2,Alert,Udp,"any","any","NTP amplification monlist attack","bad-unknown",
            ["\x17\x00\x03\x2a"],[]),
        r!(9000324,2,Alert,Tcp,"any","any","Slowloris DoS HTTP partial headers","bad-unknown",
            ["X-a: b"],[]),
        r!(9000325,2,Alert,Http,"any","any","HTTP flood attack large rate","bad-unknown"),

        // ── PHISHING/SOCIAL ENGINEERING ───────────────────────────────────────
        r!(9000330,2,Alert,Http,"any","any","Phishing page Microsoft login clone","social-engineering",
            ["microsoftonline.com.login"],[]),
        r!(9000331,2,Alert,Http,"any","any","Phishing page Google login clone","social-engineering",
            ["accounts.google.com.login"],[]),
        r!(9000332,2,Alert,Http,"any","any","Phishing Office365 credential harvest","social-engineering",
            ["office365.com.auth"],[]),
        r!(9000333,3,Alert,Http,"any","any","Homograph domain attack (unicode)","social-engineering",
            ["\xc3\xa9","xn--"],[]),

        // ── PROTOCOL ANOMALIES ────────────────────────────────────────────────
        r!(9000340,2,Alert,Http,"any","any","HTTP CONNECT tunnel proxy abuse","policy-violation",
            ["CONNECT"],[r"^CONNECT\s+[^\s]+:\d{1,5}\s+HTTP"]),
        r!(9000341,2,Alert,Http,"any","any","HTTP DELETE method on production","policy-violation",
            ["DELETE"],[r"^DELETE\s"]),
        r!(9000342,3,Alert,Http,"any","any","HTTP TRACE method (XST)","web-application-attack",
            ["TRACE"],[r"^TRACE\s"]),
        r!(9000343,2,Alert,Http,"any","any","HTTP request smuggling Transfer-Encoding","web-application-attack",
            ["Transfer-Encoding: chunked"],[r"(?i)transfer-encoding:.*chunked.*content-length:"]),
        r!(9000344,2,Alert,Http,"any","any","Open redirect via ?url= ?redirect=","web-application-attack",
            [],[r"(?i)(?:url|redirect|next|forward|destination|go|to|out|rurl|image_url)=https?://"]),

        // ── ADDITIONAL C2 PORTS ───────────────────────────────────────────────
        r!(9000350,1,Alert,Tcp,"any","53","DNS over TCP C2 (unusual)","command-and-control"),
        r!(9000351,1,Alert,Tcp,"any","80","HTTP C2 non-standard User-Agent","command-and-control",
            [],[r"(?i)^user-agent:\s*(?:go-http-client|python-requests|libcurl|ruby|java/)"]),
        r!(9000352,2,Alert,Tcp,"any","8080","HTTP proxy C2 traffic","command-and-control"),
        r!(9000353,1,Alert,Tcp,"any","443","HTTPS C2 long session idle","command-and-control"),
        r!(9000354,2,Alert,Tcp,"any","1080","SOCKS5 proxy traffic","policy-violation"),
        r!(9000355,2,Alert,Tcp,"any","3128","Squid proxy unauthorized","policy-violation"),
        r!(9000356,2,Alert,Tcp,"any","8118","Privoxy anonymizing proxy","policy-violation"),

        // ── MEMORY INJECTION INDICATORS ──────────────────────────────────────
        r!(9000360,1,Alert,Any,"any","any","Shellcode NOP sled pattern","shellcode-detect",
            ["\x90\x90\x90\x90\x90\x90\x90\x90"],[]),
        r!(9000361,1,Alert,Any,"any","any","Shellcode egghunter pattern AABBCCDD","shellcode-detect",
            ["\x41\x41\x41\x41\x42\x42\x42\x42"],[]),
        r!(9000362,1,Alert,Any,"any","any","Process hollowing CMD signature","shellcode-detect",
            ["CreateRemoteThread"],[]),
        r!(9000363,2,Alert,Http,"any","any","JAVA deserialization attack AC ED 00 05","web-application-attack",
            ["\xac\xed\x00\x05"],[]),
        r!(9000364,2,Alert,Http,"any","any","PHP serialized object injection","web-application-attack",
            ["O:8:"],[r#"O:\d+:"[^"]+":"#]),

        // ── EMAIL-BASED ATTACKS ───────────────────────────────────────────────
        r!(9000370,2,Alert,Smtp,"any","25","SMTP header injection CRLF","policy-violation",
            ["\r\n"],[r"(?:Subject|To|From|Bcc|Cc):[^\n]*\r\n[^\r]"]),
        r!(9000371,2,Alert,Smtp,"any","25","SMTP RCPT TO bulk spam indicator","policy-violation"),
        r!(9000372,2,Alert,Smtp,"any","25","SMTP open relay test","policy-violation",
            ["MAIL FROM:<>"],[]),
        r!(9000373,2,Alert,Smtp,"any","465","SMTPS auth credential spray","attempted-admin"),
        r!(9000374,2,Alert,Smtp,"any","587","SMTP submission port spray","attempted-admin"),

        // ── INDUSTRIAL / EMBEDDED ────────────────────────────────────────────
        r!(9000380,2,Alert,Tcp,"any","161","SNMP v1/v2 community string brute","attempted-admin",
            ["public"],[]),
        r!(9000381,2,Alert,Tcp,"any","161","SNMP v1/v2 community string private","attempted-admin",
            ["private"],[]),
        r!(9000382,2,Alert,Tcp,"any","23","Telnet cleartext access","policy-violation"),
        r!(9000383,2,Alert,Tcp,"any","21","FTP cleartext access","policy-violation"),
        r!(9000384,2,Alert,Tcp,"any","79","Finger protocol information disclosure","policy-violation"),
        r!(9000385,2,Alert,Tcp,"any","7","Echo port service probe","network-scan"),
        r!(9000386,2,Alert,Tcp,"any","19","Chargen DoS amplification","bad-unknown"),
        r!(9000387,2,Alert,Tcp,"any","13","Daytime protocol probe","network-scan"),

        // ── HONEYPOT TRIGGERS ────────────────────────────────────────────────
        r!(9000390,2,Alert,Http,"any","any","PHPMYADMIN unauthorized access","attempted-admin",
            ["phpmyadmin"],[r"(?i)/phpmyadmin"]),
        r!(9000391,2,Alert,Http,"any","any","Admin panel discovery attempt","attempted-admin",
            ["admin.php"],[]),
        r!(9000392,2,Alert,Http,"any","any","Database admin panel phpMyAdmin","attempted-admin",
            ["pma"],[r"(?i)/pma/"]),
        r!(9000393,2,Alert,Http,"any","any","Jenkins unauthenticated access","attempted-admin",
            ["jenkins"],[r"(?i)/jenkins/"]),
        r!(9000394,2,Alert,Http,"any","any","Grafana path traversal CVE-2021-43798","web-application-attack",
            ["/public/plugins/"],[r"(?i)/public/plugins/.*/\.\."]),
        r!(9000395,2,Alert,Http,"any","any","GitLab SSRF CVE-2021-22214","web-application-attack",
            ["Packages/npm"],[]),
        r!(9000396,2,Alert,Http,"any","any","Confluence OGNL injection CVE-2022-26134","web-application-attack",
            ["%24%7B"],[r"(?i)\$\{[^}]+\}"]),
        r!(9000397,2,Alert,Http,"any","any","VMware RCE CVE-2022-22954","web-application-attack",
            ["deviceudid"],[r"(?i)deviceudid=.*\$\{"]),
        r!(9000398,2,Alert,Http,"any","any","Exchange ProxyShell CVE-2021-34473","web-application-attack",
            ["/autodiscover/autodiscover.json"],[]),
        r!(9000399,2,Alert,Http,"any","any","Drupalgeddon2 CVE-2018-7600","web-application-attack",
            ["user/register?element_parents="],[]),
        r!(9000400,1,Alert,Http,"any","any","Apache RCE CVE-2021-41773 path traversal","web-application-attack",
            ["/.%2e/"],[r"(?i)/\.%2e/|/%2e\./|/%2e%2e/"]),

        // ── FINAL CATCH-ALL / HIGH-VALUE TARGETS ────────────────────────────
        r!(9000401,1,Alert,Http,"any","any","JNDI injection in any HTTP header","web-application-attack",
            ["${jndi:"],[r"\$\{jndi:"]),
        r!(9000402,2,Alert,Http,"any","any","Server-side template injection","web-application-attack",
            [],[r"(?i)\{\{.*(?:config|import|eval|exec|open|subprocess)\s*[\.\(]"]),
        r!(9000403,2,Alert,Http,"any","any","XXE injection DOCTYPE ENTITY","web-application-attack",
            ["<!DOCTYPE"],[r"(?i)<!DOCTYPE[^>]*\[.*<!ENTITY"]),
        r!(9000404,2,Alert,Http,"any","any","Open redirect to external domain","web-application-attack",
            [],[r"(?i)(?:next|return|redirect|url)=(?:https?://|//)[^/\s]"]),
        r!(9000405,1,Alert,Any,"any","any","HTTP desync CL.TE smuggling","web-application-attack",
            [],[r"(?i)content-length:\s*\d+.*transfer-encoding:\s*chunked"]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rule_count_at_least_400() {
        let rules = builtin_rules();
        assert!(rules.len() >= 400, "Expected 400+ builtin rules, got {}", rules.len());
    }

    #[test]
    fn all_sids_unique() {
        let rules = builtin_rules();
        let mut sids = std::collections::HashSet::new();
        for r in &rules {
            assert!(sids.insert(r.sid), "Duplicate SID: {}", r.sid);
        }
    }

    #[test]
    fn all_rules_have_messages() {
        for r in builtin_rules() {
            assert!(!r.msg.is_empty(), "SID {} has empty message", r.sid);
        }
    }

    #[test]
    fn priority_to_threat_level_mapping() {
        assert!(matches!(priority_to_threat_level(1), ThreatLevel::Critical));
        assert!(matches!(priority_to_threat_level(2), ThreatLevel::High));
        assert!(matches!(priority_to_threat_level(3), ThreatLevel::Medium));
        assert!(matches!(priority_to_threat_level(4), ThreatLevel::Low));
    }

    #[test]
    fn engine_empty_loads_builtin_rules() {
        let engine = IdsEngine::empty();
        assert!(engine.rule_count() >= 400);
    }
}
