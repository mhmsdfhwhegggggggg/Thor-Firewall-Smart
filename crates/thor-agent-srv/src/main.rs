use sysinfo::{System, ProcessExt, SystemExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use chrono::Utc;
use tracing::{info, warn, error};

// --- CORE STRUCTURED CONFIGS & THRESHOLDS ---
const METRIC_PERIOD_INTERVAL_SECS: u64 = 5;
const PROCESS_CPU_THREAT_THRESHOLD: f32 = 90.0;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HostSystemIncident {
    pub anomaly_id: String,
    pub timestamp: String,
    pub host_name: String,
    pub process_id: u32,
    pub process_name: String,
    pub parent_process_id: Option<u32>,
    pub cmd_line: String,
    pub alert_category: String,
    pub severity: String, // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    pub threat_score: f32,
}

// --- SEC RULES / SIGMA-LIKE PATTERN MATCHING ---
pub struct SignatureRule {
    pub process_name_pattern: &'static str,
    pub cmdline_must_match: Option<&'static str>,
    pub alert_cause: &'static str,
    pub severity: &'static str,
}

const SIGMA_RULES: &[SignatureRule] = &[
    SignatureRule {
        process_name_pattern: "xmrig",
        cmdline_must_match: None,
        alert_cause: "Cryptomining agent invocation",
        severity: "HIGH",
    },
    SignatureRule {
        process_name_pattern: "nc",
        cmdline_must_match: Some("-e"),
        alert_cause: "Reverse shell execution attempt",
        severity: "CRITICAL",
    },
    SignatureRule {
        process_name_pattern: "bash",
        cmdline_must_match: Some("/etc/passwd"),
        alert_cause: "Sensitive file extraction via shell cmd",
        severity: "CRITICAL",
    },
    SignatureRule {
        process_name_pattern: "powershell",
        cmdline_must_match: Some("-nop -w hidden -c"),
        alert_cause: "Obfuscated PowerShell code execution",
        severity: "HIGH",
    },
    SignatureRule {
        process_name_pattern: "svshost",
        cmdline_must_match: None,
        alert_cause: "Malicious masquerading variant of svchost process name",
        severity: "HIGH",
    },
];

// --- CORE CONTROLLER ENGINE ---
pub struct ServerEdrAgent {
    pub system_handle: System,
    pub host_name: String,
}

impl ServerEdrAgent {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        let host_name = sys.host_name().unwrap_or_else(|| "ThorServerNode".to_string());
        
        Self {
            system_handle: sys,
            host_name,
        }
    }

    pub fn scan_processes(&mut self) -> Vec<HostSystemIncident> {
        let mut incidents = Vec::new();
        self.system_handle.refresh_processes();

        let processes = self.system_handle.processes();
        info!("🔍 Thor Server Agent EDR: Scanning {} active system processes...", processes.len());

        for (pid, process) in processes {
            let proc_name = process.name();
            let cmd_line = process.cmd().join(" ");
            let cpu_usage = process.cpu_usage();

            // 1. CPU Abuse Check (Potential crypto hijack or infinite-loop exploits)
            if cpu_usage > PROCESS_CPU_THREAT_THRESHOLD {
                warn!("⚠️ CPU Threat: Process {} [PID: {}] consuming extreme resources: {:.2}%", proc_name, pid, cpu_usage);
                incidents.push(HostSystemIncident {
                    anomaly_id: format!("CPU_HIJACK_{}_{}", pid, Utc::now().timestamp()),
                    timestamp: Utc::now().to_rfc3339(),
                    host_name: self.host_name.clone(),
                    process_id: pid.as_u32(),
                    process_name: proc_name.to_string(),
                    parent_process_id: process.parent().map(|p| p.as_u32()),
                    cmd_line: cmd_line.clone(),
                    alert_category: "CPU Resource Exhaustion Overload (Potential Hijack)".to_string(),
                    severity: "MEDIUM".to_string(),
                    threat_score: 0.65,
                });
            }

            // 2. Behavioral Sigma Rule Pattern Mapping
            for rule in SIGMA_RULES {
                let proc_match = proc_name.to_lowercase().contains(&rule.process_name_pattern.to_lowercase());
                
                let cmd_match = if let Some(must_match) = rule.cmdline_must_match {
                    cmd_line.to_lowercase().contains(&must_match.to_lowercase())
                } else {
                    true
                };

                if proc_match && cmd_match {
                    warn!("‼️ CRITICAL SEC INCIDENT: [Rule match] Process {} [PID: {}] triggered rule: {}. CmdLine: {}", proc_name, pid, rule.alert_cause, cmd_line);
                    
                    incidents.push(HostSystemIncident {
                        anomaly_id: format!("SIGMA_MATCH_{}_{}", pid, Utc::now().timestamp()),
                        timestamp: Utc::now().to_rfc3339(),
                        host_name: self.host_name.clone(),
                        process_id: pid.as_u32(),
                        process_name: proc_name.to_string(),
                        parent_process_id: process.parent().map(|p| p.as_u32()),
                        cmd_line: cmd_line.clone(),
                        alert_category: rule.alert_cause.to_string(),
                        severity: rule.severity.to_string(),
                        threat_score: match rule.severity {
                            "CRITICAL" => 0.99,
                            "HIGH" => 0.85,
                            _ => 0.50,
                        },
                    });
                }
            }
        }

        incidents
    }
}

// --- MAIN THREAD LOOP ---
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    info!("🏛️ Booting Thor Server Host EDR Daemon (Security Monitoring Level)...");

    let mut edr = ServerEdrAgent::new();
    info!("✅ Thor Server Daemon bound to node: [{}] -- System Monitor initialized.", edr.host_name);

    // Continuous real-time threat auditing loop
    loop {
        let incidents = edr.scan_processes();
        
        if !incidents.is_empty() {
            for incident in incidents {
                // Ship telemetry data synchronously or asynchronously to centralized SOC backend
                info!("📡 Shipping EDR Threat Telemetry to SOC -> Incident ID: {}, Severity: {}, Process: {}, Trigger: {}", 
                    incident.anomaly_id, 
                    incident.severity, 
                    incident.process_name, 
                    incident.alert_category
                );
            }
        }

        sleep(Duration::from_sec(METRIC_PERIOD_INTERVAL_SECS)).await;
    }
}
