//! SIEM Integration — CEF (Common Event Format) and Syslog exporter
//! Supports: Splunk, IBM QRadar, ArcSight, Microsoft Sentinel
//!
//! CEF Format:
//!   CEF:Version|Device Vendor|Device Product|Device Version|
//!   Signature ID|Name|Severity|Extension
//!
//! Usage:
//!   let exporter = SiemExporter::new("syslog://siem.bank.internal:514");
//!   exporter.send(&alert).await?;

use crate::events::Alert;
use thor_common::ThreatLevel;
use anyhow::Result;
use chrono::Utc;
use tracing::{info, warn, error};

// ─── CEF Severity mapping ─────────────────────────────────────────────────────

fn cef_severity(level: &ThreatLevel) -> u8 {
    match level {
        ThreatLevel::Critical => 10,
        ThreatLevel::High     => 8,
        ThreatLevel::Medium   => 5,
        ThreatLevel::Low      => 3,
        ThreatLevel::Unknown  => 1,
    }
}

// ─── CEF record builder ───────────────────────────────────────────────────────

pub fn alert_to_cef(alert: &Alert) -> String {
    let severity  = cef_severity(&alert.threat_level);
    let timestamp = alert.timestamp.format("%b %d %Y %H:%M:%S").to_string();

    // Build CEF extension fields
    let mut ext = Vec::new();
    ext.push(format!("rt={}", alert.timestamp.timestamp_millis()));
    ext.push(format!("cs1={}", sanitize_cef(&alert.rule_name)));
    ext.push(format!("cs1Label=RuleName"));
    ext.push(format!("cs2={}", sanitize_cef(&alert.description)));
    ext.push(format!("cs2Label=Description"));
    ext.push(format!("threatLevel={:?}", alert.threat_level));

    if let Some(ip) = &alert.src_ip {
        ext.push(format!("src={}", sanitize_cef(ip)));
    }
    if let Some(ip) = &alert.dst_ip {
        ext.push(format!("dst={}", sanitize_cef(ip)));
    }
    if let Some(port) = alert.dst_port {
        ext.push(format!("dpt={}", port));
    }
    if let Some(pid) = alert.pid {
        ext.push(format!("spid={}", pid));
    }
    if let Some(proc) = &alert.process_name {
        ext.push(format!("sproc={}", sanitize_cef(proc)));
    }
    if let Some(score) = alert.ml_score {
        ext.push(format!("cn1={:.4}", score));
        ext.push("cn1Label=MLScore".to_string());
    }
    if !alert.soar_actions_taken.is_empty() {
        ext.push(format!("cs3={}", alert.soar_actions_taken.join("|")));
        ext.push("cs3Label=SOARActions".to_string());
    }
    ext.push(format!("deviceExternalId={}", sanitize_cef(&alert.id)));

    format!(
        "CEF:0|ThorSecurity|ThorFirewallSmart|0.1.0|{}|{}|{}|{}",
        sanitize_cef(&alert.id),
        sanitize_cef(&alert.rule_name),
        severity,
        ext.join(" "),
    )
}

/// Convert alert to LEEF 2.0 format (IBM QRadar)
pub fn alert_to_leef(alert: &Alert) -> String {
    let severity = cef_severity(&alert.threat_level);
    let ts = alert.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let mut fields = vec![
        format!("eventTime={}", ts),
        format!("severity={}", severity),
        format!("cat={}", sanitize_leef(&format!("{:?}", alert.rule_type))),
        format!("identSrc={}", alert.src_ip.as_deref().unwrap_or("unknown")),
        format!("identDst={}", alert.dst_ip.as_deref().unwrap_or("unknown")),
        format!("ruleName={}", sanitize_leef(&alert.rule_name)),
        format!("desc={}", sanitize_leef(&alert.description)),
        format!("alertId={}", &alert.id),
    ];
    if let Some(score) = alert.ml_score {
        fields.push(format!("mlScore={:.4}", score));
    }

    format!(
        "LEEF:2.0|ThorSecurity|ThorFirewallSmart|0.1.0|ThreatAlert|{}",
        fields.join("\t"),
    )
}

// ─── SIEM Exporter ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SiemExporter {
    endpoint: Option<String>,
    format: SiemFormat,
}

#[derive(Clone, Debug)]
pub enum SiemFormat {
    Cef,
    Leef,
}

impl SiemExporter {
    /// Create exporter. endpoint example: "syslog://siem.bank.internal:514"
    /// Pass None to disable (log-only mode).
    pub fn new(endpoint: Option<String>, format: SiemFormat) -> Self {
        if let Some(ep) = &endpoint {
            info!("📡 SIEM exporter configured: {} ({:?})", ep, format);
        } else {
            info!("📡 SIEM exporter disabled (no endpoint configured)");
        }
        Self { endpoint, format }
    }

    pub fn from_env() -> Self {
        let endpoint = std::env::var("THOR_SIEM_ENDPOINT").ok();
        let format = match std::env::var("THOR_SIEM_FORMAT").as_deref() {
            Ok("leef") | Ok("LEEF") => SiemFormat::Leef,
            _ => SiemFormat::Cef,
        };
        Self::new(endpoint, format)
    }

    /// Format alert and send to SIEM endpoint (or log if no endpoint).
    pub async fn send(&self, alert: &Alert) -> Result<()> {
        let record = match self.format {
            SiemFormat::Cef  => alert_to_cef(alert),
            SiemFormat::Leef => alert_to_leef(alert),
        };

        match &self.endpoint {
            None => {
                // Log-only mode — operators can pipe stdout to their SIEM agent
                info!(siem_record = %record, "SIEM_EXPORT");
                Ok(())
            }
            Some(ep) if ep.starts_with("http") => {
                self.send_http(ep, &record).await
            }
            Some(ep) => {
                // For syslog:// endpoints, log the record and note it
                // Full syslog UDP/TCP implementation for v0.2
                warn!("Syslog transport not yet implemented for {}. Record logged.", ep);
                info!(siem_record = %record, "SIEM_EXPORT");
                Ok(())
            }
        }
    }

    async fn send_http(&self, url: &str, record: &str) -> Result<()> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;

        let api_key = std::env::var("THOR_SIEM_API_KEY").unwrap_or_default();

        let res = client
            .post(url)
            .header("Content-Type", "text/plain")
            .header("Authorization", format!("Splunk {}", api_key))
            .body(record.to_string())
            .send()
            .await?;

        if !res.status().is_success() {
            error!("SIEM HTTP export failed: status={}", res.status());
        }
        Ok(())
    }
}

// ─── Sanitization ─────────────────────────────────────────────────────────────

/// CEF values must not contain | or \n unescaped
fn sanitize_cef(s: &str) -> String {
    s.replace('\\', "\\\\")
     .replace('|', "\\|")
     .replace('\n', "\\n")
     .replace('\r', "")
}

/// LEEF values must not contain \t or \n
fn sanitize_leef(s: &str) -> String {
    s.replace('\t', " ").replace('\n', " ").replace('\r', "")
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Alert, RuleType};
    use thor_common::ThreatLevel;
    use chrono::Utc;

    fn mock_alert() -> Alert {
        Alert {
            id: "test-id-001".to_string(),
            timestamp: Utc::now(),
            source: "test-host".to_string(),
            rule_name: "Test|Rule".to_string(),
            rule_type: RuleType::Sigma,
            threat_level: ThreatLevel::High,
            description: "Test description\nwith newline".to_string(),
            pid: Some(1234),
            process_name: Some("malware.exe".to_string()),
            src_ip: Some("10.0.1.50".to_string()),
            dst_ip: Some("185.220.101.1".to_string()),
            dst_port: Some(443),
            ml_score: Some(0.92),
            soar_actions_taken: vec!["ip_blocked:185.220.101.1".to_string()],
            raw_event_type: "network".to_string(),
        }
    }

    #[test]
    fn test_cef_format_valid() {
        let alert = mock_alert();
        let cef = alert_to_cef(&alert);
        assert!(cef.starts_with("CEF:0|ThorSecurity|"));
        assert!(!cef.contains('\n'), "CEF must be single line");
        assert!(cef.contains("src=10.0.1.50"));
        assert!(cef.contains("dst=185.220.101.1"));
    }

    #[test]
    fn test_cef_sanitizes_pipe() {
        let alert = mock_alert();
        let cef = alert_to_cef(&alert);
        // "Test|Rule" should be escaped as "Test\|Rule" in CEF extension
        assert!(cef.contains("Test\\|Rule"));
    }

    #[test]
    fn test_leef_format_valid() {
        let alert = mock_alert();
        let leef = alert_to_leef(&alert);
        assert!(leef.starts_with("LEEF:2.0|ThorSecurity|"));
        assert!(!leef.contains('\n'));
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(cef_severity(&ThreatLevel::Critical), 10);
        assert_eq!(cef_severity(&ThreatLevel::High),     8);
        assert_eq!(cef_severity(&ThreatLevel::Medium),   5);
        assert_eq!(cef_severity(&ThreatLevel::Low),      3);
        assert_eq!(cef_severity(&ThreatLevel::Unknown),  1);
    }
}
