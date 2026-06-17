//! Kill-Chain Predictor — ATT&CK-based next-stage prediction and dwell-time estimation.
//!
//! Given an active attack campaign, this module:
//! 1. Maps the current kill-chain stage to the most likely next stage.
//! 2. Predicts the specific MITRE ATT&CK techniques likely to appear next.
//! 3. Estimates attacker dwell time based on campaign velocity.
//! 4. Generates prioritized defensive recommendations.
//! 5. Produces a natural-language threat narrative for CISO briefings.
//!
//! # MITRE ATT&CK Coverage
//! Covers all 7 Lockheed Martin Kill Chain stages:
//! Reconnaissance → Weaponization → Delivery → Exploitation →
//! Installation → Command & Control → Actions on Objectives

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ml::campaign_correlator::{Campaign, KillChainStage};

// ─── Output types ─────────────────────────────────────────────────────────────

/// Kill-chain prediction output for a campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainPrediction {
    pub campaign_id:           String,
    pub current_stage:         KillChainStage,
    pub next_stage:            KillChainStage,
    pub predicted_techniques:  Vec<PredictedTechnique>,
    pub recommended_actions:   Vec<String>,
    pub dwell_time_estimate:   DwellTimeEstimate,
    pub threat_narrative:      String,
    pub generated_at:          DateTime<Utc>,
}

/// A predicted next technique with rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictedTechnique {
    pub technique_id: String,
    pub name:         String,
    pub probability:  f64,
    pub rationale:    String,
}

/// Attacker dwell time estimate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DwellTimeEstimate {
    /// Hours since first campaign activity.
    pub hours_active:    f64,
    /// Expected additional hours until Actions on Objectives.
    pub hours_remaining: f64,
    /// Confidence level [0.0, 1.0].
    pub confidence:      f64,
}

// ─── Kill Chain Predictor ─────────────────────────────────────────────────────

/// Stateless predictor — call `predict()` with any campaign.
pub struct KillChainPredictor;

impl KillChainPredictor {
    pub fn new() -> Self { Self }

    /// Generate a full kill-chain prediction for a campaign.
    pub fn predict(&self, campaign: &Campaign) -> KillChainPrediction {
        let next_stage = self.next_stage(campaign.kill_chain_stage);
        let techniques = self.predicted_techniques(campaign.kill_chain_stage, campaign);
        let actions    = self.recommended_actions(campaign.kill_chain_stage, campaign);
        let dwell      = self.dwell_time(campaign);
        let narrative  = self.threat_narrative(campaign, &dwell);

        KillChainPrediction {
            campaign_id:          campaign.id.clone(),
            current_stage:        campaign.kill_chain_stage,
            next_stage,
            predicted_techniques: techniques,
            recommended_actions:  actions,
            dwell_time_estimate:  dwell,
            threat_narrative:     narrative,
            generated_at:         Utc::now(),
        }
    }

    // ── Stage progression ──────────────────────────────────────────────────

    fn next_stage(&self, current: KillChainStage) -> KillChainStage {
        match current {
            KillChainStage::Unknown        => KillChainStage::Reconnaissance,
            KillChainStage::Reconnaissance => KillChainStage::Weaponization,
            KillChainStage::Weaponization  => KillChainStage::Delivery,
            KillChainStage::Delivery       => KillChainStage::Exploitation,
            KillChainStage::Exploitation   => KillChainStage::Installation,
            KillChainStage::Installation   => KillChainStage::CommandControl,
            KillChainStage::CommandControl => KillChainStage::ActionsOnObj,
            KillChainStage::ActionsOnObj   => KillChainStage::ActionsOnObj,
        }
    }

    // ── Technique predictions ──────────────────────────────────────────────

    fn predicted_techniques(
        &self,
        current: KillChainStage,
        campaign: &Campaign,
    ) -> Vec<PredictedTechnique> {
        let next = self.next_stage(current);
        let mut preds = self.stage_techniques(next);

        // Boost probability if similar techniques already seen in campaign
        for pred in &mut preds {
            if campaign.mitre_techniques.contains(&pred.technique_id) {
                pred.probability = (pred.probability * 1.20).min(0.98);
                pred.rationale = format!("{} [already observed]", pred.rationale);
            }
        }

        preds.sort_by(|a, b| b.probability.partial_cmp(&a.probability).unwrap_or(std::cmp::Ordering::Equal));
        preds.truncate(5);
        preds
    }

    fn stage_techniques(&self, stage: KillChainStage) -> Vec<PredictedTechnique> {
        match stage {
            KillChainStage::Reconnaissance => vec![
                pt("T1595", "Active Scanning",              0.80, "Network enumeration follows campaign start"),
                pt("T1590", "Gather Victim Network Info",   0.65, "Target mapping typical in recon phase"),
                pt("T1589", "Gather Victim Identity Info",  0.55, "Credential harvesting supports later stages"),
            ],
            KillChainStage::Weaponization => vec![
                pt("T1588.002", "Obtain Capabilities: Tool",       0.75, "Adversaries acquire off-the-shelf tools"),
                pt("T1587.001", "Develop Capabilities: Malware",   0.60, "Custom implant for stealth"),
                pt("T1583.001", "Acquire Infrastructure: Domains", 0.50, "C2 domain registration"),
            ],
            KillChainStage::Delivery => vec![
                pt("T1566.001", "Spearphishing Attachment",  0.70, "Most common initial access vector"),
                pt("T1190",     "Exploit Public-Facing App", 0.65, "Vulnerability exploitation for access"),
                pt("T1133",     "External Remote Services",  0.50, "VPN/RDP abuse for initial access"),
            ],
            KillChainStage::Exploitation => vec![
                pt("T1059.003", "Windows Command Shell",     0.75, "Shell access post-exploitation"),
                pt("T1059.004", "Unix Shell",                0.70, "Linux shell execution after exploit"),
                pt("T1055",     "Process Injection",         0.65, "Memory injection for stealth execution"),
                pt("T1068",     "Exploitation for Privilege Escalation", 0.60, "PrivEsc follows initial foothold"),
            ],
            KillChainStage::Installation => vec![
                pt("T1543.003", "Create/Modify System Process",    0.60, "Service-based persistence"),
                pt("T1547.001", "Registry Run Keys",               0.65, "Persistence via registry"),
                pt("T1053.005", "Scheduled Task",                  0.70, "Task scheduler persistence"),
                pt("T1014",     "Rootkit",                         0.55, "Kernel-level persistence"),
            ],
            KillChainStage::CommandControl => vec![
                pt("T1071.001", "Web Protocols (HTTP/S)",  0.80, "HTTP/S C2 is dominant"),
                pt("T1071.004", "DNS C2",                  0.65, "DNS tunneling for covert C2"),
                pt("T1572",     "Protocol Tunneling",      0.60, "Tunnel C2 in legitimate protocols"),
                pt("T1095",     "Non-App Layer Protocol",  0.45, "ICMP/raw socket C2"),
            ],
            KillChainStage::ActionsOnObj => vec![
                pt("T1486", "Data Encrypted for Impact", 0.60, "Ransomware deployment"),
                pt("T1041", "Exfiltration Over C2",      0.70, "Data theft via existing C2"),
                pt("T1485", "Data Destruction",          0.40, "Wiper malware deployment"),
                pt("T1048", "Exfiltration Over Alternative Protocol", 0.55, "Out-of-band data exfil"),
            ],
            KillChainStage::Unknown => vec![
                pt("T1595", "Active Scanning", 0.50, "Campaign in unknown stage — recon likely"),
            ],
        }
    }

    // ── Recommended actions ────────────────────────────────────────────────

    fn recommended_actions(
        &self,
        current: KillChainStage,
        campaign: &Campaign,
    ) -> Vec<String> {
        let mut actions = match current {
            KillChainStage::Unknown | KillChainStage::Reconnaissance => vec![
                "Enable network flow logging on all ingress/egress points".into(),
                "Review firewall rules for unnecessary exposed services".into(),
                "Activate threat-intelligence feed for observed IPs/domains".into(),
            ],
            KillChainStage::Weaponization => vec![
                "Update AV/EDR signatures immediately".into(),
                "Verify email gateway sandbox is processing all attachments".into(),
                "Audit exposed web application versions against CVE database".into(),
            ],
            KillChainStage::Delivery => vec![
                "Block observed source IPs at perimeter firewall".into(),
                "Quarantine suspicious email attachments from affected users".into(),
                "Force password reset for targeted accounts".into(),
            ],
            KillChainStage::Exploitation => vec![
                "ISOLATE affected hosts from network immediately".into(),
                "Capture memory image of affected processes for forensics".into(),
                "Revoke credentials of affected service accounts".into(),
                "Engage incident response team now".into(),
            ],
            KillChainStage::Installation => vec![
                "Scan all hosts for new services/scheduled tasks/registry keys".into(),
                "Review kernel module loads since campaign start".into(),
                "Restore affected systems from clean backup if possible".into(),
                "Enable process creation auditing enterprise-wide".into(),
            ],
            KillChainStage::CommandControl => vec![
                "Block C2 domains/IPs at DNS and firewall layers".into(),
                "Enable deep packet inspection on all outbound traffic".into(),
                "Deploy network-based C2 detection signatures".into(),
                "Consider network segmentation to limit lateral movement".into(),
            ],
            KillChainStage::ActionsOnObj => vec![
                "CRITICAL: Initiate full incident response and business continuity plan".into(),
                "Preserve all forensic evidence before remediation".into(),
                "Notify legal, compliance, and executive stakeholders".into(),
                "Assess data exfiltration scope for breach notification requirements".into(),
                "Initiate crisis communications plan if applicable".into(),
            ],
        };

        // Add threat-score-based urgency
        if campaign.threat_score > 0.85 {
            actions.insert(0, format!(
                "URGENT: Campaign threat score {:.0}% — escalate to CISO immediately",
                campaign.threat_score * 100.0
            ));
        }

        actions
    }

    // ── Dwell time estimation ──────────────────────────────────────────────

    fn dwell_time(&self, campaign: &Campaign) -> DwellTimeEstimate {
        let hours_active = (campaign.last_seen - campaign.first_seen)
            .num_minutes() as f64 / 60.0;

        // Estimate remaining time based on kill-chain stage progression
        // Average attacker dwell: ~24h per stage (industry data)
        let stages_remaining = match campaign.kill_chain_stage {
            KillChainStage::Unknown        => 7.0,
            KillChainStage::Reconnaissance => 6.0,
            KillChainStage::Weaponization  => 5.0,
            KillChainStage::Delivery       => 4.0,
            KillChainStage::Exploitation   => 3.0,
            KillChainStage::Installation   => 2.0,
            KillChainStage::CommandControl => 1.0,
            KillChainStage::ActionsOnObj   => 0.0,
        };

        // Adjust by campaign velocity (alert density)
        let velocity_factor = if campaign.alert_count > 20 { 0.5 }
                              else if campaign.alert_count > 5 { 0.75 }
                              else { 1.0 };

        let hours_remaining = stages_remaining * 24.0 * velocity_factor;

        // Confidence based on alert count
        let confidence = (campaign.alert_count as f64 / 20.0).min(0.90);

        DwellTimeEstimate { hours_active, hours_remaining, confidence }
    }

    // ── Threat narrative ───────────────────────────────────────────────────

    fn threat_narrative(&self, campaign: &Campaign, dwell: &DwellTimeEstimate) -> String {
        let stage_desc = match campaign.kill_chain_stage {
            KillChainStage::Unknown        => "is in an unknown initial phase",
            KillChainStage::Reconnaissance => "is actively performing reconnaissance against your environment",
            KillChainStage::Weaponization  => "is preparing weaponized payloads for delivery",
            KillChainStage::Delivery       => "is delivering malicious payloads to target systems",
            KillChainStage::Exploitation   => "has achieved initial exploitation on one or more systems",
            KillChainStage::Installation   => "has established persistence mechanisms across your environment",
            KillChainStage::CommandControl => "has an active command and control channel into your network",
            KillChainStage::ActionsOnObj   => "is executing its final objectives — DATA LOSS OR DAMAGE IS IMMINENT",
        };

        let engine_list: Vec<&str> = campaign.source_engines.iter().map(|s| s.as_str()).collect();
        let next_stage = self.next_stage(campaign.kill_chain_stage);

        format!(
            "An attack campaign (ID: {id}, threat score: {score:.0}%) {stage_desc}. \
             The campaign was detected by {engines} engine(s) across {alert_count} alert(s) \
             spanning {src_ip_count} unique source IP(s) and {technique_count} ATT&CK technique(s). \
             The adversary has been active for {hours:.1} hours. \
             If not contained, the campaign is expected to advance to the '{next_stage}' phase \
             within approximately {remaining:.0} hours. \
             Immediate containment is {'CRITICAL' if the threat is high else 'recommended'}.",
            id            = campaign.id,
            score         = campaign.threat_score * 100.0,
            stage_desc    = stage_desc,
            engines       = engine_list.join(", "),
            alert_count   = campaign.alert_count,
            src_ip_count  = campaign.src_ips.len(),
            technique_count = campaign.mitre_techniques.len(),
            hours         = dwell.hours_active,
            next_stage    = next_stage,
            remaining     = dwell.hours_remaining,
        )
    }
}

impl Default for KillChainPredictor {
    fn default() -> Self { Self::new() }
}

// ─── Helper ───────────────────────────────────────────────────────────────────

fn pt(id: &str, name: &str, prob: f64, rationale: &str) -> PredictedTechnique {
    PredictedTechnique {
        technique_id: id.into(),
        name:         name.into(),
        probability:  prob,
        rationale:    rationale.into(),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml::campaign_correlator::{CampaignCorrelator, CorrelatedAlert};
    use chrono::Utc;

    fn make_alert(id: &str, techniques: Vec<&str>) -> CorrelatedAlert {
        CorrelatedAlert {
            id:               id.into(),
            timestamp:        Utc::now(),
            severity:         3,
            src_ip:           Some("10.0.0.1".into()),
            dst_ip:           None,
            pid:              None,
            entity_id:        None,
            mitre_techniques: techniques.into_iter().map(|t| t.into()).collect(),
            ioc_hashes:       vec![],
            source_engine:    "test".into(),
            description:      "test".into(),
        }
    }

    #[test]
    fn predictor_produces_output_for_any_stage() {
        let predictor = KillChainPredictor::new();
        let correlator = CampaignCorrelator::new();

        // Build a campaign with C2-stage techniques
        correlator.ingest(make_alert("a1", vec!["T1071.001", "T1095"]));
        let campaigns = correlator.active_campaigns();
        assert!(!campaigns.is_empty());

        let pred = predictor.predict(&campaigns[0]);
        assert!(!pred.threat_narrative.is_empty());
        assert!(!pred.recommended_actions.is_empty());
        assert!(!pred.predicted_techniques.is_empty());
    }

    #[test]
    fn next_stage_advances_correctly() {
        let p = KillChainPredictor::new();
        assert_eq!(p.next_stage(KillChainStage::Delivery),       KillChainStage::Exploitation);
        assert_eq!(p.next_stage(KillChainStage::Installation),   KillChainStage::CommandControl);
        assert_eq!(p.next_stage(KillChainStage::CommandControl), KillChainStage::ActionsOnObj);
        assert_eq!(p.next_stage(KillChainStage::ActionsOnObj),   KillChainStage::ActionsOnObj);
    }

    #[test]
    fn dwell_time_for_fresh_campaign_is_nonzero() {
        let correlator = CampaignCorrelator::new();
        correlator.ingest(make_alert("a1", vec!["T1059"]));
        let campaigns = correlator.active_campaigns();
        let predictor = KillChainPredictor::new();
        let pred = predictor.predict(&campaigns[0]);
        assert!(pred.dwell_time_estimate.hours_remaining > 0.0);
    }

    #[test]
    fn actions_on_obj_triggers_critical_actions() {
        let correlator = CampaignCorrelator::new();
        // Use Actions-on-objectives techniques
        correlator.ingest(make_alert("a1", vec!["T1041", "T1486"]));
        let campaigns = correlator.active_campaigns();
        let predictor = KillChainPredictor::new();
        let pred = predictor.predict(&campaigns[0]);
        let has_critical = pred.recommended_actions.iter()
            .any(|a| a.contains("CRITICAL") || a.contains("incident response"));
        assert!(has_critical, "ActionsOnObj stage should produce critical recommendations");
    }
}
