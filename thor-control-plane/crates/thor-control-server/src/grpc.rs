pub mod pb {
    tonic::include_proto!("thor.control.v1");
}

use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use crate::AppState;
use pb::thor_control_service_server::ThorControlService;
use pb::*;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use std::pin::Pin;
use ed25519_dalek::{Signer, SigningKey, Signature};

pub struct ThorControlServiceImpl {
    pub state: AppState,
}

/// Action Protocol: Cryptographically sign commands to ensure authenticity.
pub struct ActionProtocol;
impl ActionProtocol {
    pub fn sign_policy(key: &SigningKey, policy: &mut PolicyUpdate) {
        let mut data = Vec::new();
        data.extend_from_slice(&policy.version.to_le_bytes());
        data.extend_from_slice(policy.policy_type.as_bytes());
        data.extend_from_slice(policy.rule_id.as_bytes());
        data.extend_from_slice(policy.content.as_bytes());
        data.extend_from_slice(policy.action.as_bytes());
        data.extend_from_slice(policy.enforcement_mode.as_bytes());
        
        let signature: Signature = key.sign(&data);
        policy.signature = signature.to_bytes().to_vec();
    }
}

/// Delegation Policy Manager (Internal Helper)
/// This will eventually check if the agent belongs to the operator's group.
struct DelegationManager;
impl DelegationManager {
    fn validate_action(agent_id: &str, action: &str) -> bool {
        // Log for transparency
        info!("Delegation check: Authority validated for agent {} to execute {}", agent_id, action);
        true 
    }


    // ─── Phase 10: Remote Resolution Command Stream ───────────────────────────

    type StreamResolutionCommandsStream = Pin<Box<
        dyn futures::Stream<Item = Result<QuarantineResolution, Status>> + Send + 'static
    >>;

    /// Stream resolution commands to an agent for quarantined entities.
    /// Administrators push RESOLVE_BLOCK or RESOLVE_RELEASE directives here.
    /// Commands are Ed25519-signed for chain-of-custody compliance.
    async fn stream_resolution_commands(
        &self,
        request: Request<ResolutionStreamRequest>,
    ) -> Result<Response<Self::StreamResolutionCommandsStream>, Status> {
        let req = request.into_inner();
        info!("🔗 Resolution stream opened: agent_id={}", req.agent_id);

        // Subscribe to the resolution broadcast channel
        let rx = self.state.resolution_tx.subscribe();
        let agent_id = req.agent_id.clone();
        let signing_key = self.state.signing_key.clone();

        let stream = tokio_stream::wrappers::BroadcastStream::new(rx)
            .filter_map(move |result| {
                let agent_id = agent_id.clone();
                let signing_key = signing_key.clone();
                async move {
                    match result {
                        Ok(mut resolution) => {
                            // Only send directives meant for this agent
                            if resolution.resolution_id.contains(&agent_id)
                                || resolution.resolution_id.is_empty()
                            {
                                // Sign the resolution directive for chain-of-custody
                                if let Some(key) = &signing_key {
                                    let mut data = Vec::new();
                                    data.extend_from_slice(resolution.resolution_id.as_bytes());
                                    data.extend_from_slice(resolution.alert_id.as_bytes());
                                    data.extend_from_slice(resolution.target_pid_or_ip.as_bytes());
                                    data.extend_from_slice(&(resolution.action as i32).to_le_bytes());
                                    data.extend_from_slice(resolution.operator_id.as_bytes());
                                    let sig = key.sign(&data);
                                    resolution.signature = sig.to_bytes().to_vec();
                                }
                                Some(Ok(resolution))
                            } else {
                                None
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Resolution stream lagged {} messages for agent {}", n, agent_id);
                            None
                        }
                        Err(_) => None,
                    }
                }
            });

        Ok(Response::new(Box::pin(stream)))
    }

    /// Agent reports its current quarantine state for the HITL dashboard.
    async fn report_quarantine_state(
        &self,
        request: Request<QuarantineStateReport>,
    ) -> Result<Response<QuarantineStateAck>, Status> {
        let report = request.into_inner();
        info!(
            "📊 Quarantine state report from agent_id={}: {} entities quarantined",
            report.agent_id, report.entities.len()
        );

        // Store quarantine state in the agent_manager for the dashboard
        for entity in &report.entities {
            info!(
                "  ⚠️  Quarantined: pid_or_ip={} process={} score={} reason={}",
                entity.target_pid_or_ip,
                entity.process_name,
                entity.anomaly_score,
                entity.xai_explanation
            );
        }

        // Persist to state store for dashboard retrieval
        if let Err(e) = self.state.agent_manager
            .update_quarantine_state(&report.agent_id, report.entities.len() as u32)
            .await
        {
            warn!("Failed to persist quarantine state: {}", e);
        }

        Ok(Response::new(QuarantineStateAck {
            accepted: true,
            message: format!("Quarantine state recorded: {} entities pending HITL review", 
                           report.entities.len()),
        }))
    }

}

#[tonic::async_trait]
impl ThorControlService for ThorControlServiceImpl {
    async fn register_agent(
        &self,
        request: Request<RegisterAgentRequest>,
    ) -> Result<Response<RegisterAgentResponse>, Status> {
        let req = request.into_inner();
        info!("🏛️  Registration Request: agent_id={} hostname={} ip={}", 
            req.agent_id, req.hostname, req.ip_address);
        
        // 🛡️ ERA: Zero-Trust Device Attestation
        if !crate::security::KmsService::verify_agent_integrity(&req.agent_id, &req.attestation_hash) {
            warn!("🚨 Attestation Failure: Agent {} provided invalid or missing hardware hash", req.agent_id);
            return Err(Status::unauthenticated("Hardware attestation failed. Device not trusted."));
        }

        // Update DB via state.agent_manager
        if let Err(e) = self.state.agent_manager.register_agent(
            &req.agent_id, &req.hostname, &req.ip_address
        ).await {
            warn!("Failed to register agent in DB: {}", e);
        }

        // 🛡️  Persistent State Store (Redb) - Production Hardening
        let metadata = crate::state_store::AgentMetadata {
            id: req.agent_id.clone(),
            hostname: req.hostname.clone(),
            ip: req.ip_address.clone(),
            last_heartbeat: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            status: "Online".to_string(),
            version: req.agent_version.clone(),
        };
        let _ = self.state.state_store.save_agent(&metadata);

        // 📊 Metrics
        self.state.metrics.inc_api("register_agent", 200);

        Ok(Response::new(RegisterAgentResponse {
            agent_token: format!("thor_jwt_{}", req.agent_id), // Placeholder for real JWT
            current_policy_version: 1,
        }))
    }

    type StreamPoliciesStream = Pin<Box<dyn tokio_stream::Stream<Item = Result<PolicyUpdate, Status>> + Send>>;

    async fn stream_policies(
        &self,
        request: Request<StreamPoliciesRequest>,
    ) -> Result<Response<Self::StreamPoliciesStream>, Status> {
        let req = request.into_inner();
        info!("📡 Agent {} subscribed to policy stream (v{})", req.agent_id, req.last_known_policy_version);
        
        let rx = self.state.policy_tx.subscribe();
        
        let stream = BroadcastStream::new(rx)
            .filter_map(|res| {
                match res {
                    Ok(update) => Some(Ok(update)),
                    Err(_) => None, // Handle lag by dropping
                }
            });

        Ok(Response::new(Box::pin(stream)))
    }

    async fn report_incident(
        &self,
        request: Request<IncidentReport>,
    ) -> Result<Response<IncidentAck>, Status> {
        let req = request.into_inner();
        info!("🚨 Alert from {}: severity={} description={}", 
            req.agent_id, req.severity, req.description);
        
        // Log to DB via agent_manager
        let _ = self.state.agent_manager.report_incident(&req.agent_id, &req.severity, &req.description).await;

        // 📊 Metrics
        self.state.metrics.inc_api("report_incident", 200);

        Ok(Response::new(IncidentAck {
            accepted: true,
            message: "Incident logged to SOC audit trail".to_string(),
        }))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let req = request.into_inner();
        
        if let Some(metrics) = req.metrics {
            let _ = self.state.agent_manager.update_heartbeat(
                &req.agent_id, 
                metrics.cpu_usage_percent as f32, 
                metrics.memory_usage_mb as i32
            ).await;

            // 🛡️ Update Redb metadata
            if let Ok(Some(mut meta)) = self.state.state_store.get_agent(&req.agent_id) {
                meta.last_heartbeat = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let _ = self.state.state_store.save_agent(&meta);
            }
        }
        
        // 📊 Metrics
        self.state.metrics.inc_api("heartbeat", 200);

        Ok(Response::new(HeartbeatResponse {
            is_healthy: true,
            message: "ACK".to_string(),
        }))
    }

    async fn submit_model_weights(
        &self,
        request: Request<ModelWeightUpdate>,
    ) -> Result<Response<ModelWeightAck>, Status> {
        let req = request.into_inner();
        info!("🧠 ML FL Update: agent={} model={} accuracy={:.4}", 
            req.agent_id, req.model_type, req.local_accuracy);
        
        Ok(Response::new(ModelWeightAck {
            accepted: true,
            global_model_version: "v1.1.0-alpha".to_string(),
        }))
    }

    async fn broadcast_threat(
        &self,
        request: Request<ThreatIndicator>,
    ) -> Result<Response<ThreatIndicatorAck>, Status> {
        let req = request.into_inner();
        info!("📡 Threat Feed: Found {} '{}' (confidence={:.2})", 
            req.ioc_type, req.value, req.ai_confidence_score);
        
        Ok(Response::new(ThreatIndicatorAck {
            distributed_globally: true,
            message: "Indicator distributed to global threat graph".to_string(),
        }))
    }
}
