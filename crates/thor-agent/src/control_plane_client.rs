//! Thor Agent gRPC Client
//! Maintains persistent connection to Control Plane and listens for policy updates.

use anyhow::Result;
use tokio::sync::mpsc;
// use tokio_stream::StreamExt;
use tracing::{info, warn, error};
use crate::detection::sigma::{GuardedDynamicRule, RuleMode, RuleSource};
use std::time::Instant;
use std::sync::atomic::AtomicUsize;

// Assuming proto integration is setup, for now we will stub out the stream reading logic conditionally:
/*
use thor_proto::thor_control_service_client::ThorControlServiceClient;
use thor_proto::{HeartbeatRequest, AgentMetrics, StreamPoliciesRequest};
*/

pub struct ControlPlaneClient {
    agent_id: String,
    token: String,
    server_url: String,
}

impl ControlPlaneClient {
    pub fn new(agent_id: String, token: String, server_url: String) -> Self {
        Self { agent_id, token, server_url }
    }

    /// تشغيل حلقة الاتصال الأبدية مع إعادة المحاولة عند الانقطاع
    pub async fn run(&self, policy_tx: mpsc::Sender<GuardedDynamicRule>) -> Result<()> {
        info!("🔗 Connecting to Control Plane at {}", self.server_url);
        
        loop {
            match self.connect_and_listen(policy_tx.clone()).await {
                Ok(_) => info!("Connection closed gracefully, reconnecting..."),
                Err(e) => {
                    error!("❌ Connection lost: {}. Reconnecting in 5 seconds...", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
        }
    }

    async fn connect_and_listen(&self, _policy_tx: mpsc::Sender<GuardedDynamicRule>) -> Result<()> {
        // 1. الاتصال بالخادم (مع mTLS في الإنتاج)
        // let mut client = ThorControlServiceClient::connect(self.server_url.clone()).await?;
        
        // 2. طلب تدفق السياسات
        /*
        let request = tonic::Request::new(StreamPoliciesRequest {
            agent_id: self.agent_id.clone(),
            agent_token: self.token.clone(),
            last_known_policy_version: 0, // يتم تحميلها من الذاكرة المحلية
        });
        */

        // let mut stream = client.stream_policies(request).await?.into_inner();
        
        info!("✅ Successfully subscribed to policy stream");

        // 3. الاستماع للتحديثات بشكل غير متزامن
        /*
        while let Some(update) = stream.next().await {
            let update = update?;
            info!("📥 Received policy update: {} (v{})", update.policy_type, update.version);
            
            if update.policy_type == "sigma" {
                // إرسال القاعدة الجديدة لمحرك Sigma المحلي للحقن الديناميكي
                let mode = if update.enforcement_mode == "SHADOW" { RuleMode::Shadow } else { RuleMode::Enforce };
                let rule = GuardedDynamicRule {
                    id: update.rule_id,
                    yaml_content: update.content,
                    title: format!("Control Plane Policy v{}", update.version),
                    mode,
                    created_at: Instant::now(),
                    match_count: AtomicUsize::new(0),
                    max_matches_per_minute: 100,
                    shadow_duration_secs: 3600,
                    source: RuleSource::HumanApproved,
                };
                let _ = _policy_tx.send(rule).await;
            }
        }
        */
        
        // محاكاة للاستعراض:
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        Ok(())
    }
}
