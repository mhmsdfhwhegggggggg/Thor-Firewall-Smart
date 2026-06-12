use anyhow::Result;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tracing::{info, warn, error};
use sqlx::PgPool;
// Ensure we handle imports effectively, assuming some mocks or later file creations for definitions
// use crate::db::models::{Agent, AgentMetrics};

// For quick mockup matching the client's payload:
#[derive(Clone, Debug, Default)]
pub struct AgentMetrics {
    pub uptime_seconds: u64,
    pub events_processed: u64,
    pub threats_detected: u64,
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: u64,
    pub is_degraded: bool,
}

pub mod proto {
    use std::collections::HashMap;
    #[derive(Clone, Debug)]
    pub struct RegisterAgentRequest {
        pub agent_id: String,
        pub hostname: String,
        pub os_version: String,
        pub thor_version: String,
        pub ip_address: String,
        pub metadata: HashMap<String, String>,
    }
}

/// يمثل جلسة وكيل متصل حالياً
pub struct AgentSession {
    pub agent_id: String,
    pub last_heartbeat: Instant,
    pub metrics: AgentMetrics,
}

pub struct AgentManager {
    db: PgPool,
    /// تخزين سريع في الذاكرة للوكلاء المتصلين (O(1) lookup)
    active_agents: Arc<DashMap<String, AgentSession>>,
    /// قناة بث لتحديثات السياسات (تتسع لـ 1000 تحديث معلق)
    policy_tx: broadcast::Sender<PolicyUpdate>,
}

#[derive(Clone, Debug)]
pub struct PolicyUpdate {
    pub version: i64,
    pub policy_type: String,
    pub rule_id: String,
    pub content: String,
    pub action: String,
    pub enforcement_mode: String,
}

impl AgentManager {
    pub fn new(db: PgPool) -> Self {
        let (policy_tx, _) = broadcast::channel(1000);
        
        Self {
            db,
            active_agents: Arc::new(DashMap::new()),
            policy_tx,
        }
    }

    /// تسجيل وكيل جديد
    pub async fn register_agent(&self, req: proto::RegisterAgentRequest) -> Result<String> {
        // 1. حفظ في قاعدة البيانات
        let meta_json = serde_json::to_value(&req.metadata)?;
        sqlx::query!(
            r#"
            INSERT INTO agents (agent_id, hostname, os_version, thor_version, ip_address, metadata)
            VALUES ($1, $2, $3, $4, $5::inet, $6)
            ON CONFLICT (agent_id) DO UPDATE SET 
                last_heartbeat = NOW(), status = 'ACTIVE'
            "#,
            req.agent_id, req.hostname, req.os_version, req.thor_version, req.ip_address, meta_json
        )
        .execute(&self.db).await?;

        // 2. إضافة للذاكرة السريعة
        self.active_agents.insert(req.agent_id.clone(), AgentSession {
            agent_id: req.agent_id.clone(),
            last_heartbeat: Instant::now(),
            metrics: AgentMetrics::default(),
        });

        // 3. توليد JWT (يجب استخدام مفتاح سري قوي في الإنتاج)
        let token = self.generate_jwt(&req.agent_id)?;
        
        info!("✅ Agent registered: {} ({})", req.agent_id, req.hostname);
        Ok(token)
    }

    /// معالجة نبض الحياة (Heartbeat)
    pub async fn process_heartbeat(&self, agent_id: &str, metrics: AgentMetrics) -> Result<()> {
        // تحديث الذاكرة أولاً (أسرع شيء)
        if let Some(mut session) = self.active_agents.get_mut(agent_id) {
            session.last_heartbeat = Instant::now();
            session.metrics = metrics.clone();
        }

        // تحديث قاعدة البيانات بشكل غير متزامن أو مجمع (Batched) في الإنتاج الحقيقي
        sqlx::query!(
            r#"
            UPDATE agents SET 
                last_heartbeat = NOW(),
                status = CASE WHEN $4 = true THEN 'DEGRADED' ELSE 'ACTIVE' END,
                cpu_usage = $1,
                memory_mb = $2
            WHERE agent_id = $3
            "#,
            metrics.cpu_usage_percent,
            metrics.memory_usage_mb as i64,
            agent_id,
            metrics.is_degraded
        ).execute(&self.db).await?;

        Ok(())
    }

    /// بث تحديث سياسة جديد لجميع الوكلاء المتصلة فوراً
    pub async fn broadcast_policy(&self, update: PolicyUpdate) -> Result<usize> {
        let receiver_count = self.policy_tx.receiver_count();
        self.policy_tx.send(update.clone()).map_err(|e| anyhow::anyhow!("Broadcast failed: {}", e))?;
        
        // تسجيل في سجل التدقيق
        let details = serde_json::to_value(&update).unwrap_or(serde_json::json!({}));
        self.log_audit("SYSTEM", "POLICY_BROADCAST", &update.policy_type, &update.rule_id, &details).await?;
        
        info!("📡 Broadcasted policy v{} to {} connected agents", update.version, receiver_count);
        Ok(receiver_count)
    }

    /// الاشتراك في تدفق السياسات (للاستخدام من قبل gRPC Stream)
    pub fn subscribe_policies(&self) -> broadcast::Receiver<PolicyUpdate> {
        self.policy_tx.subscribe()
    }

    /// مهمة خلفية لتنظيف الوكلاء غير النشطين (Dead Agent Cleanup)
    pub async fn run_cleanup_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = Instant::now();
            let mut offline_count = 0;

            self.active_agents.retain(|_agent_id, session| {
                if now.duration_since(session.last_heartbeat) > Duration::from_secs(300) { // 5 دقائق
                    offline_count += 1;
                    false // إزالته من الذاكرة
                } else {
                    true
                }
            });

            if offline_count > 0 {
                warn!("🧹 Cleaned up {} offline agents from memory", offline_count);
                // تحديث حالتهم في DB إلى 'OFFLINE' بشكل مجمع (Batch)
            }
        }
    }

    fn generate_jwt(&self, agent_id: &str) -> Result<String> {
        Ok(format!("mock_jwt_token_for_{}", agent_id))
    }

    async fn log_audit(&self, actor: &str, action: &str, res_type: &str, res_id: &str, details: &serde_json::Value) -> Result<()> {
        sqlx::query!(
            "INSERT INTO audit_logs (actor_id, action, resource_type, resource_id, details) VALUES ($1, $2, $3, $4, $5)",
            actor, action, res_type, res_id, details
        ).execute(&self.db).await?;
        Ok(())
    }
}
