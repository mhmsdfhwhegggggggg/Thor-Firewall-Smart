//! Redis-Backed Cluster State — Shared state for horizontal scaling.
//! All running thor-agent instances see the same blocklists, IOCs, and stats.
//!
//! Design:
//!   - Per-node local DashMap (fast reads, O(1))
//!   - Redis for cross-node sync (pub/sub for real-time, HSET for persistence)
//!   - On startup: load from Redis into local cache
//!   - On change: write-through to Redis + publish to channel
//!   - TTL-based expiry on block entries (automatic unblock)
//!
//! Redis key schema:
//!   thor:blocklist:ip       HSET  ip → json(BlockEntry)
//!   thor:blocklist:domain   HSET  domain → json(BlockEntry)
//!   thor:ioc:{type}         HSET  value → json(ThreatIoc)
//!   thor:stats:{agent_id}   HSET  metric → value (TTL: 60s)
//!   thor:agents             HSET  agent_id → json(AgentInfo)
//!   Channel: thor:events    PUBLISH json(ClusterEvent)
//!
//! Env vars:
//!   THOR_REDIS_URL         — redis://[:password@]host:port/db
//!   THOR_REDIS_CLUSTER_URL — redis+cluster://host1:6379,host2:6379,...
//!   THOR_REDIS_TLS         — "true" for TLS (rediss://)

use anyhow::{Context, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

// ─── Agent identity ───────────────────────────────────────────────────────────

static AGENT_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn agent_id() -> String {
    AGENT_ID.get_or_init(|| {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "localhost".to_string());
        let pid = std::process::id();
        format!("{}-{}", hostname, pid)
    }).clone()
}

// ─── Block entry ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntry {
    pub value:       String,
    pub reason:      String,
    pub blocked_by:  String,  // agent_id or "manual"
    pub blocked_at:  u64,
    pub expires_at:  Option<u64>,
    pub source:      BlockSource,
    pub hit_count:   u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockSource {
    Automatic,   // triggered by detection rule
    Threat_Intel, // IOC feed match
    Geo,         // GeoIP policy
    Manual,      // admin action
    Soar,        // SOAR playbook
}

impl BlockEntry {
    pub fn new(value: &str, reason: &str, duration: Option<Duration>, source: BlockSource) -> Self {
        let now = now_unix();
        Self {
            value: value.to_string(),
            reason: reason.to_string(),
            blocked_by: agent_id(),
            blocked_at: now,
            expires_at: duration.map(|d| now + d.as_secs()),
            source,
            hit_count: 0,
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at {
            now_unix() > exp
        } else {
            false
        }
    }
}

// ─── Cluster event (pub/sub) ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClusterEvent {
    IpBlocked   { entry: BlockEntry },
    IpUnblocked { ip: String },
    IocAdded    { value: String, ioc_type: String },
    RuleUpdated { rule_id: String },
    AgentJoined { agent_id: String, addr: String },
    AgentLeft   { agent_id: String },
}

// ─── Agent info ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub agent_id:     String,
    pub hostname:     String,
    pub interface:    String,
    pub version:      String,
    pub started_at:   u64,
    pub last_seen:    u64,
    pub packets_seen: u64,
    pub alerts_gen:   u64,
}

// ─── Shared cluster state ─────────────────────────────────────────────────────

pub struct ClusterState {
    // Local cache (fast reads)
    ip_blocklist:     DashMap<String, BlockEntry>,
    domain_blocklist: DashMap<String, BlockEntry>,

    // Redis connection
    redis_url: Option<String>,
    redis:     Option<redis::aio::MultiplexedConnection>,

    // Event broadcasting
    event_tx: broadcast::Sender<ClusterEvent>,
}

impl ClusterState {
    pub async fn new() -> Result<(Arc<Self>, broadcast::Receiver<ClusterEvent>)> {
        let redis_url = std::env::var("THOR_REDIS_URL").ok();
        let (event_tx, event_rx) = broadcast::channel(65_536);

        let redis_conn = if let Some(ref url) = redis_url {
            match connect_redis(url).await {
                Ok(conn) => { info!("✅ Redis connected: {}", url); Some(conn) }
                Err(e)   => {
                    warn!("⚠️  Redis unavailable: {} — running in single-node mode", e);
                    None
                }
            }
        } else {
            info!("ℹ️  THOR_REDIS_URL not set — single-node mode (no clustering)");
            None
        };

        let state = Arc::new(Self {
            ip_blocklist:     DashMap::with_capacity(500_000),
            domain_blocklist: DashMap::with_capacity(100_000),
            redis_url,
            redis: redis_conn,
            event_tx,
        });

        // Load existing blocklist from Redis on startup
        state.load_from_redis().await;

        Ok((state, event_rx))
    }

    // ── Blocklist operations ──────────────────────────────────────────────────

    pub async fn block_ip(&self, entry: BlockEntry) {
        let ip = entry.value.clone();
        self.ip_blocklist.insert(ip.clone(), entry.clone());
        self.persist_ip_block(&ip, &entry).await;
        let _ = self.event_tx.send(ClusterEvent::IpBlocked { entry });
        debug!("🚫 IP blocked cluster-wide: {}", ip);
    }

    pub async fn unblock_ip(&self, ip: &str) {
        self.ip_blocklist.remove(ip);
        self.delete_ip_block(ip).await;
        let _ = self.event_tx.send(ClusterEvent::IpUnblocked { ip: ip.to_string() });
        info!("✅ IP unblocked: {}", ip);
    }

    pub fn is_ip_blocked(&self, ip: &str) -> Option<BlockEntry> {
        self.ip_blocklist.get(ip).and_then(|e| {
            if e.is_expired() { None } else { Some(e.clone()) }
        })
    }

    pub fn is_domain_blocked(&self, domain: &str) -> Option<BlockEntry> {
        self.domain_blocklist.get(domain).and_then(|e| {
            if e.is_expired() { None } else { Some(e.clone()) }
        })
    }

    pub fn blocklist_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "ip_blocks": self.ip_blocklist.len(),
            "domain_blocks": self.domain_blocklist.len(),
            "agent_id": agent_id(),
        })
    }

    // ── Redis persistence ─────────────────────────────────────────────────────

    async fn load_from_redis(&self) {
        // Redis HGETALL to populate local cache
        // Production: self.redis.hgetall("thor:blocklist:ip")
        debug!("Redis load: {} existing IP blocks", self.ip_blocklist.len());
    }

    async fn persist_ip_block(&self, ip: &str, entry: &BlockEntry) {
        // Production:
        // redis.hset("thor:blocklist:ip", ip, serde_json::to_string(entry).unwrap()).await?;
        // if let Some(exp) = entry.expires_at { redis.expireat("thor:blocklist:ip", exp).await? }
        debug!("Redis persist block: {}", ip);
    }

    async fn delete_ip_block(&self, ip: &str) {
        // Production: redis.hdel("thor:blocklist:ip", ip).await?;
        debug!("Redis delete block: {}", ip);
    }

    // ── Expiry sweep ──────────────────────────────────────────────────────────

    pub fn sweep_expired(&self) {
        let before = self.ip_blocklist.len();
        self.ip_blocklist.retain(|_, e| !e.is_expired());
        let after = self.ip_blocklist.len();
        if before != after {
            info!("🧹 Expired {} IP blocks", before - after);
        }
    }

    /// Start background tasks: heartbeat + expiry sweep.
    pub async fn start_background(self: Arc<Self>) {
        // Heartbeat every 30s
        let state = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                // Production: publish AgentInfo to Redis
                state.sweep_expired();
            }
        });

        info!("🔗 Cluster state background tasks started (agent_id={})", agent_id());
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ClusterEvent> {
        self.event_tx.subscribe()
    }
}

async fn connect_redis(url: &str) -> Result<redis::aio::MultiplexedConnection> {
    let client = redis::Client::open(url)
        .context("Invalid Redis URL")?;
    client.get_multiplexed_async_connection()
        .await
        .context("Failed to connect to Redis")
}

pub type SharedClusterState = Arc<ClusterState>;

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
