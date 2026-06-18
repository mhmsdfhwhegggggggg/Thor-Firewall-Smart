//! LDAP / Active Directory Integration — Phase 4
//!
//! Enables UEBA to use real identities instead of numeric UIDs.
//! Provides:
//!   - User lookup (uid → full name, department, email, groups)
//!   - Group-based role mapping (AD group → ThorRole)
//!   - Periodic user cache refresh (every 15 minutes)
//!
//! Config via environment variables:
//!   THOR_LDAP_URL=ldaps://dc.corp.local:636
//!   THOR_LDAP_BIND_DN=cn=thor-svc,ou=services,dc=corp,dc=local
//!   THOR_LDAP_BIND_PW=...
//!   THOR_LDAP_BASE_DN=dc=corp,dc=local
//!   THOR_LDAP_ADMIN_GROUP=CN=ThorAdmins,OU=Security,DC=corp,DC=local
//!   THOR_LDAP_ANALYST_GROUP=CN=ThorAnalysts,OU=Security,DC=corp,DC=local

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use serde::{Deserialize, Serialize};

use crate::api::auth_middleware::ThorRole;

// ─── User identity ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapUser {
    pub username:     String,
    pub display_name: String,
    pub email:        Option<String>,
    pub department:   Option<String>,
    pub groups:       Vec<String>,
    pub thor_role:    Option<ThorRole>,
    pub is_active:    bool,
}

// ─── LDAP Config ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LdapConfig {
    pub url:           String,
    pub bind_dn:       String,
    pub bind_pw:       String,
    pub base_dn:       String,
    pub admin_group:   String,
    pub analyst_group: String,
    pub user_filter:   String,
    pub refresh_secs:  u64,
}

impl LdapConfig {
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("THOR_LDAP_URL").ok()?;
        let bind_dn = std::env::var("THOR_LDAP_BIND_DN").ok()?;
        let bind_pw = std::env::var("THOR_LDAP_BIND_PW").ok()?;
        let base_dn = std::env::var("THOR_LDAP_BASE_DN").ok()?;
        Some(Self {
            url, bind_dn, bind_pw, base_dn,
            admin_group:   std::env::var("THOR_LDAP_ADMIN_GROUP").unwrap_or_default(),
            analyst_group: std::env::var("THOR_LDAP_ANALYST_GROUP").unwrap_or_default(),
            user_filter:   std::env::var("THOR_LDAP_USER_FILTER")
                .unwrap_or_else(|_| "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))".into()),
            refresh_secs:  std::env::var("THOR_LDAP_REFRESH_SECS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(900),
        })
    }
}

// ─── LDAP Cache ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct LdapCache {
    /// username → LdapUser
    users: Arc<RwLock<HashMap<String, LdapUser>>>,
    config: LdapConfig,
}

impl LdapCache {
    pub async fn new(config: LdapConfig) -> Self {
        let cache = Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            config,
        };
        if let Err(e) = cache.sync().await {
            warn!("Initial LDAP sync failed: {}. Will retry in background.", e);
        }
        let cache_clone = cache.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(cache_clone.config.refresh_secs);
            loop {
                tokio::time::sleep(interval).await;
                match cache_clone.sync().await {
                    Ok(n) => info!("🔄 LDAP cache refreshed: {} users", n),
                    Err(e) => warn!("LDAP sync error: {}", e),
                }
            }
        });
        cache
    }

    pub async fn get_user(&self, username: &str) -> Option<LdapUser> {
        self.users.read().await.get(username).cloned()
    }

    pub async fn enrich_username(&self, username: &str) -> (String, Option<String>) {
        if let Some(user) = self.get_user(username).await {
            (user.display_name, user.department)
        } else {
            (username.to_string(), None)
        }
    }

    pub fn derive_role(&self, groups: &[String]) -> Option<ThorRole> {
        if groups.iter().any(|g| g == &self.config.admin_group) {
            Some(ThorRole::Admin)
        } else if groups.iter().any(|g| g == &self.config.analyst_group) {
            Some(ThorRole::Analyst)
        } else {
            None
        }
    }

    async fn sync(&self) -> anyhow::Result<usize> {
        // Stub — implement with ldap3 crate when ready
        // Add to Cargo.toml: ldap3 = { version = "0.11", features = ["gssapi"] }
        debug!("LDAP sync stub: connecting to {}", self.config.url);
        info!("⚠️  LDAP sync stub — add ldap3 dependency and implement full sync");
        Ok(0)
    }
}

pub async fn init_ldap() -> Option<LdapCache> {
    let config = LdapConfig::from_env()?;
    info!("🔐 LDAP integration enabled: {}", config.url);
    Some(LdapCache::new(config).await)
}
