//! User and Entity Behavioral Analytics (UEBA) Engine
//! Enhanced Production Version with Continuous Learning & Advanced Anomaly Scoring

use std::collections::HashMap;
use std::sync::RwLock;
use chrono::{DateTime, Utc, Timelike};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ─── Entity identity ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EntityId {
    User(String),
    Process(String),
    Host(String),
    Service(String),
    NetworkZone(String),
}

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityId::User(s)        => write!(f, "user:{}", s),
            EntityId::Process(s)     => write!(f, "proc:{}", s),
            EntityId::Host(s)        => write!(f, "host:{}", s),
            EntityId::Service(s)     => write!(f, "svc:{}", s),
            EntityId::NetworkZone(s) => write!(f, "zone:{}", s),
        }
    }
}

// ─── Entity feature vector ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EntityFeatures {
    pub auth_rate:           f64,
    pub unique_dest_ips:     f64,
    pub bytes_per_min:       f64,
    pub process_create_rate: f64,
    pub file_access_rate:    f64,
    pub auth_failure_rate:   f64,
    pub hour_of_day:         f64,
    pub day_of_week:         f64,
    pub internal_vs_external_ratio: f64,
    pub privilege_level:     f64,
}

impl EntityFeatures {
    pub const DIM: usize = 10;

    pub fn zero() -> Self {
        Self {
            auth_rate:           0.0,
            unique_dest_ips:     0.0,
            bytes_per_min:       0.0,
            process_create_rate: 0.0,
            file_access_rate:    0.0,
            auth_failure_rate:   0.0,
            hour_of_day:         0.0,
            day_of_week:         0.0,
            internal_vs_external_ratio: 0.0,
            privilege_level:     0.0,
        }
    }

    pub fn as_array(&self) -> [f64; Self::DIM] {
        [
            self.auth_rate,
            self.unique_dest_ips,
            self.bytes_per_min,
            self.process_create_rate,
            self.file_access_rate,
            self.auth_failure_rate,
            self.hour_of_day,
            self.day_of_week,
            self.internal_vs_external_ratio,
            self.privilege_level,
        ]
    }

    fn from_array(a: [f64; Self::DIM]) -> Self {
        Self {
            auth_rate:           a[0],
            unique_dest_ips:     a[1],
            bytes_per_min:       a[2],
            process_create_rate: a[3],
            file_access_rate:    a[4],
            auth_failure_rate:   a[5],
            hour_of_day:         a[6],
            day_of_week:         a[7],
            internal_vs_external_ratio: a[8],
            privilege_level:     a[9],
        }
    }

    pub fn update_ema(&mut self, new_obs: &EntityFeatures, alpha: f64) {
        let arr = new_obs.as_array();
        let base = self.as_array();
        let updated: [f64; Self::DIM] = std::array::from_fn(|i| {
            alpha * arr[i] + (1.0 - alpha) * base[i]
        });
        *self = Self::from_array(updated);
    }
}

// ─── Entity Profile ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EntityProfile {
    pub entity_id:     EntityId,
    pub baseline:      EntityFeatures,
    pub variance:      [f64; EntityFeatures::DIM],
    m2:                [f64; EntityFeatures::DIM],
    pub obs_count:     u64,
    pub score_history: Vec<f64>,
    pub first_seen:    DateTime<Utc>,
    pub last_seen:     DateTime<Utc>,
}

impl EntityProfile {
    pub fn new(entity_id: EntityId) -> Self {
        let now = Utc::now();
        Self {
            entity_id,
            baseline:      EntityFeatures::zero(),
            variance:      [1.0; EntityFeatures::DIM],
            m2:            [0.0; EntityFeatures::DIM],
            obs_count:     0,
            score_history: Vec::with_capacity(100),
            first_seen:    now,
            last_seen:     now,
        }
    }

    pub fn update(&mut self, obs: &EntityFeatures) {
        self.obs_count += 1;
        self.last_seen  = Utc::now();

        let obs_arr  = obs.as_array();
        let base_arr = self.baseline.as_array();

        for i in 0..EntityFeatures::DIM {
            let delta  = obs_arr[i] - base_arr[i];
            let delta2 = obs_arr[i] - (base_arr[i] + delta / self.obs_count as f64);
            self.m2[i] += delta * delta2;
            self.variance[i] = if self.obs_count > 1 {
                (self.m2[i] / (self.obs_count - 1) as f64).max(1e-6)
            } else {
                1.0
            };
        }

        let alpha = if self.obs_count < 20 { 0.25 } else { 0.02 };
        self.baseline.update_ema(obs, alpha);
    }

    pub fn compute_anomaly_score(&self, obs: &EntityFeatures) -> f64 {
        if self.obs_count < 10 { return 0.0; }
        
        let obs_arr = obs.as_array();
        let base_arr = self.baseline.as_array();
        
        let mut squared_dist = 0.0;
        for i in 0..EntityFeatures::DIM {
            let diff = obs_arr[i] - base_arr[i];
            squared_dist += (diff * diff) / self.variance[i].max(1e-6);
        }
        
        let mahalanobis = (squared_dist / EntityFeatures::DIM as f64).sqrt();
        
        // Sigmoid mapping to [0, 1]
        1.0 / (1.0 + (-mahalanobis + 4.0).exp())
    }
}

// ─── UEBA Engine ──────────────────────────────────────────────────────────────

pub struct UebaEngine {
    profiles: RwLock<HashMap<EntityId, EntityProfile>>,
    global_threshold: f64,
}

impl UebaEngine {
    pub fn new() -> Self {
        Self {
            profiles: RwLock::new(HashMap::new()),
            global_threshold: 0.85,
        }
    }

    pub fn ingest(&self, entity_id: EntityId, features: EntityFeatures) -> Option<f64> {
        let mut profiles = self.profiles.write().unwrap();
        let profile = profiles.entry(entity_id.clone())
            .or_insert_with(|| EntityProfile::new(entity_id));

        let score = profile.compute_anomaly_score(&features);
        profile.update(&features);
        
        if score > self.global_threshold {
            info!("🚨 UEBA Anomaly Detected for {}: score={:.4}", profile.entity_id, score);
        }
        
        Some(score)
    }
}
