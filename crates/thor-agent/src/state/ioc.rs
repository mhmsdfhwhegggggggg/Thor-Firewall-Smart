//! IOC Database — Bloom filter (O(1) negatives) + DashMap (O(1) positives)
//! Supports: IP addresses, domains, file hashes (SHA256)

use bloomfilter::Bloom;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, debug};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocEntry {
    pub value: String,
    pub ioc_type: IocType,
    pub threat_level: String,
    pub source: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IocType {
    IpAddress,
    Domain,
    FileHash,
    Url,
}

pub struct IocDatabase {
    /// Bloom filter for fast negative checks (if NOT in bloom → definitely not IOC)
    bloom: RwLock<Bloom<String>>,
    /// DashMap for full IOC data (true positives only)
    iocs: DashMap<String, IocEntry>,
    capacity: usize,
}

impl IocDatabase {
    pub fn new(capacity: usize, false_positive_rate: f64) -> Self {
        let bloom = Bloom::new_for_fp_rate(capacity, false_positive_rate);
        info!("🌸 Bloom filter: capacity={}, FPR={}", capacity, false_positive_rate);
        Self {
            bloom: RwLock::new(bloom),
            iocs: DashMap::with_capacity(capacity / 10),
            capacity,
        }
    }

    pub fn insert(&self, ioc: IocEntry) {
        let key = ioc.value.clone();
        self.bloom.write().set(&key);
        self.iocs.insert(key, ioc);
    }

    pub fn bulk_insert_ips(&self, ips: impl IntoIterator<Item = String>, source: &str) -> usize {
        let mut count = 0;
        let mut bloom = self.bloom.write();
        for ip in ips {
            bloom.set(&ip);
            self.iocs.insert(ip.clone(), IocEntry {
                value: ip,
                ioc_type: IocType::IpAddress,
                threat_level: "HIGH".to_string(),
                source: source.to_string(),
                tags: vec!["bulk".to_string()],
            });
            count += 1;
        }
        count
    }

    /// O(1) check — returns None if definitely not an IOC, Some(entry) if positive match
    pub fn check(&self, value: &str) -> Option<IocEntry> {
        // Bloom filter fast path (99% of benign IPs exit here without DashMap lookup)
        if !self.bloom.read().check(&value.to_string()) {
            debug!("Bloom filter negative for: {}", value);
            return None;
        }
        // Confirm in DashMap (eliminates false positives)
        self.iocs.get(value).map(|e| e.clone())
    }

    pub fn remove(&self, value: &str) -> bool {
        // Note: Bloom filters can't remove — only DashMap is cleaned
        self.iocs.remove(value).is_some()
    }

    pub fn len(&self) -> usize { self.iocs.len() }
    pub fn is_empty(&self) -> bool { self.iocs.is_empty() }
}

    pub fn len(&self) -> usize {
        self.iocs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.iocs.is_empty()
    }
}
