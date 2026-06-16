//! FIM Baseline — persistent, tamper-evident file record store (sled embedded DB)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

use super::hasher::FileRecord;

pub struct FimBaseline {
    db: sled::Db,
}

impl FimBaseline {
    pub fn open(path: &str) -> Result<Self> {
        let db = sled::Config::new()
            .path(path)
            .mode(sled::Mode::HighThroughput)
            .open()
            .context("Failed to open FIM baseline DB")?;
        info!("📁 FIM baseline DB: {} (existing entries: {})", path, db.len());
        Ok(Self { db })
    }

    pub fn insert(&self, path: &str, record: &FileRecord) -> Result<()> {
        let val = serde_json::to_vec(record)?;
        self.db.insert(path.as_bytes(), val)?;
        Ok(())
    }

    pub fn get(&self, path: &str) -> Result<Option<FileRecord>> {
        match self.db.get(path.as_bytes())? {
            Some(v) => Ok(Some(serde_json::from_slice(&v)?)),
            None => Ok(None),
        }
    }

    pub fn remove(&self, path: &str) -> Result<()> {
        self.db.remove(path.as_bytes())?;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.db.len()
    }

    pub fn is_empty(&self) -> bool {
        self.db.is_empty()
    }

    /// Return all file paths that start with the given directory prefix
    pub fn files_under(&self, dir: &Path) -> Result<Option<Vec<String>>> {
        let prefix = dir.to_string_lossy().to_string();
        let mut paths = Vec::new();
        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (k, _) = item?;
            if let Ok(p) = std::str::from_utf8(&k) {
                paths.push(p.to_string());
            }
        }
        if paths.is_empty() {
            Ok(None)
        } else {
            Ok(Some(paths))
        }
    }

    /// Export all baseline records for reporting
    pub fn export_all(&self) -> Vec<FileRecord> {
        self.db
            .iter()
            .filter_map(|r| r.ok())
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    }

    /// Count records by directory prefix
    pub fn count_under(&self, prefix: &str) -> usize {
        self.db.scan_prefix(prefix.as_bytes()).count()
    }
}
