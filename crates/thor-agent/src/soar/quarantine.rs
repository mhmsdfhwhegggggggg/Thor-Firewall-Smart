//! File Quarantine — atomic move to quarantine dir with metadata preservation

use anyhow::{Context, Result};
use chrono::Utc;
use sha2::{Sha256, Digest};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub original_path: String,
    pub quarantine_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub quarantined_at: String,
    pub pid: Option<u32>,
    pub alert_id: String,
}

pub struct FileQuarantiner {
    quarantine_dir: PathBuf,
}

impl FileQuarantiner {
    pub fn new(quarantine_dir: impl Into<PathBuf>) -> Self {
        Self { quarantine_dir: quarantine_dir.into() }
    }

    pub async fn quarantine_file(
        &self,
        file_path: &str,
        pid: Option<u32>,
        alert_id: &str,
    ) -> Result<QuarantineRecord> {
        info!("🔒 Quarantining file: {}", file_path);
        let qdir = self.quarantine_dir.clone();
        let fpath = file_path.to_string();
        let aid = alert_id.to_string();

        tokio::task::spawn_blocking(move || {
            // Ensure quarantine dir exists
            fs::create_dir_all(&qdir).context("Cannot create quarantine dir")?;

            let src = PathBuf::from(&fpath);
            if !src.exists() {
                return Err(anyhow::anyhow!("File not found: {}", fpath));
            }

            // Calculate SHA256 before moving
            let sha256 = hash_file(&src)?;
            let size_bytes = src.metadata().map(|m| m.len()).unwrap_or(0);

            // Quarantine filename: timestamp_sha256prefix_filename
            let ts = Utc::now().format("%Y%m%d_%H%M%S");
            let fname = src.file_name().and_then(|n| n.to_str()).unwrap_or("unknown");
            let qname = format!("{}_{:.8}_{}", ts, sha256, fname);
            let dst = qdir.join(&qname);

            // Atomic move (same filesystem) or copy+delete
            fs::rename(&src, &dst)
                .or_else(|_| {
                    fs::copy(&src, &dst)?;
                    fs::remove_file(&src)?;
                    Ok::<(), std::io::Error>(())
                })
                .context("Failed to quarantine file")?;

            // Write metadata sidecar
            let record = QuarantineRecord {
                original_path: fpath.clone(),
                quarantine_path: dst.to_string_lossy().to_string(),
                sha256: sha256.clone(),
                size_bytes,
                quarantined_at: Utc::now().to_rfc3339(),
                pid,
                alert_id: aid,
            };
            let meta_path = dst.with_extension("json");
            let meta_json = serde_json::to_string_pretty(&record)?;
            fs::write(&meta_path, meta_json).context("Failed to write quarantine metadata")?;

            info!("✅ File quarantined: {} → {} (sha256:{})", fpath, dst.display(), &sha256[..16]);
            Ok(record)
        }).await.context("spawn_blocking failed")?
    }
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).context("Cannot open file for hashing")?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}
