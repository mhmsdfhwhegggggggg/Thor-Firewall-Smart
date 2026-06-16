//! File hasher — Blake3 primary, SHA256 for compatibility
//! Blake3 is ~10x faster than SHA256, cryptographically sound.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use tokio::fs;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: String,
    pub blake3_hash: String,
    pub sha256_hash: String,
    pub size: u64,
    pub inode: u64,
    pub permissions: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    pub ctime: i64,
    pub recorded_at: String,
}

pub struct FileHasher;

impl FileHasher {
    /// Hash a single file; returns FileRecord with Blake3 + SHA256
    pub async fn hash_file(path: &Path) -> Result<FileRecord> {
        let path_str = path.to_string_lossy().to_string();

        let meta = fs::metadata(path)
            .await
            .with_context(|| format!("Cannot stat: {}", path_str))?;

        if meta.len() > 512 * 1024 * 1024 {
            // Skip files > 512MB
            anyhow::bail!("File too large to hash: {}", path_str);
        }

        let path_owned = path.to_path_buf();
        let (blake3_hash, sha256_hash) = tokio::task::spawn_blocking(move || {
            hash_file_sync(&path_owned)
        })
        .await
        .context("spawn_blocking failed")??;

        Ok(FileRecord {
            path: path_str,
            blake3_hash,
            sha256_hash,
            size: meta.len(),
            inode: meta.ino(),
            permissions: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            mtime: meta.mtime(),
            ctime: meta.ctime(),
            recorded_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Recursively scan a directory (bounded to 4 levels deep)
    pub async fn scan_directory(dir: &Path) -> HashMap<String, FileRecord> {
        let dir_owned = dir.to_path_buf();
        tokio::task::spawn_blocking(move || scan_dir_sync(&dir_owned, 0))
            .await
            .unwrap_or_default()
    }
}

fn hash_file_sync(path: &Path) -> Result<(String, String)> {
    use sha2::{Digest, Sha256};

    let mut file = std::fs::File::open(path)
        .with_context(|| format!("Cannot open: {}", path.display()))?;

    let mut blake3_hasher = blake3::Hasher::new();
    let mut sha256_hasher = Sha256::new();
    let mut buf = vec![0u8; 65536];

    loop {
        let n = file.read(&mut buf).context("Read error")?;
        if n == 0 {
            break;
        }
        blake3_hasher.update(&buf[..n]);
        sha256_hasher.update(&buf[..n]);
    }

    let blake3_hash = blake3_hasher.finalize().to_hex().to_string();
    let sha256_hash = format!("{:x}", sha256_hasher.finalize());

    Ok((blake3_hash, sha256_hash))
}

fn scan_dir_sync(dir: &Path, depth: usize) -> HashMap<String, FileRecord> {
    const MAX_DEPTH: usize = 4;
    let mut records = HashMap::new();

    if depth > MAX_DEPTH {
        return records;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("Cannot read dir {:?}: {}", dir, e);
            return records;
        }
    };

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let fname = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        // Skip hidden swap/temp files
        if fname.starts_with('.') && (fname.ends_with(".swp") || fname.ends_with('~')) {
            continue;
        }

        if path.is_symlink() || path.is_file() {
            match hash_and_stat(&path) {
                Ok(rec) => {
                    records.insert(path.to_string_lossy().to_string(), rec);
                }
                Err(e) => warn!("Cannot hash {:?}: {}", path, e),
            }
        } else if path.is_dir() {
            let sub = scan_dir_sync(&path, depth + 1);
            records.extend(sub);
        }
    }

    records
}

fn hash_and_stat(path: &Path) -> Result<FileRecord> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::metadata(path)?;

    if meta.len() > 100 * 1024 * 1024 {
        // For large files (>100MB), use mtime+size as fingerprint
        return Ok(FileRecord {
            path: path.to_string_lossy().to_string(),
            blake3_hash: format!("size:{}:mtime:{}", meta.len(), meta.mtime()),
            sha256_hash: "skipped:too_large".to_string(),
            size: meta.len(),
            inode: meta.ino(),
            permissions: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            mtime: meta.mtime(),
            ctime: meta.ctime(),
            recorded_at: chrono::Utc::now().to_rfc3339(),
        });
    }

    let (blake3_hash, sha256_hash) = hash_file_sync(path)?;

    Ok(FileRecord {
        path: path.to_string_lossy().to_string(),
        blake3_hash,
        sha256_hash,
        size: meta.len(),
        inode: meta.ino(),
        permissions: meta.mode(),
        uid: meta.uid(),
        gid: meta.gid(),
        mtime: meta.mtime(),
        ctime: meta.ctime(),
        recorded_at: chrono::Utc::now().to_rfc3339(),
    })
}
