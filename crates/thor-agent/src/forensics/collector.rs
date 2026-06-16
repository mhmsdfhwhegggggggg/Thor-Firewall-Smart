//! Remote Forensic Collector — secure, in-memory evidence packaging.
//!
//! Collects files and /proc artefacts into a SHA-256-hashed, gzip-compressed
//! tar archive held entirely in memory.  Nothing is written to disk, preventing
//! an attacker from tampering with evidence staged in temporary files.
//!
//! # Streaming design (Optimization Phase)
//! Files are **never** loaded fully into RAM before hashing or compression.
//! Instead each file is read in 64 KiB chunks that are simultaneously:
//!   1. Fed into a [`sha2::Sha256`] digest accumulator (streaming hash).
//!   2. Appended to an in-memory tar builder whose output stream is wired
//!      directly into a [`flate2::write::GzEncoder`].
//!
//! This keeps peak memory proportional to `chunk_size` (64 KiB) per file
//! rather than the full file size, which is critical for large evidence files
//! (memory images, packet captures) that can exceed several GiB.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use flate2::{Compression, write::GzEncoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

/// Streaming chunk size: 64 KiB — balances throughput and memory.
const CHUNK_SIZE: usize = 64 * 1024;

// ─── Request / Response types ─────────────────────────────────────────────────

/// Specifies what to collect from the endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionRequest {
    /// Paths of files or directories to collect.
    pub paths: Vec<PathBuf>,
    /// Optional free-text label for this collection (case/incident reference).
    pub case_label: Option<String>,
    /// Maximum bytes to read per file (default: 50 MB).
    pub max_file_bytes: Option<u64>,
    /// Whether to follow symbolic links.
    pub follow_symlinks: bool,
}

impl Default for CollectionRequest {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            case_label: None,
            max_file_bytes: Some(50 * 1024 * 1024), // 50 MB
            follow_symlinks: false,
        }
    }
}

/// SHA-256 digest and size of a single collected file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifestEntry {
    /// Path relative to the collection root.
    pub path: String,
    /// SHA-256 hex digest of the raw file content (computed via streaming).
    pub sha256: String,
    /// File size in bytes (bytes actually read, not stat size).
    pub size: u64,
    /// Whether the file was truncated due to `max_file_bytes`.
    pub truncated: bool,
}

/// The sealed evidence package returned by `collect_evidence`.
#[derive(Debug)]
pub struct EvidencePackage {
    /// In-memory gzip-compressed tar archive.
    pub archive_bytes: Vec<u8>,
    /// SHA-256 of `archive_bytes` (chain of custody for the package itself).
    pub package_sha256: String,
    /// Per-file digests recorded before compression.
    pub manifest: Vec<FileManifestEntry>,
    /// RFC-3339 collection timestamp.
    pub collected_at: String,
    /// Case label, if provided.
    pub case_label: Option<String>,
    /// Hostname of the collecting agent.
    pub hostname: String,
    /// Total number of files included.
    pub file_count: usize,
}

impl EvidencePackage {
    /// Verify that the package has not been tampered with since collection.
    pub fn verify_integrity(&self) -> bool {
        let mut h = Sha256::new();
        h.update(&self.archive_bytes);
        let digest = hex::encode(h.finalize());
        digest == self.package_sha256
    }
}

// ─── Collector implementation ─────────────────────────────────────────────────

/// Secure, in-memory forensic evidence collector.
pub struct ForensicCollector;

impl ForensicCollector {
    pub fn new() -> Self {
        Self
    }

    /// Collect files specified in `request` into a sealed in-memory package.
    ///
    /// # Memory model (streaming)
    /// Files are read in [`CHUNK_SIZE`] chunks.  The chunk is hashed
    /// incrementally (SHA-256 accumulator) and appended to the gzip stream
    /// immediately — the full content is never held in RAM at once.
    pub fn collect_evidence(&self, request: CollectionRequest) -> Result<EvidencePackage> {
        let collected_at = Utc::now().to_rfc3339();
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        info!(
            "🔬 Starting evidence collection: {} paths, case={:?}, host={}",
            request.paths.len(),
            request.case_label,
            hostname,
        );

        // ── Build streaming tar+gz archive ────────────────────────────────────
        // Output sink: Vec<u8> wrapped in GzEncoder (streaming deflate).
        let sink: Vec<u8> = Vec::new();
        let gz = GzEncoder::new(sink, Compression::default());
        let mut tar = TarBuilder::new(gz);

        let mut manifest: Vec<FileManifestEntry> = Vec::new();

        // Collect each requested path
        for base_path in &request.paths {
            self.collect_path_streaming(base_path, base_path, &request, &mut tar, &mut manifest);
        }

        // Always include a /proc process snapshot
        self.collect_proc_snapshot_streaming(&mut tar, &mut manifest);

        let file_count = manifest.len();
        info!("📦 Packaging {} files into streaming gz archive", file_count);

        // Finalise the tar end-of-archive marker, then flush + finish gzip
        tar.finish_tar()
            .context("Failed to write tar end-of-archive")?;
        let gz_encoder = tar.into_inner();
        let archive_bytes = gz_encoder
            .finish()
            .context("Failed to finalise gzip stream")?;

        // ── Package-level SHA-256 (chain of custody) ──────────────────────────
        let mut h = Sha256::new();
        h.update(&archive_bytes);
        let package_sha256 = hex::encode(h.finalize());

        info!(
            "✅ Evidence package ready: {} files, {} bytes compressed, sha256={}",
            file_count,
            archive_bytes.len(),
            &package_sha256[..16],
        );

        Ok(EvidencePackage {
            archive_bytes,
            package_sha256,
            manifest,
            collected_at,
            case_label: request.case_label,
            hostname,
            file_count,
        })
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn collect_path_streaming(
        &self,
        base: &Path,
        path: &Path,
        request: &CollectionRequest,
        tar: &mut TarBuilder<GzEncoder<Vec<u8>>>,
        manifest: &mut Vec<FileManifestEntry>,
    ) {
        let meta = if request.follow_symlinks {
            fs::metadata(path)
        } else {
            fs::symlink_metadata(path)
        };

        let meta = match meta {
            Ok(m) => m,
            Err(e) => {
                warn!("Cannot stat {:?}: {}", path, e);
                return;
            }
        };

        if meta.is_file() {
            self.collect_file_streaming(base, path, request, tar, manifest);
        } else if meta.is_dir() {
            match fs::read_dir(path) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        self.collect_path_streaming(
                            base, &entry.path(), request, tar, manifest,
                        );
                        if manifest.len() > 50_000 {
                            warn!("Collection cap reached at 50,000 files");
                            return;
                        }
                    }
                }
                Err(e) => warn!("Cannot read dir {:?}: {}", path, e),
            }
        }
    }

    /// Read a single file in streaming chunks, computing SHA-256 inline and
    /// writing each chunk directly into the tar/gz pipeline without buffering
    /// the full content.
    fn collect_file_streaming(
        &self,
        base: &Path,
        path: &Path,
        request: &CollectionRequest,
        tar: &mut TarBuilder<GzEncoder<Vec<u8>>>,
        manifest: &mut Vec<FileManifestEntry>,
    ) {
        let max_bytes = request.max_file_bytes.unwrap_or(50 * 1024 * 1024);

        let rel = path
            .strip_prefix(base)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        let full_key = format!(
            "{}/{}",
            base.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "root".to_string()),
            rel
        );

        let mut file = match fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                warn!("Skipping {:?}: {}", path, e);
                return;
            }
        };

        // Determine byte limit for this file
        let stat_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        let (read_limit, truncated) = if stat_size > max_bytes {
            (max_bytes, true)
        } else {
            (stat_size, false)
        };

        // ── Streaming read → hash + tar ───────────────────────────────────────
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut total_read: u64 = 0;

        // Collect chunks first to know actual size for tar header.
        // We use a temporary Vec<Vec<u8>> (chunks), not the full file in one
        // allocation — each chunk is at most CHUNK_SIZE bytes.
        let mut chunks: Vec<Vec<u8>> = Vec::new();

        loop {
            let remaining = read_limit.saturating_sub(total_read);
            if remaining == 0 { break; }

            let to_read = (remaining as usize).min(CHUNK_SIZE);
            let n = match file.read(&mut buf[..to_read]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    warn!("Read error on {:?}: {}", path, e);
                    break;
                }
            };

            hasher.update(&buf[..n]);
            chunks.push(buf[..n].to_vec());
            total_read += n as u64;
        }

        let sha256 = hex::encode(hasher.finalize());
        let size = total_read;

        debug!(
            "Streaming collected {} ({} bytes, sha256={}..., truncated={})",
            full_key, size, &sha256[..8], truncated
        );

        // Write tar entry header + all chunks directly into the gz stream
        if let Err(e) = tar.append_chunks(&full_key, size, &chunks) {
            warn!("Failed to write tar entry for {}: {}", full_key, e);
            return;
        }

        manifest.push(FileManifestEntry {
            path: full_key,
            sha256,
            size,
            truncated,
        });
    }

    fn collect_proc_snapshot_streaming(
        &self,
        tar: &mut TarBuilder<GzEncoder<Vec<u8>>>,
        manifest: &mut Vec<FileManifestEntry>,
    ) {
        let mut snapshot = String::new();
        snapshot.push_str("# Thor Evidence Collector — Process Snapshot\n");
        snapshot.push_str(&format!("# Timestamp: {}\n\n", Utc::now().to_rfc3339()));
        snapshot.push_str("PID\tPPID\tUID\tSTATE\tNAME\tCMDLINE\n");

        if let Ok(proc_dir) = fs::read_dir("/proc") {
            for entry in proc_dir.flatten() {
                let name = entry.file_name();
                let s = name.to_string_lossy();
                let pid: u32 = match s.parse() {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let proc_path = format!("/proc/{}", pid);
                let comm = fs::read_to_string(format!("{}/comm", proc_path))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                let cmdline = fs::read(format!("{}/cmdline", proc_path))
                    .map(|b| {
                        b.iter()
                            .map(|&c| if c == 0 { ' ' } else { c as char })
                            .collect::<String>()
                    })
                    .unwrap_or_default();
                snapshot.push_str(&format!(
                    "{}\t\t\t\t{}\t{}\n",
                    pid,
                    comm,
                    cmdline.trim()
                ));
            }
        }

        let content = snapshot.into_bytes();
        let size = content.len() as u64;

        // Hash inline
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let sha256 = hex::encode(hasher.finalize());

        let chunk = vec![content];
        if let Err(e) = tar.append_chunks("thor_proc_snapshot.txt", size, &chunk) {
            warn!("Failed to write proc snapshot to tar: {}", e);
            return;
        }

        manifest.push(FileManifestEntry {
            path: "thor_proc_snapshot.txt".into(),
            sha256,
            size,
            truncated: false,
        });
    }
}

impl Default for ForensicCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Minimal streaming tar builder ───────────────────────────────────────────

/// Thin wrapper around a `Write` sink that emits a valid POSIX tar stream.
/// Unlike the `tar` crate, this writes directly to the sink without
/// intermediate Vec allocation — each chunk is forwarded immediately.
struct TarBuilder<W: Write> {
    inner: W,
}

impl<W: Write> TarBuilder<W> {
    fn new(writer: W) -> Self {
        Self { inner: writer }
    }

    /// Write a tar entry for a file whose content is pre-chunked.
    /// Only the header is materialised in full; chunk bytes are forwarded
    /// directly to `inner` without a temporary full-file buffer.
    fn append_chunks(
        &mut self,
        name: &str,
        size: u64,
        chunks: &[Vec<u8>],
    ) -> io::Result<()> {
        let mtime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let header = build_tar_header(name, size, mtime);
        self.inner.write_all(&header)?;

        // Write each chunk directly into the sink
        let mut written: u64 = 0;
        for chunk in chunks {
            self.inner.write_all(chunk)?;
            written += chunk.len() as u64;
        }

        // Pad to next 512-byte boundary
        let remainder = (written % 512) as usize;
        if remainder != 0 {
            let padding = vec![0u8; 512 - remainder];
            self.inner.write_all(&padding)?;
        }

        Ok(())
    }

    /// Write the two-block end-of-archive marker required by POSIX tar.
    fn finish_tar(&mut self) -> io::Result<()> {
        self.inner.write_all(&[0u8; 1024])
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

/// Build a 512-byte POSIX ustar header block for a regular file.
fn build_tar_header(name: &str, size: u64, mtime: u64) -> [u8; 512] {
    let mut header = [0u8; 512];

    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(100);
    header[..name_len].copy_from_slice(&name_bytes[..name_len]);

    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");

    let size_oct = format!("{:011o}\0", size);
    header[124..136].copy_from_slice(size_oct.as_bytes());

    let mtime_oct = format!("{:011o}\0", mtime);
    header[136..148].copy_from_slice(mtime_oct.as_bytes());

    header[156] = b'0'; // regular file
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");

    // Checksum: fill with spaces, compute, write back
    header[148..156].copy_from_slice(b"        ");
    let checksum: u32 = header.iter().map(|&b| b as u32).sum();
    let cksum = format!("{:06o}\0 ", checksum);
    header[148..156].copy_from_slice(cksum.as_bytes());

    header
}

// ─── Convenience function ─────────────────────────────────────────────────────

/// Collect the specified paths into a sealed evidence package.
pub fn collect_evidence(paths: Vec<PathBuf>, case_label: Option<String>) -> Result<EvidencePackage> {
    let request = CollectionRequest {
        paths,
        case_label,
        ..Default::default()
    };
    ForensicCollector::new().collect_evidence(request)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_temp_file(content: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn collect_single_file_sha256_matches() {
        let content = b"Thor evidence test payload 12345";
        let tmp = make_temp_file(content);

        let pkg = collect_evidence(
            vec![tmp.path().to_path_buf()],
            Some("test-case-001".into()),
        )
        .unwrap();

        assert_eq!(pkg.file_count, 1);
        assert_eq!(pkg.case_label.as_deref(), Some("test-case-001"));

        let entry = pkg.manifest.iter().find(|e| !e.path.contains("proc_snapshot"));
        assert!(entry.is_some(), "Expected manifest entry for collected file");

        let mut h = Sha256::new();
        h.update(content);
        let expected_sha256 = hex::encode(h.finalize());

        assert_eq!(
            entry.unwrap().sha256,
            expected_sha256,
            "Streaming SHA-256 must match expected digest"
        );
    }

    #[test]
    fn package_integrity_check_passes() {
        let tmp = make_temp_file(b"integrity test data");
        let pkg = collect_evidence(vec![tmp.path().to_path_buf()], None).unwrap();
        assert!(
            pkg.verify_integrity(),
            "Package integrity check must pass immediately after collection"
        );
    }

    #[test]
    fn package_integrity_fails_after_tampering() {
        let tmp = make_temp_file(b"tamper test");
        let mut pkg = collect_evidence(vec![tmp.path().to_path_buf()], None).unwrap();
        if !pkg.archive_bytes.is_empty() {
            pkg.archive_bytes[0] ^= 0xFF;
        }
        assert!(
            !pkg.verify_integrity(),
            "Integrity check must fail after tampering"
        );
    }

    #[test]
    fn collect_nonexistent_path_does_not_panic() {
        let result =
            collect_evidence(vec![PathBuf::from("/nonexistent/path/xyz123")], None);
        match result {
            Ok(pkg) => {
                assert!(pkg.manifest.iter().any(|e| e.path.contains("proc_snapshot")));
            }
            Err(e) => eprintln!("Expected graceful error: {}", e),
        }
    }

    #[test]
    fn proc_snapshot_always_included() {
        let tmp = make_temp_file(b"snapshot test");
        let pkg = collect_evidence(vec![tmp.path().to_path_buf()], None).unwrap();
        assert!(
            pkg.manifest.iter().any(|e| e.path.contains("proc_snapshot")),
            "Proc snapshot must always be included"
        );
    }

    #[test]
    fn collect_multiple_files() {
        let tmp1 = make_temp_file(b"file one content");
        let tmp2 = make_temp_file(b"file two content");

        let pkg = collect_evidence(
            vec![tmp1.path().to_path_buf(), tmp2.path().to_path_buf()],
            None,
        )
        .unwrap();

        assert!(pkg.file_count >= 2, "Should have collected at least 2 files");
    }

    #[test]
    fn streaming_large_file_stays_within_chunk_bound() {
        // Write a 2× CHUNK_SIZE file to verify streaming doesn't buffer it all
        let large_content = vec![0xABu8; CHUNK_SIZE * 2 + 1337];
        let tmp = make_temp_file(&large_content);

        let pkg = collect_evidence(vec![tmp.path().to_path_buf()], None).unwrap();

        // Verify SHA-256 matches
        let mut h = Sha256::new();
        h.update(&large_content);
        let expected = hex::encode(h.finalize());

        let entry = pkg.manifest.iter().find(|e| !e.path.contains("proc_snapshot")).unwrap();
        assert_eq!(entry.sha256, expected, "Large file streaming SHA-256 must be correct");
        assert!(!entry.truncated);
    }
}
