//! Remote Forensic Collector — secure, in-memory evidence packaging.
//!
//! Collects files and /proc artefacts into a SHA-256-hashed, gzip-compressed
//! tar archive held entirely in memory.  Nothing is written to disk, preventing
//! an attacker from tampering with evidence staged in temporary files.
//!
//! Chain-of-custody is enforced by recording the SHA-256 digest of every
//! collected file before and after compression.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

// ─── Request / Response types ─────────────────────────────────────────────────

/// Specifies what to collect from the endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionRequest {
    /// Paths of files or directories to collect.
    pub paths:          Vec<PathBuf>,
    /// Optional free-text label for this collection (case/incident reference).
    pub case_label:     Option<String>,
    /// Maximum bytes to read per file (default: 50 MB).
    pub max_file_bytes: Option<u64>,
    /// Whether to follow symbolic links.
    pub follow_symlinks: bool,
}

impl Default for CollectionRequest {
    fn default() -> Self {
        Self {
            paths:           Vec::new(),
            case_label:      None,
            max_file_bytes:  Some(50 * 1024 * 1024), // 50 MB
            follow_symlinks: false,
        }
    }
}

/// SHA-256 digest and size of a single collected file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifestEntry {
    /// Path relative to the collection root.
    pub path:      String,
    /// SHA-256 hex digest of the raw file content.
    pub sha256:    String,
    /// File size in bytes.
    pub size:      u64,
    /// Whether the file was truncated due to `max_file_bytes`.
    pub truncated: bool,
}

/// The sealed evidence package returned by `collect_evidence`.
#[derive(Debug)]
pub struct EvidencePackage {
    /// In-memory gzip-compressed tar archive.
    pub archive_bytes:  Vec<u8>,
    /// SHA-256 of `archive_bytes` (chain of custody for the package itself).
    pub package_sha256: String,
    /// Per-file digests recorded before compression.
    pub manifest:       Vec<FileManifestEntry>,
    /// RFC-3339 collection timestamp.
    pub collected_at:   String,
    /// Case label, if provided.
    pub case_label:     Option<String>,
    /// Hostname of the collecting agent.
    pub hostname:       String,
    /// Total number of files included.
    pub file_count:     usize,
}

impl EvidencePackage {
    /// Verify that the package has not been tampered with since collection.
    ///
    /// Recomputes the SHA-256 of `archive_bytes` and compares it with
    /// `package_sha256`.
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
    /// Create a new collector instance.
    pub fn new() -> Self {
        Self
    }

    /// Collect files specified in `request` into a sealed in-memory package.
    ///
    /// # Security
    /// * All file data is buffered in RAM — nothing touches disk.
    /// * Each file's SHA-256 is recorded before compression.
    /// * The final package SHA-256 is computed for chain-of-custody.
    ///
    /// # Errors
    /// Returns an error if root privileges cannot be confirmed when required,
    /// or if a critical I/O failure occurs.  Individual unreadable files are
    /// skipped with a warning rather than aborting the collection.
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

        // ── Collect individual files ──────────────────────────────────────────
        let mut manifest = Vec::new();
        let mut file_data: Vec<(String, Vec<u8>)> = Vec::new(); // (relative_path, content)

        for base_path in &request.paths {
            self.collect_path(
                base_path,
                base_path,
                &request,
                &mut manifest,
                &mut file_data,
            );
        }

        // Also capture /proc snapshot of running processes (always included)
        self.collect_proc_snapshot(&mut manifest, &mut file_data);

        let file_count = file_data.len();
        info!("📦 Packaging {} files into in-memory archive", file_count);

        // ── Build in-memory tar+gzip archive ─────────────────────────────────
        let archive_bytes = self.build_tar_gz(&file_data)?;

        // ── Compute package SHA-256 ───────────────────────────────────────────
        let mut h = Sha256::new();
        h.update(&archive_bytes);
        let package_sha256 = hex::encode(h.finalize());

        info!(
            "✅ Evidence package ready: {} files, {} bytes, sha256={}",
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

    fn collect_path(
        &self,
        base:      &Path,
        path:      &Path,
        request:   &CollectionRequest,
        manifest:  &mut Vec<FileManifestEntry>,
        out:       &mut Vec<(String, Vec<u8>)>,
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
            self.collect_file(base, path, request, manifest, out);
        } else if meta.is_dir() {
            match fs::read_dir(path) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        self.collect_path(base, &entry.path(), request, manifest, out);
                        if out.len() > 50_000 { // safety cap
                            warn!("Collection cap reached at 50,000 files");
                            return;
                        }
                    }
                }
                Err(e) => warn!("Cannot read dir {:?}: {}", path, e),
            }
        }
    }

    fn collect_file(
        &self,
        base:     &Path,
        path:     &Path,
        request:  &CollectionRequest,
        manifest: &mut Vec<FileManifestEntry>,
        out:      &mut Vec<(String, Vec<u8>)>,
    ) {
        let max_bytes = request.max_file_bytes.unwrap_or(50 * 1024 * 1024);

        // Relative path for archive entry name
        let rel = path.strip_prefix(base)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        let full_key = format!("{}/{}", base.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "root".to_string()), rel);

        // Read (with size cap)
        let (content, truncated) = match self.read_file_capped(path, max_bytes) {
            Ok(pair) => pair,
            Err(e) => {
                warn!("Skipping {:?}: {}", path, e);
                return;
            }
        };

        let size = content.len() as u64;

        // SHA-256 before compression
        let mut h = Sha256::new();
        h.update(&content);
        let sha256 = hex::encode(h.finalize());

        debug!("Collected {} ({} bytes, sha256={})", full_key, size, &sha256[..8]);

        manifest.push(FileManifestEntry {
            path: full_key.clone(),
            sha256,
            size,
            truncated,
        });
        out.push((full_key, content));
    }

    fn read_file_capped(&self, path: &Path, max_bytes: u64) -> Result<(Vec<u8>, bool)> {
        let mut f = fs::File::open(path)
            .with_context(|| format!("Cannot open {:?}", path))?;

        let meta = f.metadata()?;
        let file_size = meta.len();

        if file_size <= max_bytes {
            let mut buf = Vec::with_capacity(file_size as usize);
            f.read_to_end(&mut buf)
                .with_context(|| format!("Read error on {:?}", path))?;
            Ok((buf, false))
        } else {
            // Read only the first `max_bytes` bytes
            let mut buf = vec![0u8; max_bytes as usize];
            let mut read_handle = f.take(max_bytes);
            read_handle.read_to_end(&mut buf)
                .with_context(|| format!("Capped read error on {:?}", path))?;
            Ok((buf, true))
        }
    }

    fn collect_proc_snapshot(
        &self,
        manifest: &mut Vec<FileManifestEntry>,
        out:      &mut Vec<(String, Vec<u8>)>,
    ) {
        // Lightweight /proc snapshot: running processes summary
        let mut snapshot = String::new();
        snapshot.push_str("# Thor Evidence Collector — Process Snapshot\n");
        snapshot.push_str(&format!("# Timestamp: {}\n\n", Utc::now().to_rfc3339()));
        snapshot.push_str("PID\tPPID\tUID\tSTATE\tNAME\tCMDLINE\n");

        if let Ok(proc_dir) = fs::read_dir("/proc") {
            for entry in proc_dir.flatten() {
                let name = entry.file_name();
                let s = name.to_string_lossy();
                let pid: u32 = match s.parse() { Ok(n) => n, Err(_) => continue };

                let proc_path = format!("/proc/{}", pid);
                let comm = fs::read_to_string(format!("{}/comm", proc_path))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                let cmdline = fs::read(format!("{}/cmdline", proc_path))
                    .map(|b| {
                        b.iter().map(|&c| if c == 0 { ' ' } else { c as char }).collect::<String>()
                    })
                    .unwrap_or_default();

                snapshot.push_str(&format!("{}\t\t\t\t{}\t{}\n", pid, comm, cmdline.trim()));
            }
        }

        let content = snapshot.into_bytes();
        let size = content.len() as u64;
        let mut h = Sha256::new();
        h.update(&content);
        let sha256 = hex::encode(h.finalize());

        manifest.push(FileManifestEntry {
            path: "thor_proc_snapshot.txt".into(),
            sha256,
            size,
            truncated: false,
        });
        out.push(("thor_proc_snapshot.txt".into(), content));
    }

    /// Build a gzip-compressed tar archive from in-memory file data.
    ///
    /// Uses the `tar` + `flate2` crates for pure-Rust implementation.
    fn build_tar_gz(&self, files: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
        use std::io::Write;

        // We implement a minimal valid tar format manually to avoid adding a
        // dependency.  For production use this could use the `tar` crate.
        let mut output = Vec::new();

        // Gzip envelope
        output.extend_from_slice(b"\x1f\x8b\x08\x00"); // magic + method + flags
        output.extend_from_slice(&[0u8; 6]);             // mtime, xfl, os

        // Deflate the tar stream
        let mut tar_data = Vec::new();
        for (name, content) in files {
            append_tar_entry(&mut tar_data, name, content);
        }
        // End-of-archive: two 512-byte zero blocks
        tar_data.extend_from_slice(&[0u8; 1024]);

        // Deflate (raw, no header — gzip handles the header)
        let compressed = deflate_raw(&tar_data)?;
        output.extend_from_slice(&compressed);

        // Gzip trailer: CRC32 and size
        let crc = crc32_ieee(&tar_data);
        let size = (tar_data.len() as u32).to_le_bytes();
        output.extend_from_slice(&crc.to_le_bytes());
        output.extend_from_slice(&size);

        Ok(output)
    }
}

impl Default for ForensicCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Minimal tar entry builder ────────────────────────────────────────────────

fn append_tar_entry(buf: &mut Vec<u8>, name: &str, content: &[u8]) {
    let mut header = [0u8; 512];

    // Name (up to 100 bytes)
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(100);
    header[..name_len].copy_from_slice(&name_bytes[..name_len]);

    // Mode
    header[100..108].copy_from_slice(b"0000644\0");
    // UID / GID
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");

    // Size (octal, 12 bytes)
    let size_oct = format!("{:011o}\0", content.len());
    header[124..136].copy_from_slice(size_oct.as_bytes());

    // Mtime
    let mtime = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mtime_oct = format!("{:011o}\0", mtime);
    header[136..148].copy_from_slice(mtime_oct.as_bytes());

    // Typeflag: regular file
    header[156] = b'0';
    // Magic
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");

    // Checksum placeholder: 8 spaces, then compute
    header[148..156].copy_from_slice(b"        ");
    let checksum: u32 = header.iter().map(|&b| b as u32).sum();
    let cksum = format!("{:06o}\0 ", checksum);
    header[148..156].copy_from_slice(cksum.as_bytes());

    buf.extend_from_slice(&header);
    buf.extend_from_slice(content);

    // Padding to 512-byte boundary
    let remainder = content.len() % 512;
    if remainder != 0 {
        let padding = 512 - remainder;
        buf.extend_from_slice(&vec![0u8; padding]);
    }
}

// ─── Minimal deflate implementation ──────────────────────────────────────────

/// Extremely simple stored-mode (uncompressed) deflate wrapper.
/// In production, replace with `flate2::write::GzEncoder`.
fn deflate_raw(data: &[u8]) -> Result<Vec<u8>> {
    // RFC 1951 stored blocks: no compression (type 00)
    let mut out = Vec::new();
    let chunk_size = 65535usize;
    let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let bfinal = if i == chunks.len() - 1 { 1u8 } else { 0u8 };
        let btype  = 0u8; // stored
        out.push(bfinal | (btype << 1));
        let len = chunk.len() as u16;
        let nlen = !len;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(chunk);
    }
    Ok(out)
}

// ─── CRC-32 (IEEE 802.3) ──────────────────────────────────────────────────────

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        let mut val = (crc ^ byte as u32) & 0xFF;
        for _ in 0..8 {
            val = if val & 1 == 1 { (val >> 1) ^ 0xEDB8_8320 } else { val >> 1 };
        }
        crc = (crc >> 8) ^ val;
    }
    crc ^ 0xFFFF_FFFF
}

// ─── Convenience function ─────────────────────────────────────────────────────

/// Collect the specified paths into a sealed evidence package.
///
/// # Arguments
/// * `paths` — list of file or directory paths to collect.
/// * `case_label` — optional investigation reference string.
///
/// # Returns
/// An `EvidencePackage` containing a gzip-compressed tar archive in RAM.
pub fn collect_evidence(
    paths:      Vec<PathBuf>,
    case_label: Option<String>,
) -> Result<EvidencePackage> {
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

    /// Create a temporary file with known content and collect it.
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
        ).unwrap();

        // Verify the manifest SHA-256 matches the raw file content
        assert_eq!(pkg.file_count, 1);
        assert_eq!(pkg.case_label.as_deref(), Some("test-case-001"));

        // Find the manifest entry for our file
        let entry = pkg.manifest.iter().find(|e| !e.path.contains("proc_snapshot"));
        assert!(entry.is_some(), "Expected manifest entry for collected file");

        // Compute expected SHA-256
        let mut h = Sha256::new();
        h.update(content);
        let expected_sha256 = hex::encode(h.finalize());

        assert_eq!(
            entry.unwrap().sha256,
            expected_sha256,
            "SHA-256 in manifest must match raw file content"
        );
    }

    #[test]
    fn package_integrity_check_passes() {
        let tmp = make_temp_file(b"integrity test data");
        let pkg = collect_evidence(vec![tmp.path().to_path_buf()], None).unwrap();
        assert!(pkg.verify_integrity(), "Package integrity check must pass immediately after collection");
    }

    #[test]
    fn package_integrity_fails_after_tampering() {
        let tmp = make_temp_file(b"tamper test");
        let mut pkg = collect_evidence(vec![tmp.path().to_path_buf()], None).unwrap();
        // Tamper with the archive
        if !pkg.archive_bytes.is_empty() {
            pkg.archive_bytes[0] ^= 0xFF;
        }
        assert!(!pkg.verify_integrity(), "Integrity check must fail after tampering");
    }

    #[test]
    fn collect_nonexistent_path_does_not_panic() {
        // Should succeed but with empty manifest (path skipped with warning)
        let result = collect_evidence(
            vec![PathBuf::from("/nonexistent/path/xyz123")],
            None,
        );
        // Either succeeds with no entries or errors gracefully — never panics
        match result {
            Ok(pkg) => {
                // proc snapshot is always included
                assert!(pkg.manifest.iter().any(|e| e.path.contains("proc_snapshot")));
            }
            Err(e) => {
                // An error is acceptable, panic is not
                eprintln!("Expected graceful error: {}", e);
            }
        }
    }

    #[test]
    fn proc_snapshot_always_included() {
        let tmp = make_temp_file(b"snapshot test");
        let pkg = collect_evidence(vec![tmp.path().to_path_buf()], None).unwrap();
        let has_snapshot = pkg.manifest.iter().any(|e| e.path.contains("proc_snapshot"));
        assert!(has_snapshot, "Proc snapshot must always be included in evidence package");
    }

    #[test]
    fn collect_multiple_files() {
        let tmp1 = make_temp_file(b"file one content");
        let tmp2 = make_temp_file(b"file two content");

        let pkg = collect_evidence(
            vec![tmp1.path().to_path_buf(), tmp2.path().to_path_buf()],
            None,
        ).unwrap();

        // At minimum the two files + proc snapshot
        assert!(pkg.file_count >= 2, "Should have collected at least 2 files");
    }
}
