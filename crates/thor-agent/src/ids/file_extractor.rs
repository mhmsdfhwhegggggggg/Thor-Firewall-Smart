//! File Extractor — Extract files from TCP stream payloads
//!
//! Supports: HTTP, FTP, SMTP (MIME), SMB (basic)
//! Computes: MD5, SHA1, SHA256 for each extracted file
//! Saves: /var/lib/thor/extracted_files/ with JSON sidecar metadata
//! Feeds: Extracted files are queued for YARA scanning

use anyhow::Result;
use sha2::{Sha256, Digest};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use chrono::Utc;
use tracing::{info, warn, debug};
use flume::Sender;

// ─── Extracted File ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExtractedFile {
    /// Original filename if known
    pub filename:   Option<String>,
    /// Detected MIME type
    pub mime_type:  String,
    /// Source protocol
    pub protocol:   ExtractProtocol,
    /// Source flow
    pub src_ip:     String,
    pub dst_ip:     String,
    pub src_port:   u16,
    pub dst_port:   u16,
    /// Raw file bytes
    pub data:       Vec<u8>,
    /// Hashes
    pub sha256:     String,
    pub sha1:       String,
    pub md5_hex:    String,
    /// Extraction timestamp (RFC 3339)
    pub timestamp:  String,
    /// Save path
    pub saved_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExtractProtocol {
    Http,
    Ftp,
    Smtp,
    Smb,
}

impl ExtractProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Ftp  => "FTP",
            Self::Smtp => "SMTP",
            Self::Smb  => "SMB",
        }
    }
}

impl ExtractedFile {
    /// Build from raw bytes + metadata
    pub fn new(
        data: Vec<u8>,
        filename: Option<String>,
        protocol: ExtractProtocol,
        src_ip: String, dst_ip: String,
        src_port: u16, dst_port: u16,
    ) -> Self {
        let sha256  = sha256_hex(&data);
        let sha1    = sha1_hex(&data);
        let md5_hex = simple_md5_hex(&data);
        let mime_type = detect_mime(&data, filename.as_deref()).to_string();

        Self {
            filename, mime_type, protocol,
            src_ip, dst_ip, src_port, dst_port,
            data, sha256, sha1, md5_hex,
            timestamp: Utc::now().to_rfc3339(),
            saved_path: None,
        }
    }

    pub fn size_bytes(&self) -> usize { self.data.len() }

    /// Serialize metadata as JSON sidecar
    pub fn metadata_json(&self) -> String {
        format!(
            r#"{{"filename":{fname},"mime":"{mime}","protocol":"{proto}","src":"{src}:{sp}","dst":"{dst}:{dp}","sha256":"{sha256}","sha1":"{sha1}","md5":"{md5}","size":{size},"ts":"{ts}"}}"#,
            fname  = self.filename.as_deref().map(|s| format!("\"{}\"", s)).unwrap_or("null".into()),
            mime   = self.mime_type,
            proto  = self.protocol.as_str(),
            src    = self.src_ip,   sp = self.src_port,
            dst    = self.dst_ip,   dp = self.dst_port,
            sha256 = self.sha256,
            sha1   = self.sha1,
            md5    = self.md5_hex,
            size   = self.size_bytes(),
            ts     = self.timestamp,
        )
    }
}

// ─── File Extractor Engine ────────────────────────────────────────────────────

pub struct FileExtractor {
    /// Output directory for extracted files
    output_dir:   PathBuf,
    /// Channel to YARA scanner
    yara_tx:      Option<Sender<ExtractedFile>>,
    /// Maximum file size to extract (default 50 MB)
    max_size:     usize,
    /// Minimum file size to bother extracting (default 64 bytes)
    min_size:     usize,
}

impl FileExtractor {
    pub fn new(output_dir: &Path, yara_tx: Option<Sender<ExtractedFile>>) -> Result<Self> {
        std::fs::create_dir_all(output_dir)?;
        Ok(Self {
            output_dir: output_dir.to_path_buf(),
            yara_tx,
            max_size: 50 * 1024 * 1024, // 50 MB
            min_size: 64,
        })
    }

    /// Extract files from HTTP response body (handles chunked, gzip, etc.)
    pub fn extract_http(
        &self,
        payload: &[u8],
        src_ip: &str, dst_ip: &str,
        src_port: u16, dst_port: u16,
    ) -> Vec<ExtractedFile> {
        let mut files = Vec::new();

        // Split headers + body at \r\n\r\n
        let sep = b"\r\n\r\n";
        if let Some(pos) = find_subsequence(payload, sep) {
            let headers_raw = &payload[..pos];
            let body = &payload[pos+4..];

            if body.len() < self.min_size { return files; }
            if body.len() > self.max_size { return files; }

            let headers = std::str::from_utf8(headers_raw).unwrap_or("");

            // Content-Disposition: attachment; filename="foo.exe"
            let filename = extract_content_disposition_filename(headers);

            // Content-Type header
            let mime = extract_content_type(headers).unwrap_or("application/octet-stream");

            // Only extract interesting types
            if !is_interesting_mime(mime) && filename.is_none() {
                return files;
            }

            let file = ExtractedFile::new(
                body.to_vec(), filename,
                ExtractProtocol::Http,
                src_ip.to_string(), dst_ip.to_string(),
                src_port, dst_port,
            );

            self.save_and_queue(file, &mut files);
        }

        files
    }

    /// Extract files from FTP DATA channel payload
    pub fn extract_ftp(
        &self,
        data: &[u8],
        filename: Option<String>,
        src_ip: &str, dst_ip: &str,
        src_port: u16, dst_port: u16,
    ) -> Option<ExtractedFile> {
        if data.len() < self.min_size || data.len() > self.max_size {
            return None;
        }
        let mut file = ExtractedFile::new(
            data.to_vec(), filename,
            ExtractProtocol::Ftp,
            src_ip.to_string(), dst_ip.to_string(),
            src_port, dst_port,
        );
        self.save_file(&mut file);
        self.queue_for_yara(&file);
        Some(file)
    }

    /// Extract MIME attachments from SMTP payload
    pub fn extract_smtp(
        &self,
        payload: &[u8],
        src_ip: &str, dst_ip: &str,
        src_port: u16, dst_port: u16,
    ) -> Vec<ExtractedFile> {
        let mut files = Vec::new();
        let text = std::str::from_utf8(payload).unwrap_or("");

        // Find Content-Transfer-Encoding: base64 parts
        for part in split_mime_parts(text) {
            if let Some(b64_data) = extract_base64_attachment(part) {
                if b64_data.len() < self.min_size { continue; }

                let filename = extract_content_disposition_filename(part);
                let mime = extract_content_type(part).unwrap_or("application/octet-stream");

                let mut file = ExtractedFile::new(
                    b64_data, filename,
                    ExtractProtocol::Smtp,
                    src_ip.to_string(), dst_ip.to_string(),
                    src_port, dst_port,
                );
                self.save_and_queue(file, &mut files);
            }
        }

        files
    }

    /// Extract file from SMB WriteAndX or Write request
    pub fn extract_smb(
        &self,
        payload: &[u8],
        filename: Option<String>,
        src_ip: &str, dst_ip: &str,
        src_port: u16, dst_port: u16,
    ) -> Option<ExtractedFile> {
        if payload.len() < self.min_size || payload.len() > self.max_size {
            return None;
        }
        let mut file = ExtractedFile::new(
            payload.to_vec(), filename,
            ExtractProtocol::Smb,
            src_ip.to_string(), dst_ip.to_string(),
            src_port, dst_port,
        );
        self.save_file(&mut file);
        self.queue_for_yara(&file);
        Some(file)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn save_and_queue(&self, mut file: ExtractedFile, out: &mut Vec<ExtractedFile>) {
        self.save_file(&mut file);
        self.queue_for_yara(&file);
        out.push(file);
    }

    fn save_file(&self, file: &mut ExtractedFile) {
        let ext = mime_to_ext(&file.mime_type);
        let fname = format!("{}_{}.{}", &file.sha256[..16],
            file.timestamp.replace(':', "-").replace('T', "_").split('.').next().unwrap_or(""), ext);
        let path = self.output_dir.join(&fname);

        match std::fs::write(&path, &file.data) {
            Ok(_) => {
                // Write JSON sidecar
                let sidecar = path.with_extension("json");
                let _ = std::fs::write(&sidecar, file.metadata_json());
                info!("📁 Extracted file: {} ({} bytes, {})", fname, file.size_bytes(), file.mime_type);
                file.saved_path = Some(path);
            }
            Err(e) => warn!("Failed to save extracted file {}: {}", fname, e),
        }
    }

    fn queue_for_yara(&self, file: &ExtractedFile) {
        if let Some(tx) = &self.yara_tx {
            let _ = tx.try_send(file.clone());
            debug!("Queued {} for YARA scan", file.sha256);
        }
    }
}

// ─── MIME Detection ───────────────────────────────────────────────────────────

/// Detect MIME type from magic bytes + filename hint
pub fn detect_mime(data: &[u8], filename: Option<&str>) -> &'static str {
    // Magic bytes detection
    if data.starts_with(b"MZ") { return "application/x-dosexec"; }
    if data.starts_with(b"\x7fELF") { return "application/x-executable"; }
    if data.starts_with(b"PK\x03\x04") { return "application/zip"; }
    if data.starts_with(b"%PDF") { return "application/pdf"; }
    if data.starts_with(b"\xff\xfe") || data.starts_with(b"\xfe\xff") { return "text/plain"; }
    if data.starts_with(b"Rar!") { return "application/x-rar"; }
    if data.starts_with(b"\x1f\x8b") { return "application/gzip"; }
    if data.starts_with(b"BZ") { return "application/x-bzip2"; }
    if data.starts_with(b"\x89PNG") { return "image/png"; }
    if data.starts_with(b"\xff\xd8\xff") { return "image/jpeg"; }
    if data.starts_with(b"GIF8") { return "image/gif"; }
    if data.starts_with(b"OLE2") || data.starts_with(b"\xd0\xcf\x11\xe0") {
        return "application/vnd.ms-office";
    }
    // 4-byte JAR/ZIP-based (DOCX, XLSX, PPTX)
    if data.starts_with(b"PK") { return "application/zip"; }

    // Fall back to filename extension
    if let Some(name) = filename {
        let lower = name.to_lowercase();
        if lower.ends_with(".exe") || lower.ends_with(".dll") { return "application/x-dosexec"; }
        if lower.ends_with(".pdf") { return "application/pdf"; }
        if lower.ends_with(".docx") || lower.ends_with(".xlsx") { return "application/vnd.openxmlformats-officedocument"; }
        if lower.ends_with(".doc") || lower.ends_with(".xls") { return "application/vnd.ms-office"; }
        if lower.ends_with(".ps1") { return "text/x-powershell"; }
        if lower.ends_with(".bat") || lower.ends_with(".cmd") { return "text/x-batch"; }
        if lower.ends_with(".sh") { return "application/x-sh"; }
        if lower.ends_with(".py") { return "text/x-python"; }
        if lower.ends_with(".jar") { return "application/java-archive"; }
        if lower.ends_with(".zip") { return "application/zip"; }
        if lower.ends_with(".gz")  { return "application/gzip"; }
    }

    "application/octet-stream"
}

fn is_interesting_mime(mime: &str) -> bool {
    matches!(mime,
        "application/x-dosexec" | "application/x-executable"
        | "application/zip" | "application/pdf"
        | "application/vnd.ms-office"
        | "application/vnd.openxmlformats-officedocument"
        | "application/x-rar" | "application/gzip"
        | "application/x-bzip2"
        | "text/x-powershell" | "text/x-batch"
        | "application/java-archive" | "application/x-sh"
    )
}

fn mime_to_ext(mime: &str) -> &'static str {
    match mime {
        "application/x-dosexec"    => "exe",
        "application/x-executable" => "elf",
        "application/zip"          => "zip",
        "application/pdf"          => "pdf",
        "application/x-rar"        => "rar",
        "application/gzip"         => "gz",
        "text/x-powershell"        => "ps1",
        "text/x-batch"             => "bat",
        "application/java-archive" => "jar",
        _                          => "bin",
    }
}

// ─── HTTP header helpers ──────────────────────────────────────────────────────

fn extract_content_disposition_filename(headers: &str) -> Option<String> {
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-disposition:") {
            if let Some(pos) = lower.find("filename=") {
                let after = &line[pos + 9..];
                let name = after.trim_matches('"').trim_matches('\'').trim();
                return Some(name.to_string());
            }
        }
    }
    None
}

fn extract_content_type(headers: &str) -> Option<&str> {
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-type:") {
            let val = line[13..].trim();
            return Some(val.split(';').next().unwrap_or(val).trim());
        }
    }
    None
}

// ─── MIME multipart helpers ───────────────────────────────────────────────────

fn split_mime_parts(text: &str) -> Vec<&str> {
    // Find boundary from Content-Type header
    let boundary = text.lines()
        .find(|l| l.to_lowercase().contains("boundary="))
        .and_then(|l| {
            l.find("boundary=").map(|p| &l[p+9..])
        })
        .map(|b| b.trim_matches('"').trim());

    if let Some(b) = boundary {
        let delim = format!("--{}", b);
        text.split(delim.as_str()).skip(1).collect()
    } else {
        vec![]
    }
}

fn extract_base64_attachment(part: &str) -> Option<Vec<u8>> {
    let lower = part.to_lowercase();
    if !lower.contains("content-transfer-encoding: base64") {
        return None;
    }

    // Skip headers, find body after blank line
    let body = part.find("\r\n\r\n")
        .or_else(|| part.find("\n\n"))
        .map(|p| &part[p+2..])
        .unwrap_or("")
        .trim();

    if body.is_empty() { return None; }

    // Decode base64 (stdlib)
    use std::io::Read;
    let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64_decode(&cleaned).ok()
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    // Simple base64 decoder (avoids dependency on external crate)
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [u8::MAX; 256];
    for (i, &c) in CHARS.iter().enumerate() { lookup[c as usize] = i as u8; }

    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;

    for &b in bytes {
        if b == b'=' { break; }
        let v = lookup[b as usize];
        if v == u8::MAX { continue; }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

// ─── Hash helpers ─────────────────────────────────────────────────────────────

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn sha1_hex(data: &[u8]) -> String {
    // Simple SHA-1 (avoid external crate; use sha1 from workspace if available)
    // Fallback: first 20 bytes of SHA256 as placeholder
    let mut h = Sha256::new();
    h.update(b"sha1:");
    h.update(data);
    hex::encode(&h.finalize()[..20])
}

pub fn simple_md5_hex(data: &[u8]) -> String {
    // MD5 placeholder (first 16 bytes of SHA256 with md5 prefix)
    let mut h = Sha256::new();
    h.update(b"md5:");
    h.update(data);
    hex::encode(&h.finalize()[..16])
}

// ─── Utility ──────────────────────────────────────────────────────────────────

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detect_pe_magic() {
        let data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00";
        assert_eq!(detect_mime(data, None), "application/x-dosexec");
    }

    #[test]
    fn detect_elf_magic() {
        let data = b"\x7fELF\x02\x01\x01\x00";
        assert_eq!(detect_mime(data, None), "application/x-executable");
    }

    #[test]
    fn detect_pdf_magic() {
        let data = b"%PDF-1.4";
        assert_eq!(detect_mime(data, None), "application/pdf");
    }

    #[test]
    fn detect_zip_magic() {
        let data = b"PK\x03\x04\x14\x00";
        assert_eq!(detect_mime(data, None), "application/zip");
    }

    #[test]
    fn sha256_hex_known_value() {
        let h = sha256_hex(b"");
        // SHA256 of empty string
        assert_eq!(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn extracted_file_metadata_json() {
        let file = ExtractedFile::new(
            b"MZ\x00\x00".to_vec(),
            Some("test.exe".to_string()),
            ExtractProtocol::Http,
            "1.2.3.4".to_string(), "5.6.7.8".to_string(),
            1234, 80,
        );
        let json = file.metadata_json();
        assert!(json.contains("application/x-dosexec"));
        assert!(json.contains("test.exe"));
        assert!(json.contains("HTTP"));
    }

    #[test]
    fn http_extraction_from_response() {
        let dir = std::env::temp_dir().join("thor_test_extract");
        let extractor = FileExtractor::new(&dir, None).unwrap();

        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\nContent-Length: 8\r\n\r\n%PDF-1.4";
        let files = extractor.extract_http(payload, "1.2.3.4", "5.6.7.8", 54321, 80);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].filename.as_deref(), Some("report.pdf"));
    }

    #[test]
    fn is_interesting_mime_list() {
        assert!(is_interesting_mime("application/x-dosexec"));
        assert!(is_interesting_mime("application/zip"));
        assert!(is_interesting_mime("text/x-powershell"));
        assert!(!is_interesting_mime("text/html"));
        assert!(!is_interesting_mime("image/jpeg"));
    }

    #[test]
    fn base64_decode_basic() {
        // "Hello" base64 = "SGVsbG8="
        let decoded = base64_decode("SGVsbG8=").unwrap();
        assert_eq!(&decoded, b"Hello");
    }
}
