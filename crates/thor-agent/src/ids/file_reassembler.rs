//! File Reassembler — Reconstruct multi-segment files from TCP streams
//!
//! Integrates with TcpReassembler to provide:
//!   ▸ HTTP chunked transfer decoding
//!   ▸ HTTP Content-Length based body extraction
//!   ▸ FTP RETR/STOR session tracking
//!   ▸ SMTP DATA section with MIME boundary detection
//!   ▸ SMB Write request accumulation
//!
//! All reassembled files are sent to FileExtractor for hash + YARA.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};
use flume::Sender;

use super::file_extractor::{ExtractedFile, ExtractProtocol, FileExtractor};

// ─── Session State ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum SessionKind {
    HttpRequest  { content_length: Option<usize>, chunked: bool },
    HttpResponse { content_length: Option<usize>, chunked: bool },
    FtpData      { filename: Option<String> },
    SmtpData,
    SmbWrite     { filename: Option<String> },
}

struct ReassemblySession {
    kind:       SessionKind,
    buffer:     Vec<u8>,
    headers:    String,
    headers_done: bool,
    expected:   Option<usize>,
    src_ip:     String,
    dst_ip:     String,
    src_port:   u16,
    dst_port:   u16,
    last_seen:  Instant,
}

impl ReassemblySession {
    fn new(kind: SessionKind, src_ip: String, dst_ip: String,
           src_port: u16, dst_port: u16) -> Self {
        Self {
            kind, buffer: Vec::new(), headers: String::new(),
            headers_done: false, expected: None,
            src_ip, dst_ip, src_port, dst_port,
            last_seen: Instant::now(),
        }
    }

    fn is_complete(&self) -> bool {
        match self.expected {
            Some(n) => self.buffer.len() >= n,
            None    => false,
        }
    }

    fn is_stale(&self, ttl: Duration) -> bool {
        self.last_seen.elapsed() > ttl
    }
}

// ─── Session Key ──────────────────────────────────────────────────────────────

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
struct SessionKey {
    src_ip:   String,
    src_port: u16,
    dst_ip:   String,
    dst_port: u16,
}

// ─── File Reassembler ─────────────────────────────────────────────────────────

pub struct FileReassembler {
    sessions:   Arc<DashMap<SessionKey, ReassemblySession>>,
    extractor:  Arc<FileExtractor>,
    session_ttl: Duration,
    max_file_size: usize,
}

impl FileReassembler {
    pub fn new(extractor: Arc<FileExtractor>) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            extractor,
            session_ttl: Duration::from_secs(60),
            max_file_size: 50 * 1024 * 1024,
        }
    }

    /// Push HTTP payload chunk. Returns extracted files when complete.
    pub fn push_http(&self, payload: &[u8],
                     src_ip: &str, dst_ip: &str,
                     src_port: u16, dst_port: u16,
                     is_response: bool) -> Vec<ExtractedFile> {
        let key = SessionKey {
            src_ip: src_ip.to_string(), src_port,
            dst_ip: dst_ip.to_string(), dst_port,
        };

        let mut session = self.sessions.entry(key.clone()).or_insert_with(|| {
            ReassemblySession::new(
                if is_response {
                    SessionKind::HttpResponse { content_length: None, chunked: false }
                } else {
                    SessionKind::HttpRequest { content_length: None, chunked: false }
                },
                src_ip.to_string(), dst_ip.to_string(), src_port, dst_port,
            )
        });

        session.last_seen = Instant::now();

        // Accumulate headers until \r\n\r\n
        if !session.headers_done {
            let combined = [session.buffer.as_slice(), payload].concat();
            if let Some(sep) = find_header_end(&combined) {
                session.headers = String::from_utf8_lossy(&combined[..sep]).to_string();
                session.headers_done = true;

                // Parse Content-Length / Transfer-Encoding
                let cl = parse_content_length(&session.headers);
                let chunked = session.headers.to_lowercase().contains("transfer-encoding: chunked");

                match &mut session.kind {
                    SessionKind::HttpResponse { content_length, chunked: ck, .. } => {
                        *content_length = cl;
                        *ck = chunked;
                        session.expected = cl;
                    }
                    SessionKind::HttpRequest { content_length, chunked: ck } => {
                        *content_length = cl;
                        *ck = chunked;
                        session.expected = cl;
                    }
                    _ => {}
                }

                session.buffer = combined[sep+4..].to_vec();
            } else {
                session.buffer = combined;
                return vec![];
            }
        } else {
            session.buffer.extend_from_slice(payload);
        }

        // Size guard
        if session.buffer.len() > self.max_file_size {
            self.sessions.remove(&key);
            return vec![];
        }

        // Check completion
        if session.is_complete() || self.looks_complete(&session) {
            let buf = std::mem::take(&mut session.buffer);
            let headers = session.headers.clone();
            let src = session.src_ip.clone();
            let dst = session.dst_ip.clone();
            let sp = session.src_port;
            let dp = session.dst_port;
            drop(session);
            self.sessions.remove(&key);

            // Build a synthetic HTTP response for extractor
            let synthetic = [headers.as_bytes(), b"\r\n\r\n", &buf].concat();
            return self.extractor.extract_http(&synthetic, &src, &dst, sp, dp);
        }

        vec![]
    }

    /// Push FTP data. Call with each DATA channel chunk.
    pub fn push_ftp(&self, data: &[u8], filename: Option<String>,
                    src_ip: &str, dst_ip: &str,
                    src_port: u16, dst_port: u16,
                    is_final: bool) -> Option<ExtractedFile> {
        let key = SessionKey {
            src_ip: src_ip.to_string(), src_port,
            dst_ip: dst_ip.to_string(), dst_port,
        };

        {
            let mut session = self.sessions.entry(key.clone()).or_insert_with(|| {
                ReassemblySession::new(
                    SessionKind::FtpData { filename: filename.clone() },
                    src_ip.to_string(), dst_ip.to_string(), src_port, dst_port,
                )
            });
            session.last_seen = Instant::now();
            session.buffer.extend_from_slice(data);
        }

        if is_final {
            if let Some((_, session)) = self.sessions.remove(&key) {
                let fname = match &session.kind {
                    SessionKind::FtpData { filename } => filename.clone(),
                    _ => None,
                }.or(filename);

                return self.extractor.extract_ftp(
                    &session.buffer, fname,
                    &session.src_ip, &session.dst_ip,
                    session.src_port, session.dst_port,
                );
            }
        }
        None
    }

    /// Push SMTP DATA section payload
    pub fn push_smtp(&self, data: &[u8],
                     src_ip: &str, dst_ip: &str,
                     src_port: u16, dst_port: u16,
                     is_final: bool) -> Vec<ExtractedFile> {
        let key = SessionKey {
            src_ip: src_ip.to_string(), src_port,
            dst_ip: dst_ip.to_string(), dst_port,
        };

        {
            let mut session = self.sessions.entry(key.clone()).or_insert_with(|| {
                ReassemblySession::new(
                    SessionKind::SmtpData,
                    src_ip.to_string(), dst_ip.to_string(), src_port, dst_port,
                )
            });
            session.last_seen = Instant::now();
            session.buffer.extend_from_slice(data);
        }

        if is_final {
            if let Some((_, session)) = self.sessions.remove(&key) {
                return self.extractor.extract_smtp(
                    &session.buffer,
                    &session.src_ip, &session.dst_ip,
                    session.src_port, session.dst_port,
                );
            }
        }
        vec![]
    }

    /// Clean up stale sessions
    pub fn sweep_stale(&self) -> usize {
        let ttl = self.session_ttl;
        let before = self.sessions.len();
        self.sessions.retain(|_, s| !s.is_stale(ttl));
        let removed = before.saturating_sub(self.sessions.len());
        if removed > 0 {
            debug!("FileReassembler: swept {} stale sessions", removed);
        }
        removed
    }

    pub fn active_sessions(&self) -> usize { self.sessions.len() }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn looks_complete(&self, session: &ReassemblySession) -> bool {
        // For chunked: look for terminal "0\r\n\r\n"
        let buf = &session.buffer;
        if buf.len() > 5 {
            let tail = &buf[buf.len().saturating_sub(8)..];
            if tail.windows(5).any(|w| w == b"0\r\n\r\n") {
                return true;
            }
        }
        false
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            return line[15..].trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn make_extractor() -> Arc<FileExtractor> {
        let dir = std::env::temp_dir().join("thor_test_reassem");
        Arc::new(FileExtractor::new(&dir, None).unwrap())
    }

    #[test]
    fn find_header_end_basic() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nBODY";
        let pos = find_header_end(data).unwrap();
        assert_eq!(&data[pos+4..], b"BODY");
    }

    #[test]
    fn parse_content_length_from_headers() {
        let headers = "HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nContent-Type: application/pdf";
        assert_eq!(parse_content_length(headers), Some(1024));
    }

    #[test]
    fn http_response_extraction_via_reassembler() {
        let extractor = make_extractor();
        let reassembler = FileReassembler::new(extractor);

        // Single-segment HTTP response with PDF
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: 8\r\nContent-Disposition: attachment; filename=\"doc.pdf\"\r\n\r\n%PDF-1.4";
        let files = reassembler.push_http(payload, "1.2.3.4", "5.6.7.8", 54321, 80, true);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].filename.as_deref(), Some("doc.pdf"));
    }

    #[test]
    fn ftp_file_accumulation() {
        let extractor = make_extractor();
        let reassembler = FileReassembler::new(extractor);

        // Three FTP chunks
        reassembler.push_ftp(b"MZ\x90\x00", Some("evil.exe".into()), "1.1.1.1", "2.2.2.2", 20, 20001, false);
        reassembler.push_ftp(b"\x03\x00\x00\x00", None, "1.1.1.1", "2.2.2.2", 20, 20001, false);
        let result = reassembler.push_ftp(b"\x04\x00\x00\x00", None, "1.1.1.1", "2.2.2.2", 20, 20001, true);

        assert!(result.is_some());
        let f = result.unwrap();
        assert_eq!(f.filename.as_deref(), Some("evil.exe"));
        assert_eq!(&f.data[..2], b"MZ");
    }

    #[test]
    fn stale_sweep_removes_old_sessions() {
        let extractor = make_extractor();
        let mut reassembler = FileReassembler::new(extractor);
        reassembler.session_ttl = Duration::from_millis(1);

        reassembler.push_ftp(b"data", Some("file".into()), "1.1.1.1", "2.2.2.2", 20, 20001, false);
        std::thread::sleep(Duration::from_millis(5));
        let swept = reassembler.sweep_stale();
        assert_eq!(swept, 1);
        assert_eq!(reassembler.active_sessions(), 0);
    }
}
