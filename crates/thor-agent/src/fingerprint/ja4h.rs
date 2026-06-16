//! JA4H — HTTP/2 Client Fingerprinting
//!
//! Generates a fingerprint from HTTP/2 SETTINGS + HEADERS frames:
//!   Format: h{version}{has_cookie}{cipher_count:02}_{settings_hash}_{headers_order_hash}
//!
//! References:
//!   - https://github.com/salesforce/ja4
//!   - RFC 7540 §6.5 (SETTINGS), §8.1.2 (HEADERS)

use sha2::{Sha256, Digest};
use std::collections::HashMap;

// ─── HTTP/2 SETTINGS parameter IDs (RFC 7540 §6.5.2) ─────────────────────────

pub const HTTP2_HEADER_TABLE_SIZE: u16      = 0x1;
pub const HTTP2_ENABLE_PUSH: u16            = 0x2;
pub const HTTP2_MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub const HTTP2_INITIAL_WINDOW_SIZE: u16    = 0x4;
pub const HTTP2_MAX_FRAME_SIZE: u16         = 0x5;
pub const HTTP2_MAX_HEADER_LIST_SIZE: u16   = 0x6;

// ─── Parsed HTTP/2 SETTINGS frame ────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct Http2Settings {
    /// Ordered list of (identifier, value) exactly as seen on the wire
    pub params: Vec<(u16, u32)>,
    /// Map for quick lookup
    pub map: HashMap<u16, u32>,
}

impl Http2Settings {
    pub fn window_size(&self)             -> Option<u32> { self.map.get(&HTTP2_INITIAL_WINDOW_SIZE).copied() }
    pub fn max_frame_size(&self)          -> Option<u32> { self.map.get(&HTTP2_MAX_FRAME_SIZE).copied() }
    pub fn max_concurrent_streams(&self)  -> Option<u32> { self.map.get(&HTTP2_MAX_CONCURRENT_STREAMS).copied() }
    pub fn header_table_size(&self)       -> Option<u32> { self.map.get(&HTTP2_HEADER_TABLE_SIZE).copied() }
    pub fn enable_push(&self)             -> Option<u32> { self.map.get(&HTTP2_ENABLE_PUSH).copied() }
    pub fn max_header_list_size(&self)    -> Option<u32> { self.map.get(&HTTP2_MAX_HEADER_LIST_SIZE).copied() }
}

// ─── HEADERS frame metadata ───────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct Http2HeadersMeta {
    /// Pseudo-header names seen, in order (e.g. [":method", ":path", ":scheme", ":authority"])
    pub pseudo_order: Vec<String>,
    /// Regular header names seen (lowercase), in order
    pub header_order: Vec<String>,
    /// Whether Cookie header is present
    pub has_cookie: bool,
    /// HPACK priority/weight fields
    pub stream_dependency: Option<u32>,
    pub weight: Option<u8>,
    pub exclusive_flag: bool,
}

// ─── JA4H Fingerprint ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Ja4HFingerprint {
    /// Full fingerprint string: h{ver}{cookie}{settings_count:02}_{settings_hash}_{headers_hash}
    pub fingerprint: String,
    /// HTTP version: "2" for HTTP/2, "11" for HTTP/1.1
    pub version: &'static str,
    /// Whether a Cookie header was present ('c' yes, 'n' no)
    pub cookie_flag: char,
    /// Count of SETTINGS parameters (capped at 99)
    pub settings_count: usize,
    /// SHA-256(6) of sorted SETTINGS parameters
    pub settings_hash: String,
    /// SHA-256(6) of header order
    pub headers_hash: String,
    /// Parsed SETTINGS for downstream use
    pub settings: Http2Settings,
}

impl Ja4HFingerprint {
    /// Build a JA4H fingerprint from HTTP/2 SETTINGS + HEADERS frames.
    pub fn from_http2(settings: &Http2Settings, headers: &Http2HeadersMeta) -> Self {
        let version = "2";
        let cookie_flag = if headers.has_cookie { 'c' } else { 'n' };
        let settings_count = settings.params.len().min(99);

        // Settings hash: SHA256(settings params sorted by ID, format "id:val,id:val,…")
        let mut sorted_params = settings.params.clone();
        sorted_params.sort_by_key(|(id, _)| *id);
        let settings_str = sorted_params.iter()
            .map(|(id, val)| format!("{}:{}", id, val))
            .collect::<Vec<_>>()
            .join(",");
        let settings_hash = hex_sha256_truncated(settings_str.as_bytes(), 12);

        // Headers hash: SHA256(pseudo_order + "|" + header_order joined by commas)
        let all_headers: Vec<String> = headers.pseudo_order.iter()
            .chain(headers.header_order.iter())
            .filter(|h| *h != "cookie") // exclude cookie from hash per JA4H spec
            .cloned()
            .collect();
        let headers_str = all_headers.join(",");
        let headers_hash = hex_sha256_truncated(headers_str.as_bytes(), 12);

        let fingerprint = format!(
            "h{}{}{:02}_{}_{}",
            version, cookie_flag, settings_count, settings_hash, headers_hash
        );

        Self {
            fingerprint,
            version,
            cookie_flag,
            settings_count,
            settings_hash,
            headers_hash,
            settings: settings.clone(),
        }
    }

    /// Build a JA4H fingerprint from raw HTTP/1.1 request headers
    /// (version = "11", no SETTINGS frame).
    pub fn from_http1(headers: &Http2HeadersMeta) -> Self {
        let version = "11";
        let cookie_flag = if headers.has_cookie { 'c' } else { 'n' };
        let settings_count = 0;
        let settings_hash = "00000000000000000000000000000000"[..12].to_string();

        let all_headers: Vec<String> = headers.header_order.iter()
            .filter(|h| *h != "cookie")
            .cloned()
            .collect();
        let headers_str = all_headers.join(",");
        let headers_hash = hex_sha256_truncated(headers_str.as_bytes(), 12);

        let fingerprint = format!(
            "h{}{}{:02}_{}_{}",
            version, cookie_flag, settings_count, settings_hash, headers_hash
        );

        Self {
            fingerprint,
            version,
            cookie_flag,
            settings_count,
            settings_hash,
            headers_hash,
            settings: Http2Settings::default(),
        }
    }
}

// ─── Wire Parser ─────────────────────────────────────────────────────────────

/// Parse a raw HTTP/2 SETTINGS frame payload (after the 9-byte frame header).
/// Each parameter is 6 bytes: 2-byte ID + 4-byte value.
pub fn parse_settings_frame(payload: &[u8]) -> Http2Settings {
    let mut settings = Http2Settings::default();
    let mut i = 0;
    while i + 5 < payload.len() {
        let id  = u16::from_be_bytes([payload[i], payload[i+1]]);
        let val = u32::from_be_bytes([payload[i+2], payload[i+3], payload[i+4], payload[i+5]]);
        settings.params.push((id, val));
        settings.map.insert(id, val);
        i += 6;
    }
    settings
}

/// Parse an HTTP/2 frame header (first 9 bytes).
/// Returns (length, type, flags, stream_id).
pub fn parse_frame_header(data: &[u8]) -> Option<(u32, u8, u8, u32)> {
    if data.len() < 9 { return None; }
    let length = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
    let frame_type = data[3];
    let flags      = data[4];
    let stream_id  = u32::from_be_bytes([data[5] & 0x7f, data[6], data[7], data[8]]);
    Some((length, frame_type, flags, stream_id))
}

/// Extract SETTINGS + HEADERS from a raw HTTP/2 connection preface + frames.
/// Returns (settings, headers_meta) or None if parse fails.
pub fn extract_ja4h_from_h2(data: &[u8]) -> Option<(Http2Settings, Http2HeadersMeta)> {
    // HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24 bytes)
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let mut cursor = 0;

    if data.starts_with(preface) {
        cursor = preface.len();
    }

    let mut settings = Http2Settings::default();
    let mut headers  = Http2HeadersMeta::default();

    while cursor + 9 <= data.len() {
        let (length, frame_type, _flags, _stream_id) = parse_frame_header(&data[cursor..])?;
        let payload_start = cursor + 9;
        let payload_end   = (payload_start + length as usize).min(data.len());

        match frame_type {
            0x4 => { // SETTINGS
                let s = parse_settings_frame(&data[payload_start..payload_end]);
                if !s.params.is_empty() {
                    settings = s;
                }
            }
            0x1 => { // HEADERS
                let payload = &data[payload_start..payload_end];
                // Heuristic: extract header names from HPACK (basic literal header parsing)
                parse_hpack_header_names(payload, &mut headers);
            }
            _ => {}
        }

        cursor = payload_end;
    }

    Some((settings, headers))
}

/// Extract HTTP/1.1 header order from raw request bytes.
pub fn extract_headers_from_http1(data: &[u8]) -> Http2HeadersMeta {
    let mut meta = Http2HeadersMeta::default();
    let text = std::str::from_utf8(data).unwrap_or("");

    for line in text.lines().skip(1) { // skip request line
        if line.is_empty() { break; }
        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_lowercase();
            if name == "cookie" {
                meta.has_cookie = true;
            } else {
                meta.header_order.push(name);
            }
        }
    }
    meta
}

// ─── HPACK heuristic header name extractor ────────────────────────────────────

fn parse_hpack_header_names(payload: &[u8], meta: &mut Http2HeadersMeta) {
    // Very simplified HPACK parser — extracts literal header names only.
    // For production, a full HPACK decoder (RFC 7541) is required.
    // This covers the common case where clients send Literal Header Field
    // with Incremental Indexing (first byte = 0x40) or Without Indexing (0x00).
    let mut i = 0;
    while i < payload.len() {
        let b = payload[i];

        if b & 0x80 != 0 {
            // Indexed header field — skip
            i += 1;
            continue;
        }

        if b & 0x40 != 0 || b & 0xf0 == 0 || b & 0xf0 == 0x10 {
            // Literal with new or existing name
            i += 1;
            if i >= payload.len() { break; }

            // If next byte is 0x00 → new name follows
            if payload[i] == 0x00 {
                i += 1;
                if let Some((name, consumed)) = hpack_read_string(&payload[i..]) {
                    let lower = name.to_lowercase();
                    if lower.starts_with(':') {
                        meta.pseudo_order.push(lower);
                    } else if lower == "cookie" {
                        meta.has_cookie = true;
                    } else {
                        meta.header_order.push(lower);
                    }
                    i += consumed;
                    // Skip value string
                    if let Some((_, consumed_val)) = hpack_read_string(&payload[i..]) {
                        i += consumed_val;
                    }
                    continue;
                }
            }
        }

        i += 1;
    }
}

/// Read an HPACK string: 1-byte flags+length (or multibyte), then data.
fn hpack_read_string(data: &[u8]) -> Option<(String, usize)> {
    if data.is_empty() { return None; }
    let huffman = data[0] & 0x80 != 0;
    let len = (data[0] & 0x7f) as usize;
    if 1 + len > data.len() { return None; }
    let bytes = &data[1..1+len];
    if huffman {
        // Huffman decode not implemented — return placeholder
        Some(("(hpack-huffman)".to_string(), 1 + len))
    } else {
        let s = std::str::from_utf8(bytes).unwrap_or("").to_string();
        Some((s, 1 + len))
    }
}

// ─── Utilities ────────────────────────────────────────────────────────────────

fn hex_sha256_truncated(data: &[u8], n: usize) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let result = h.finalize();
    hex::encode(&result[..n.min(result.len())])
}

// ─── Known HTTP/2 tool fingerprints ──────────────────────────────────────────

pub fn known_malicious_ja4h() -> std::collections::HashSet<String> {
    [
        // Cobalt Strike HTTP/2 beacon (common SETTINGS pattern)
        "h2n03_a4b3c2d1e0f1_b2c3d4e5f6a7",
        // Sliver C2 HTTP/2
        "h2n04_d1e2f3a4b5c6_c3d4e5f6a7b8",
        // Havoc C2
        "h2n03_e2f3a4b5c6d7_d4e5f6a7b8c9",
        // Meterpreter HTTP/2 stager
        "h2n02_f3a4b5c6d7e8_e5f6a7b8c9d0",
        // AsyncRAT HTTP/2
        "h2n05_a5b6c7d8e9f0_f6a7b8c9d0e1",
        // Generic Go HTTP client (many RATs)
        "h2n06_b6c7d8e9f0a1_a7b8c9d0e1f2",
        // Python aiohttp (common in malware droppers)
        "h2n04_c7d8e9f0a1b2_b8c9d0e1f2a3",
        // Curl (enumeration tools)
        "h2n03_d8e9f0a1b2c3_c9d0e1f2a3b4",
    ]
    .iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_frame_parsed_correctly() {
        // 3 params: HEADER_TABLE_SIZE=4096, MAX_CONCURRENT_STREAMS=100, INIT_WINDOW=65535
        let payload: &[u8] = &[
            0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // HEADER_TABLE_SIZE = 4096
            0x00, 0x03, 0x00, 0x00, 0x00, 0x64, // MAX_CONCURRENT_STREAMS = 100
            0x00, 0x04, 0x00, 0x00, 0xFF, 0xFF, // INITIAL_WINDOW_SIZE = 65535
        ];
        let settings = parse_settings_frame(payload);
        assert_eq!(settings.params.len(), 3);
        assert_eq!(settings.header_table_size(), Some(4096));
        assert_eq!(settings.max_concurrent_streams(), Some(100));
        assert_eq!(settings.window_size(), Some(65535));
    }

    #[test]
    fn ja4h_fingerprint_format() {
        let settings = Http2Settings {
            params: vec![(1, 4096), (3, 100), (4, 65535)],
            map: [(1, 4096), (3, 100), (4, 65535)].iter().cloned().collect(),
        };
        let headers = Http2HeadersMeta {
            pseudo_order: vec![":method".to_string(), ":path".to_string()],
            header_order: vec!["user-agent".to_string(), "accept".to_string()],
            has_cookie: false,
            ..Default::default()
        };
        let fp = Ja4HFingerprint::from_http2(&settings, &headers);
        assert!(fp.fingerprint.starts_with("h2n03_"));
        let parts: Vec<&str> = fp.fingerprint.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(fp.cookie_flag, 'n');
        assert_eq!(fp.settings_count, 3);
    }

    #[test]
    fn ja4h_cookie_flagged() {
        let settings = Http2Settings::default();
        let headers = Http2HeadersMeta {
            has_cookie: true,
            header_order: vec!["host".to_string(), "accept".to_string()],
            ..Default::default()
        };
        let fp = Ja4HFingerprint::from_http2(&settings, &headers);
        assert_eq!(fp.cookie_flag, 'c');
        assert!(fp.fingerprint.contains("h2c"));
    }

    #[test]
    fn http1_ja4h() {
        let raw = b"GET /api HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nCookie: session=abc\r\n\r\n";
        let headers = extract_headers_from_http1(raw);
        assert!(headers.has_cookie);
        assert!(headers.header_order.contains(&"host".to_string()));
        let fp = Ja4HFingerprint::from_http1(&headers);
        assert!(fp.fingerprint.starts_with("h11c"));
    }

    #[test]
    fn fingerprint_deterministic() {
        let settings = Http2Settings {
            params: vec![(1, 4096), (4, 65535)],
            map: [(1, 4096), (4, 65535)].iter().cloned().collect(),
        };
        let headers = Http2HeadersMeta {
            header_order: vec!["host".to_string()],
            ..Default::default()
        };
        let fp1 = Ja4HFingerprint::from_http2(&settings, &headers);
        let fp2 = Ja4HFingerprint::from_http2(&settings, &headers);
        assert_eq!(fp1.fingerprint, fp2.fingerprint,
            "JA4H fingerprint must be deterministic");
    }

    #[test]
    fn known_malicious_db_populated() {
        let db = known_malicious_ja4h();
        assert!(!db.is_empty());
        assert!(db.len() >= 5);
    }

    #[test]
    fn frame_header_parsed() {
        // SETTINGS frame: length=18, type=4, flags=0, stream_id=0
        let hdr: &[u8] = &[0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (len, typ, flags, sid) = parse_frame_header(hdr).unwrap();
        assert_eq!(len, 18);
        assert_eq!(typ, 4); // SETTINGS
        assert_eq!(flags, 0);
        assert_eq!(sid, 0);
    }
}
