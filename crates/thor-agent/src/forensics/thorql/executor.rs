//! ThorQL Executor — maps AST table names to real data-collection functions
//! and applies WHERE filter rows, returning a columnar result set.
//!
//! Each "table" is a virtual data source backed by /proc, sysinfo, or eBPF maps.
//! New tables can be added by implementing the `DataSource` trait.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, Result};
use serde_json::Value as JsValue;
use tracing::{debug, warn};

use super::parser::{Expr, Op, Projection, SelectStatement, Value};

// ─── Row type ─────────────────────────────────────────────────────────────────

/// A single result row: column name → JSON value.
pub type Row = HashMap<String, JsValue>;

// ─── QueryResult ──────────────────────────────────────────────────────────────

/// The full result of a ThorQL query execution.
#[derive(Debug)]
pub struct QueryResult {
    /// Ordered column names (from projection).
    pub columns: Vec<String>,
    /// Data rows — each map contains at least the projected columns.
    pub rows:    Vec<Row>,
    /// Number of rows examined before filtering.
    pub scanned: usize,
}

// ─── DataSource trait ─────────────────────────────────────────────────────────

trait DataSource: Send + Sync {
    /// Return all rows for this table (unfiltered).
    fn scan(&self) -> Vec<Row>;
}

// ─── processes() ──────────────────────────────────────────────────────────────

struct ProcessesSource;

impl DataSource for ProcessesSource {
    fn scan(&self) -> Vec<Row> {
        let mut rows = Vec::new();

        let proc_dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(e) => { warn!("Cannot read /proc: {}", e); return rows; }
        };

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            let pid: u32 = match s.parse() {
                Ok(n) => n,
                Err(_) => continue,
            };

            let proc_path = format!("/proc/{}", pid);

            let cmdline = read_proc_null_separated(&format!("{}/cmdline", proc_path))
                .unwrap_or_default();

            let comm = fs::read_to_string(format!("{}/comm", proc_path))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();

            let exe = fs::read_link(format!("{}/exe", proc_path))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            let (ppid, state, uid) = parse_status(&format!("{}/status", proc_path));

            let mut row = Row::new();
            row.insert("pid".into(),      JsValue::from(pid));
            row.insert("name".into(),     JsValue::from(comm.as_str()));
            row.insert("cmdline".into(),  JsValue::from(cmdline.as_str()));
            row.insert("exe".into(),      JsValue::from(exe.as_str()));
            row.insert("ppid".into(),     JsValue::from(ppid));
            row.insert("state".into(),    JsValue::from(state.as_str()));
            row.insert("uid".into(),      JsValue::from(uid));
            rows.push(row);
        }
        rows
    }
}

fn read_proc_null_separated(path: &str) -> Result<String> {
    let bytes = fs::read(path)?;
    Ok(bytes.iter()
        .map(|&b| if b == 0 { ' ' } else { b as char })
        .collect::<String>()
        .trim()
        .to_string())
}

fn parse_status(path: &str) -> (u32, String, u32) {
    let mut ppid  = 0u32;
    let mut state = String::from("?");
    let mut uid   = 0u32;

    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("PPid:\t") {
                ppid = rest.trim().parse().unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("State:\t") {
                state = rest.split_whitespace().next().unwrap_or("?").to_string();
            } else if let Some(rest) = line.strip_prefix("Uid:\t") {
                uid = rest.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
            }
        }
    }
    (ppid, state, uid)
}

// ─── connections() ────────────────────────────────────────────────────────────

struct ConnectionsSource;

impl DataSource for ConnectionsSource {
    fn scan(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        // Read /proc/net/tcp and /proc/net/tcp6
        for (file, proto) in [("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")] {
            if let Ok(content) = fs::read_to_string(file) {
                for line in content.lines().skip(1) {
                    if let Some(row) = parse_net_entry(line, proto) {
                        rows.push(row);
                    }
                }
            }
        }
        // Enrich with process names
        enrich_connections_with_pids(&mut rows);
        rows
    }
}

fn hex_to_ip_port(hex: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 { return None; }

    let port = u16::from_str_radix(parts[1], 16).ok()?;

    // IPv4: 4 hex chars reversed
    if parts[0].len() == 8 {
        let n = u32::from_str_radix(parts[0], 16).ok()?;
        let ip = std::net::Ipv4Addr::from(u32::from_be(n));
        Some((ip.to_string(), port))
    } else {
        // IPv6: 32 hex chars
        Some(("(ipv6)".to_string(), port))
    }
}

fn tcp_state(hex: &str) -> &'static str {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _    => "UNKNOWN",
    }
}

fn parse_net_entry(line: &str, proto: &str) -> Option<Row> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 12 { return None; }

    let (local_ip, local_port) = hex_to_ip_port(parts[1])?;
    let (remote_ip, remote_port) = hex_to_ip_port(parts[2])?;
    let state = tcp_state(parts[3]).to_string();
    let inode: u64 = parts[9].parse().unwrap_or(0);

    let mut row = Row::new();
    row.insert("protocol".into(),    JsValue::from(proto));
    row.insert("local_ip".into(),    JsValue::from(local_ip.as_str()));
    row.insert("local_port".into(),  JsValue::from(local_port));
    row.insert("remote_ip".into(),   JsValue::from(remote_ip.as_str()));
    row.insert("remote_port".into(), JsValue::from(remote_port));
    row.insert("state".into(),       JsValue::from(state.as_str()));
    row.insert("inode".into(),       JsValue::from(inode));
    row.insert("pid".into(),         JsValue::from(0u64));
    row.insert("process_name".into(), JsValue::from(""));
    Some(row)
}

fn enrich_connections_with_pids(rows: &mut Vec<Row>) {
    // Build inode → (pid, name) map from /proc/<pid>/fd
    let mut inode_map: HashMap<u64, (u32, String)> = HashMap::new();

    if let Ok(proc_dir) = fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let fname = entry.file_name();
            let s = fname.to_string_lossy();
            let pid: u32 = match s.parse() { Ok(n) => n, Err(_) => continue };

            let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();

            if let Ok(fd_dir) = fs::read_dir(format!("/proc/{}/fd", pid)) {
                for fd_entry in fd_dir.flatten() {
                    if let Ok(link) = fs::read_link(fd_entry.path()) {
                        let target = link.to_string_lossy();
                        // socket:[12345]
                        if let Some(inner) = target.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                            if let Ok(inode) = inner.parse::<u64>() {
                                inode_map.insert(inode, (pid, comm.clone()));
                            }
                        }
                    }
                }
            }
        }
    }

    for row in rows.iter_mut() {
        if let Some(JsValue::Number(n)) = row.get("inode") {
            let inode = n.as_u64().unwrap_or(0);
            if let Some((pid, name)) = inode_map.get(&inode) {
                row.insert("pid".into(), JsValue::from(*pid));
                row.insert("process_name".into(), JsValue::from(name.as_str()));
            }
        }
    }
}

// ─── files(<path>) source ─────────────────────────────────────────────────────

struct FilesSource {
    root: String,
}

impl DataSource for FilesSource {
    fn scan(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        walk_directory(Path::new(&self.root), &mut rows, 0);
        rows
    }
}

fn walk_directory(path: &Path, rows: &mut Vec<Row>, depth: usize) {
    if depth > 5 { return; } // prevent runaway recursion
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };

    if meta.is_file() {
        use std::os::unix::fs::MetadataExt;
        let mut row = Row::new();
        row.insert("path".into(),  JsValue::from(path.to_string_lossy().as_ref()));
        row.insert("size".into(),  JsValue::from(meta.size()));
        row.insert("mtime".into(), JsValue::from(meta.mtime()));
        row.insert("mode".into(),  JsValue::from(meta.mode()));
        row.insert("uid".into(),   JsValue::from(meta.uid()));
        rows.push(row);
    } else if meta.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                walk_directory(&entry.path(), rows, depth + 1);
                if rows.len() > 10_000 { break; } // safety cap
            }
        }
    }
}

// ─── users() source ───────────────────────────────────────────────────────────

struct UsersSource;

impl DataSource for UsersSource {
    fn scan(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        if let Ok(content) = fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                if line.starts_with('#') { continue; }
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() < 7 { continue; }
                let mut row = Row::new();
                row.insert("username".into(), JsValue::from(parts[0]));
                row.insert("uid".into(),      JsValue::from(parts[2].parse::<u32>().unwrap_or(0)));
                row.insert("gid".into(),      JsValue::from(parts[3].parse::<u32>().unwrap_or(0)));
                row.insert("gecos".into(),    JsValue::from(parts[4]));
                row.insert("home".into(),     JsValue::from(parts[5]));
                row.insert("shell".into(),    JsValue::from(parts[6]));
                rows.push(row);
            }
        }
        rows
    }
}

// ─── cron_jobs() source ───────────────────────────────────────────────────────

struct CronJobsSource;

impl DataSource for CronJobsSource {
    fn scan(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        let locations = vec![
            "/etc/crontab",
            "/etc/cron.d",
            "/var/spool/cron/crontabs",
        ];
        for loc in locations {
            collect_cron_entries(Path::new(loc), &mut rows);
        }
        rows
    }
}

fn collect_cron_entries(path: &Path, rows: &mut Vec<Row>) {
    if path.is_file() {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
                let mut row = Row::new();
                row.insert("source".into(), JsValue::from(path.to_string_lossy().as_ref()));
                row.insert("entry".into(),  JsValue::from(trimmed));
                rows.push(row);
            }
        }
    } else if path.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                collect_cron_entries(&entry.path(), rows);
            }
        }
    }
}

// ─── Resolver: table name → DataSource ───────────────────────────────────────

fn resolve_source(table: &str) -> Result<Box<dyn DataSource>> {
    // files(<path>) with optional argument
    if table.starts_with("files(") && table.ends_with(')') {
        let inner = &table[6..table.len() - 1];
        let root = inner.trim_matches('"').trim_matches('\'').to_string();
        return Ok(Box::new(FilesSource { root }));
    }
    match table {
        "processes"    => Ok(Box::new(ProcessesSource)),
        "connections"  => Ok(Box::new(ConnectionsSource)),
        "users"        => Ok(Box::new(UsersSource)),
        "cron_jobs"    => Ok(Box::new(CronJobsSource)),
        other          => Err(anyhow!("Unknown table: '{}'", other)),
    }
}

// ─── WHERE filter evaluation ──────────────────────────────────────────────────

/// Evaluate an expression against a row. Returns `true` if the row matches.
fn eval_expr(expr: &Expr, row: &Row) -> bool {
    match expr {
        Expr::And(a, b) => eval_expr(a, row) && eval_expr(b, row),
        Expr::Or(a, b)  => eval_expr(a, row) || eval_expr(b, row),
        Expr::Not(inner) => !eval_expr(inner, row),
        Expr::Comparison { column, op, value } => {
            let cell = row.get(column.as_str())
                .or_else(|| {
                    // Case-insensitive column lookup
                    let lower = column.to_lowercase();
                    row.iter().find(|(k, _)| k.to_lowercase() == lower).map(|(_, v)| v)
                });

            match cell {
                None => false,
                Some(cell_val) => compare_values(cell_val, op, value),
            }
        }
    }
}

fn compare_values(cell: &JsValue, op: &Op, rhs: &Value) -> bool {
    match op {
        Op::Like | Op::NotLike => {
            let s = json_as_str(cell);
            let pattern = match rhs {
                Value::Str(p) => p.as_str(),
                _ => return false,
            };
            let matched = like_match(&s, pattern);
            if *op == Op::NotLike { !matched } else { matched }
        }
        Op::Eq | Op::NotEq | Op::Gt | Op::Lt | Op::Gte | Op::Lte => {
            let matched = match rhs {
                Value::Str(s) => {
                    let cell_s = json_as_str(cell);
                    match op {
                        Op::Eq    => cell_s == *s,
                        Op::NotEq => cell_s != *s,
                        _         => false,
                    }
                }
                Value::Int(n) => {
                    let cell_n = json_as_i64(cell);
                    match op {
                        Op::Eq    => cell_n == *n,
                        Op::NotEq => cell_n != *n,
                        Op::Gt    => cell_n > *n,
                        Op::Lt    => cell_n < *n,
                        Op::Gte   => cell_n >= *n,
                        Op::Lte   => cell_n <= *n,
                        _         => false,
                    }
                }
                Value::Float(f) => {
                    let cell_f = json_as_f64(cell);
                    match op {
                        Op::Eq    => (cell_f - f).abs() < 1e-9,
                        Op::NotEq => (cell_f - f).abs() >= 1e-9,
                        Op::Gt    => cell_f > *f,
                        Op::Lt    => cell_f < *f,
                        Op::Gte   => cell_f >= *f,
                        Op::Lte   => cell_f <= *f,
                        _         => false,
                    }
                }
            };
            matched
        }
    }
}

fn json_as_str(v: &JsValue) -> String {
    match v {
        JsValue::String(s) => s.clone(),
        JsValue::Number(n) => n.to_string(),
        JsValue::Bool(b)   => b.to_string(),
        JsValue::Null      => String::new(),
        other              => other.to_string(),
    }
}

fn json_as_i64(v: &JsValue) -> i64 {
    match v {
        JsValue::Number(n) => n.as_i64().unwrap_or(0),
        JsValue::String(s) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

fn json_as_f64(v: &JsValue) -> f64 {
    match v {
        JsValue::Number(n) => n.as_f64().unwrap_or(0.0),
        JsValue::String(s) => s.parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// SQL-style LIKE pattern matching. `%` = any substring, `_` = any single char.
fn like_match(text: &str, pattern: &str) -> bool {
    let text_chars: Vec<char> = text.chars().collect();
    let pat_chars:  Vec<char> = pattern.chars().collect();
    like_match_inner(&text_chars, &pat_chars)
}

fn like_match_inner(text: &[char], pat: &[char]) -> bool {
    if pat.is_empty() { return text.is_empty(); }
    if pat[0] == '%' {
        for i in 0..=text.len() {
            if like_match_inner(&text[i..], &pat[1..]) { return true; }
        }
        return false;
    }
    if text.is_empty() { return false; }
    let head_match = pat[0] == '_' || pat[0].to_lowercase().eq(text[0].to_lowercase());
    head_match && like_match_inner(&text[1..], &pat[1..])
}

// ─── Projection ───────────────────────────────────────────────────────────────

fn project_row(row: Row, projection: &Projection) -> Row {
    match projection {
        Projection::All => row,
        Projection::Columns(cols) => {
            let mut projected = Row::new();
            for col in cols {
                if let Some(val) = row.get(col) {
                    projected.insert(col.clone(), val.clone());
                } else {
                    projected.insert(col.clone(), JsValue::Null);
                }
            }
            projected
        }
    }
}

fn projection_columns(projection: &Projection, sample: Option<&Row>) -> Vec<String> {
    match projection {
        Projection::Columns(cols) => cols.clone(),
        Projection::All => sample
            .map(|r| r.keys().cloned().collect())
            .unwrap_or_default(),
    }
}

// ─── Public executor entry-point ──────────────────────────────────────────────

/// Execute a parsed `SelectStatement` and return the result set.
///
/// # Errors
/// Returns an error if the table name is unknown or data collection fails.
pub fn execute(stmt: &SelectStatement) -> Result<QueryResult> {
    debug!("ThorQL execute: FROM {}", stmt.table);

    let source = resolve_source(&stmt.table)?;
    let all_rows = source.scan();
    let scanned  = all_rows.len();

    let filtered: Vec<Row> = all_rows
        .into_iter()
        .filter(|row| {
            stmt.condition.as_ref()
                .map(|expr| eval_expr(expr, row))
                .unwrap_or(true)
        })
        .map(|row| project_row(row, &stmt.projection))
        .collect();

    let columns = projection_columns(&stmt.projection, filtered.first());

    Ok(QueryResult { columns, rows: filtered, scanned })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::parser::parse;

    #[test]
    fn execute_processes_table() {
        let stmt = parse("SELECT pid, name FROM processes").unwrap();
        let result = execute(&stmt).unwrap();
        assert!(!result.rows.is_empty(), "Should have at least one process (self)");
        // Every row should have 'pid' and 'name'
        for row in &result.rows {
            assert!(row.contains_key("pid"), "Missing 'pid' column");
            assert!(row.contains_key("name"), "Missing 'name' column");
        }
    }

    #[test]
    fn execute_users_table() {
        let stmt = parse("SELECT username, uid FROM users").unwrap();
        let result = execute(&stmt).unwrap();
        // Should have at least root
        assert!(!result.rows.is_empty());
        let has_root = result.rows.iter().any(|r| {
            r.get("username").and_then(|v| v.as_str()) == Some("root")
        });
        assert!(has_root, "root user should be present");
    }

    #[test]
    fn execute_cron_jobs_table() {
        let stmt = parse("SELECT * FROM cron_jobs").unwrap();
        let result = execute(&stmt);
        assert!(result.is_ok(), "cron_jobs scan should not panic");
    }

    #[test]
    fn like_filter_works() {
        assert!(like_match("bash --login", "%bash%"));
        assert!(!like_match("python3", "%bash%"));
        assert!(like_match("nc -e /bin/sh", "%-e%"));
        assert!(like_match("any", "%"));
    }

    #[test]
    fn unknown_table_returns_error() {
        let stmt = parse("SELECT * FROM nonexistent_table_xyz").unwrap();
        assert!(execute(&stmt).is_err());
    }
}
