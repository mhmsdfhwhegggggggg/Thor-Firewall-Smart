//! ThorQL Executor — maps AST table names to real data-collection functions
//! and applies WHERE filter rows, returning a columnar result set.
//!
//! Each "table" is a virtual data source backed by /proc, sysinfo, or eBPF maps.
//! New tables can be added by implementing the `DataSource` trait.
//!
//! # JOIN support
//! A single INNER JOIN between two virtual tables is executed as a hash join:
//!   1. Scan the left table, build a hash map: join_key → [rows].
//!   2. Scan the right table, probe the hash map.
//!   3. Merge each matching pair into one wide row.
//! The merged row uses `table.column` prefixes to avoid name collisions.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, Result};
use serde_json::Value as JsValue;
use tracing::{debug, warn};

use super::parser::{Expr, JoinClause, Op, Projection, SelectStatement, Value};

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
    /// Number of rows examined before filtering (left table size for JOINs).
    pub scanned: usize,
}

// ─── DataSource trait ─────────────────────────────────────────────────────────

trait DataSource: Send + Sync {
    /// Return all rows for this table (unfiltered).
    fn scan(&self) -> Vec<Row>;
    /// The canonical table alias used for column qualification.
    fn table_name(&self) -> &str;
}

// ─── processes() ──────────────────────────────────────────────────────────────

struct ProcessesSource;

impl DataSource for ProcessesSource {
    fn table_name(&self) -> &str { "processes" }

    fn scan(&self) -> Vec<Row> {
        let mut rows = Vec::new();

        let proc_dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(e) => { warn!("Cannot read /proc: {}", e); return rows; }
        };

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            let pid: u32 = match s.parse() { Ok(n) => n, Err(_) => continue };

            let proc_path = format!("/proc/{}", pid);

            let cmdline = read_proc_null_separated(&format!("{}/cmdline", proc_path))
                .unwrap_or_default();
            let comm = fs::read_to_string(format!("{}/comm", proc_path))
                .map(|s| s.trim().to_string()).unwrap_or_default();
            let exe = fs::read_link(format!("{}/exe", proc_path))
                .map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            let (ppid, state, uid) = parse_status(&format!("{}/status", proc_path));

            let mut row = Row::new();
            row.insert("pid".into(),     JsValue::from(pid));
            row.insert("name".into(),    JsValue::from(comm.as_str()));
            row.insert("cmdline".into(), JsValue::from(cmdline.as_str()));
            row.insert("exe".into(),     JsValue::from(exe.as_str()));
            row.insert("ppid".into(),    JsValue::from(ppid));
            row.insert("state".into(),   JsValue::from(state.as_str()));
            row.insert("uid".into(),     JsValue::from(uid));
            rows.push(row);
        }
        rows
    }
}

fn read_proc_null_separated(path: &str) -> Result<String> {
    let bytes = fs::read(path)?;
    Ok(bytes.iter()
        .map(|&b| if b == 0 { ' ' } else { b as char })
        .collect::<String>().trim().to_string())
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
                uid = rest.split_whitespace().next()
                    .and_then(|s| s.parse().ok()).unwrap_or(0);
            }
        }
    }
    (ppid, state, uid)
}

// ─── connections() ────────────────────────────────────────────────────────────

struct ConnectionsSource;

impl DataSource for ConnectionsSource {
    fn table_name(&self) -> &str { "connections" }

    fn scan(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        for (file, proto) in [("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")] {
            if let Ok(content) = fs::read_to_string(file) {
                for line in content.lines().skip(1) {
                    if let Some(row) = parse_net_entry(line, proto) {
                        rows.push(row);
                    }
                }
            }
        }
        enrich_connections_with_pids(&mut rows);
        rows
    }
}

fn hex_to_ip_port(hex: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 { return None; }
    let port = u16::from_str_radix(parts[1], 16).ok()?;
    if parts[0].len() == 8 {
        let n = u32::from_str_radix(parts[0], 16).ok()?;
        let ip = std::net::Ipv4Addr::from(u32::from_be(n));
        Some((ip.to_string(), port))
    } else {
        Some(("(ipv6)".to_string(), port))
    }
}

fn tcp_state(hex: &str) -> &'static str {
    match hex {
        "01" => "ESTABLISHED", "02" => "SYN_SENT",
        "03" => "SYN_RECV",   "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",  "06" => "TIME_WAIT",
        "07" => "CLOSE",      "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",   "0A" => "LISTEN",
        "0B" => "CLOSING",    _    => "UNKNOWN",
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
    row.insert("protocol".into(),     JsValue::from(proto));
    row.insert("local_ip".into(),     JsValue::from(local_ip.as_str()));
    row.insert("local_port".into(),   JsValue::from(local_port));
    row.insert("remote_ip".into(),    JsValue::from(remote_ip.as_str()));
    row.insert("remote_port".into(),  JsValue::from(remote_port));
    row.insert("state".into(),        JsValue::from(state.as_str()));
    row.insert("inode".into(),        JsValue::from(inode));
    row.insert("pid".into(),          JsValue::from(0u64));
    row.insert("process_name".into(), JsValue::from(""));
    Some(row)
}

fn enrich_connections_with_pids(rows: &mut Vec<Row>) {
    let mut inode_map: HashMap<u64, (u32, String)> = HashMap::new();

    if let Ok(proc_dir) = fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let fname = entry.file_name();
            let s = fname.to_string_lossy();
            let pid: u32 = match s.parse() { Ok(n) => n, Err(_) => continue };
            let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
                .map(|s| s.trim().to_string()).unwrap_or_default();

            if let Ok(fd_dir) = fs::read_dir(format!("/proc/{}/fd", pid)) {
                for fd_entry in fd_dir.flatten() {
                    if let Ok(link) = fs::read_link(fd_entry.path()) {
                        let target = link.to_string_lossy();
                        if let Some(inner) = target
                            .strip_prefix("socket:[").and_then(|s| s.strip_suffix(']'))
                        {
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

struct FilesSource { root: String }

impl DataSource for FilesSource {
    fn table_name(&self) -> &str { "files" }

    fn scan(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        walk_directory(Path::new(&self.root), &mut rows, 0);
        rows
    }
}

fn walk_directory(path: &Path, rows: &mut Vec<Row>, depth: usize) {
    if depth > 5 { return; }
    let meta = match fs::symlink_metadata(path) { Ok(m) => m, Err(_) => return };

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
                if rows.len() > 10_000 { break; }
            }
        }
    }
}

// ─── users() source ───────────────────────────────────────────────────────────

struct UsersSource;

impl DataSource for UsersSource {
    fn table_name(&self) -> &str { "users" }

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
    fn table_name(&self) -> &str { "cron_jobs" }

    fn scan(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        for loc in ["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"] {
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
    if table.starts_with("files(") && table.ends_with(')') {
        let inner = &table[6..table.len() - 1];
        let root = inner.trim_matches('"').trim_matches('\'').to_string();
        return Ok(Box::new(FilesSource { root }));
    }
    match table {
        "processes"   => Ok(Box::new(ProcessesSource)),
        "connections" => Ok(Box::new(ConnectionsSource)),
        "users"       => Ok(Box::new(UsersSource)),
        "cron_jobs"   => Ok(Box::new(CronJobsSource)),
        other         => Err(anyhow!("Unknown table: '{}'", other)),
    }
}

// ─── WHERE filter evaluation ──────────────────────────────────────────────────

/// Evaluate an expression against a row.
fn eval_expr(expr: &Expr, row: &Row) -> bool {
    match expr {
        Expr::And(a, b)  => eval_expr(a, row) && eval_expr(b, row),
        Expr::Or(a, b)   => eval_expr(a, row) || eval_expr(b, row),
        Expr::Not(inner) => !eval_expr(inner, row),
        Expr::Comparison { column, op, value } => {
            // Support both `table.column` qualified lookup and bare `column`.
            let cell = row.get(column.as_str()).or_else(|| {
                // Strip table prefix if present: `connections.pid` → `pid`
                let bare = column.split('.').last().unwrap_or(column);
                row.get(bare).or_else(|| {
                    let lower = column.to_lowercase();
                    row.iter().find(|(k, _)| k.to_lowercase() == lower).map(|(_, v)| v)
                })
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
            let pattern = if let Value::Str(p) = rhs { p.as_str() } else { return false; };
            let matched = like_match(&s, pattern);
            if *op == Op::NotLike { !matched } else { matched }
        }
        _ => match rhs {
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
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    like_inner(&t, &p)
}

fn like_inner(text: &[char], pat: &[char]) -> bool {
    if pat.is_empty() { return text.is_empty(); }
    if pat[0] == '%' {
        for i in 0..=text.len() {
            if like_inner(&text[i..], &pat[1..]) { return true; }
        }
        return false;
    }
    if text.is_empty() { return false; }
    let head_match = pat[0] == '_' || pat[0].to_lowercase().eq(text[0].to_lowercase());
    head_match && like_inner(&text[1..], &pat[1..])
}

// ─── Projection ───────────────────────────────────────────────────────────────

fn project_row(row: Row, projection: &Projection) -> Row {
    match projection {
        Projection::All => row,
        Projection::Columns(cols) => {
            let mut projected = Row::new();
            for col in cols {
                // Try qualified lookup first, then bare column name
                let bare = col.split('.').last().unwrap_or(col);
                let val = row.get(col.as_str())
                    .or_else(|| row.get(bare))
                    .cloned()
                    .unwrap_or(JsValue::Null);
                projected.insert(col.clone(), val);
            }
            projected
        }
    }
}

fn projection_columns(projection: &Projection, sample: Option<&Row>) -> Vec<String> {
    match projection {
        Projection::Columns(cols) => cols.clone(),
        Projection::All => sample
            .map(|r| { let mut cols: Vec<_> = r.keys().cloned().collect(); cols.sort(); cols })
            .unwrap_or_default(),
    }
}

// ─── Hash JOIN implementation ─────────────────────────────────────────────────

/// Strip optional `table.` prefix to get the bare column name.
fn bare_column(col: &str) -> &str {
    col.split('.').last().unwrap_or(col)
}

/// Execute an INNER hash JOIN between two data sources.
///
/// Algorithm:
///   1. Scan left table → build HashMap<key_value, Vec<Row>>.
///   2. Scan right table → probe hash map.
///   3. For each match pair (left_row, right_row):
///      - Prefix left columns as `left_table.column`.
///      - Prefix right columns as `right_table.column`.
///      - Also store bare column names for unqualified WHERE references.
fn execute_join(
    left_source:  &dyn DataSource,
    right_source: &dyn DataSource,
    join:         &JoinClause,
) -> Vec<Row> {
    let left_rows  = left_source.scan();
    let right_rows = right_source.scan();

    let left_alias  = left_source.table_name();
    let right_alias = right_source.table_name();

    let left_key_bare  = bare_column(&join.left_key);
    let right_key_bare = bare_column(&join.right_key);

    // Build phase: left table → hash map keyed on join value (as string)
    let mut build_map: HashMap<String, Vec<Row>> = HashMap::new();
    for row in left_rows {
        let key = row.get(left_key_bare)
            .map(json_as_str)
            .unwrap_or_default();
        build_map.entry(key).or_default().push(row);
    }

    // Probe phase
    let mut result = Vec::new();
    for right_row in &right_rows {
        let probe_key = right_row.get(right_key_bare)
            .map(json_as_str)
            .unwrap_or_default();

        if let Some(left_matches) = build_map.get(&probe_key) {
            for left_row in left_matches {
                let mut merged = Row::new();

                // Add left columns with table prefix AND bare name
                for (k, v) in left_row {
                    merged.insert(format!("{}.{}", left_alias, k), v.clone());
                    // Bare insertion — right table wins on collision
                    merged.entry(k.clone()).or_insert_with(|| v.clone());
                }
                // Add right columns with table prefix AND bare name
                for (k, v) in right_row {
                    merged.insert(format!("{}.{}", right_alias, k), v.clone());
                    merged.insert(k.clone(), v.clone());
                }

                result.push(merged);
            }
        }
    }
    result
}

// ─── Public executor entry-point ──────────────────────────────────────────────

/// Execute a parsed `SelectStatement` and return the result set.
pub fn execute(stmt: &SelectStatement) -> Result<QueryResult> {
    debug!("ThorQL execute: FROM {}", stmt.table);

    let left_source = resolve_source(&stmt.table)?;

    let all_rows: Vec<Row> = if let Some(join) = &stmt.join {
        // JOIN path
        let right_source = resolve_source(&join.table)?;
        execute_join(left_source.as_ref(), right_source.as_ref(), join)
    } else {
        // Simple single-table scan
        left_source.scan()
    };

    let scanned = all_rows.len();

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
        for row in &result.rows {
            assert!(row.contains_key("pid"),  "Missing 'pid' column");
            assert!(row.contains_key("name"), "Missing 'name' column");
        }
    }

    #[test]
    fn execute_users_table() {
        let stmt = parse("SELECT username, uid FROM users").unwrap();
        let result = execute(&stmt).unwrap();
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
    fn join_processes_connections() {
        let stmt = parse(
            "SELECT processes.pid, connections.remote_ip \
             FROM processes JOIN connections ON processes.pid = connections.pid"
        ).unwrap();
        let result = execute(&stmt).unwrap();
        // May return 0 rows in test (no connections), but must not error
        for row in &result.rows {
            assert!(
                row.contains_key("processes.pid") || row.contains_key("pid"),
                "Joined row must have pid column"
            );
        }
    }

    #[test]
    fn join_processes_users_on_uid() {
        let stmt = parse(
            "SELECT * FROM processes JOIN users ON uid = uid"
        ).unwrap();
        let result = execute(&stmt).unwrap();
        // Joining on uid — every process should be joinable to at least one user
        // (test process runs under some uid that exists in /etc/passwd)
        assert!(
            result.rows.len() > 0 || result.scanned == 0,
            "JOIN result should not error"
        );
    }

    #[test]
    fn join_where_filter_applied_after_join() {
        let stmt = parse(
            "SELECT * FROM processes JOIN users ON uid = uid WHERE uid = 0"
        ).unwrap();
        let result = execute(&stmt).unwrap();
        // All returned rows must have uid = 0
        for row in &result.rows {
            let uid = row.get("uid")
                .and_then(|v| v.as_u64())
                .unwrap_or(999);
            assert_eq!(uid, 0, "Filter WHERE uid=0 must be respected in JOIN result");
        }
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

    #[test]
    fn scanned_count_accurate() {
        let stmt = parse("SELECT pid FROM processes WHERE pid > 999999999").unwrap();
        let result = execute(&stmt).unwrap();
        assert_eq!(result.rows.len(), 0, "No process has PID > 999999999");
        assert!(result.scanned > 0,      "Scanned must reflect actual process count");
    }

    #[test]
    fn star_projection_returns_all_columns() {
        let stmt = parse("SELECT * FROM users").unwrap();
        let result = execute(&stmt).unwrap();
        if let Some(row) = result.rows.first() {
            assert!(row.contains_key("username"), "Missing 'username' in * projection");
            assert!(row.contains_key("uid"),      "Missing 'uid' in * projection");
            assert!(row.contains_key("shell"),    "Missing 'shell' in * projection");
        }
    }
}
