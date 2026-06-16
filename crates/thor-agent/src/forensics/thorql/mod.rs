//! ThorQL — SQL-like query language for endpoint forensics.
//!
//! Supports querying live system state via virtual tables backed by /proc,
//! sysinfo, and eBPF maps.  Syntax is a strict subset of SQL:
//!
//! ```text
//! SELECT <col>[, <col>]* | *
//! FROM   <table>
//! [WHERE <expr>]
//! ```
//!
//! Supported tables: `processes`, `connections`, `users`, `cron_jobs`,
//!                   `files(<path>)`.
//!
//! # Example
//! ```
//! let result = thorql::execute_query(
//!     "SELECT pid, name FROM processes WHERE name LIKE '%sshd%'"
//! ).unwrap();
//! println!("{} rows found", result.rows.len());
//! ```

pub mod executor;
pub mod parser;

use anyhow::Result;
pub use executor::QueryResult;

/// Parse and execute a ThorQL query string.
///
/// # Arguments
/// * `query` — a ThorQL SELECT statement as a UTF-8 string.
///
/// # Returns
/// A `QueryResult` with matching rows, column names, and scan statistics.
///
/// # Errors
/// Returns an error if the query is syntactically invalid or the table
/// does not exist.
pub fn execute_query(query: &str) -> Result<QueryResult> {
    let stmt = parser::parse(query)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    executor::execute(&stmt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_process_query() {
        let result = execute_query(
            "SELECT pid, name, cmdline FROM processes WHERE pid > 0"
        ).unwrap();
        assert!(!result.rows.is_empty());
    }

    #[test]
    fn end_to_end_bad_syntax_returns_err() {
        assert!(execute_query("INVALID QUERY").is_err());
    }
}
