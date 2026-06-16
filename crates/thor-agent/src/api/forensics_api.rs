//! Forensics API handlers — exposes Axis-3 DFIR capabilities over REST.
//!
//! Routes (all require Analyst+ JWT):
//!
//! | Method | Path                              | Handler               |
//! |--------|-----------------------------------|-----------------------|
//! | POST   | /api/v1/forensics/query           | run_thorql_query      |
//! | POST   | /api/v1/forensics/artifact        | run_artifact_handler  |
//! | GET    | /api/v1/forensics/artifacts       | list_artifacts        |
//! | POST   | /api/v1/forensics/collect         | collect_files         |
//! | POST   | /api/v1/forensics/scan/memory     | scan_process_memory   |
//!
//! All handlers serialize their responses as JSON and return structured
//! errors via `ForensicsError` rather than panicking.

use std::path::PathBuf;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsValue};
use tracing::{error, info, warn};

use crate::forensics::{
    artifacts::ArtifactRegistry,
    collector::{collect_evidence, CollectionRequest, ForensicCollector},
    memory_scanner::{builtin_memory_rules, MemoryScanner},
    thorql::execute_query,
};

use super::ApiState;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Structured error returned by forensics handlers.
#[derive(Debug, Serialize)]
pub struct ForensicsError {
    pub error:   &'static str,
    pub detail:  String,
    pub code:    u16,
}

impl IntoResponse for ForensicsError {
    fn into_response(self) -> Response {
        let code = StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (code, Json(self)).into_response()
    }
}

macro_rules! forensics_err {
    ($code:expr, $msg:literal, $detail:expr) => {
        ForensicsError { error: $msg, detail: format!("{}", $detail), code: $code }
    };
}

// ─── Request / Response shapes ────────────────────────────────────────────────

/// Request body for `RunThorQLQuery`.
#[derive(Debug, Deserialize)]
pub struct ThorQLRequest {
    /// ThorQL query string, e.g. `SELECT pid, name FROM processes WHERE uid = 0`.
    pub query: String,
    /// Optional row limit (default: 1000).
    pub limit: Option<usize>,
}

/// Response body for `RunThorQLQuery`.
#[derive(Debug, Serialize)]
pub struct ThorQLResponse {
    pub columns:      Vec<String>,
    pub rows:         Vec<JsValue>,
    pub row_count:    usize,
    pub rows_scanned: usize,
}

/// Request body for `RunArtifact`.
#[derive(Debug, Deserialize)]
pub struct ArtifactRequest {
    /// Artifact ID, e.g. `"linux.network.active_connections"`.
    pub artifact_id: String,
}

/// Request body for `CollectFiles`.
#[derive(Debug, Deserialize)]
pub struct CollectFilesRequest {
    /// Absolute paths of files or directories to collect.
    pub paths:           Vec<String>,
    /// Optional investigation case label.
    pub case_label:      Option<String>,
    /// Maximum bytes to read per file (default: 50 MB).
    pub max_file_bytes:  Option<u64>,
    /// Whether to follow symlinks.
    pub follow_symlinks: Option<bool>,
}

/// Response body for `CollectFiles`.
#[derive(Debug, Serialize)]
pub struct CollectFilesResponse {
    /// Total number of files in the package.
    pub file_count:     usize,
    /// SHA-256 of the archive (chain of custody).
    pub package_sha256: String,
    /// Per-file manifest.
    pub manifest:       Vec<ManifestEntry>,
    /// RFC-3339 timestamp.
    pub collected_at:   String,
    /// Collecting host.
    pub hostname:       String,
}

#[derive(Debug, Serialize)]
pub struct ManifestEntry {
    pub path:      String,
    pub sha256:    String,
    pub size:      u64,
    pub truncated: bool,
}

/// Request body for `ScanProcessMemory`.
#[derive(Debug, Deserialize)]
pub struct ScanMemoryRequest {
    /// Target process ID.
    pub pid:         u32,
    /// Optional custom YARA rules (uses built-ins if empty).
    pub yara_rules:  Option<Vec<String>>,
}

/// Response body for `ScanProcessMemory`.
#[derive(Debug, Serialize)]
pub struct ScanMemoryResponse {
    pub pid:             u32,
    pub process_name:    String,
    pub match_count:     usize,
    pub regions_scanned: usize,
    pub regions_skipped: usize,
    pub bytes_read:      u64,
    pub completed:       bool,
    pub matches:         Vec<MemoryMatchDto>,
}

#[derive(Debug, Serialize)]
pub struct MemoryMatchDto {
    pub rule_name:    String,
    pub match_offset: String, // hex string for clarity
    pub region_start: String,
    pub region_end:   String,
    pub permissions:  String,
    pub pathname:     String,
    pub tags:         Vec<String>,
}

// ─── Handler: RunThorQLQuery ──────────────────────────────────────────────────

/// Execute a raw ThorQL query and return results as JSON.
///
/// # Route
/// `POST /api/v1/forensics/query`
///
/// # Security
/// Requires Analyst JWT.  Query is parsed and rejected if syntactically invalid
/// before any data is accessed.
pub async fn run_thorql_query(
    State(_state): State<ApiState>,
    Json(req):     Json<ThorQLRequest>,
) -> Result<Json<ThorQLResponse>, ForensicsError> {
    let query = req.query.trim().to_string();
    if query.is_empty() {
        return Err(forensics_err!(400, "empty_query", "Query string must not be empty"));
    }
    if query.len() > 4096 {
        return Err(forensics_err!(400, "query_too_long", "Query exceeds 4096 character limit"));
    }

    info!("ThorQL query: {}", &query[..query.len().min(120)]);

    let limit = req.limit.unwrap_or(1000).min(10_000);

    let result = tokio::task::spawn_blocking(move || execute_query(&query))
        .await
        .map_err(|e| forensics_err!(500, "task_error", e))?
        .map_err(|e| {
            warn!("ThorQL error: {}", e);
            forensics_err!(400, "query_error", e)
        })?;

    let rows_scanned = result.scanned;
    let columns      = result.columns.clone();

    let rows: Vec<JsValue> = result
        .rows
        .into_iter()
        .take(limit)
        .map(|row| json!(row))
        .collect();

    let row_count = rows.len();
    info!("ThorQL: {} rows returned ({} scanned)", row_count, rows_scanned);

    Ok(Json(ThorQLResponse { columns, rows, row_count, rows_scanned }))
}

// ─── Handler: RunArtifact ─────────────────────────────────────────────────────

/// Execute a named forensic artifact and return results as JSON.
///
/// # Route
/// `POST /api/v1/forensics/artifact`
pub async fn run_artifact_handler(
    State(_state): State<ApiState>,
    Json(req):     Json<ArtifactRequest>,
) -> Result<Json<ThorQLResponse>, ForensicsError> {
    let artifact_id = req.artifact_id.trim().to_string();
    if artifact_id.is_empty() {
        return Err(forensics_err!(400, "empty_artifact_id", "artifact_id must not be empty"));
    }

    info!("Running forensic artifact: {}", artifact_id);

    let result = tokio::task::spawn_blocking(move || {
        let registry = ArtifactRegistry::new();
        registry.run(&artifact_id)
    })
    .await
    .map_err(|e| forensics_err!(500, "task_error", e))?
    .map_err(|e| {
        warn!("Artifact error: {}", e);
        forensics_err!(404, "artifact_error", e)
    })?;

    let rows_scanned = result.scanned;
    let columns      = result.columns.clone();

    let rows: Vec<JsValue> = result
        .rows
        .into_iter()
        .take(1000)
        .map(|row| json!(row))
        .collect();

    let row_count = rows.len();
    Ok(Json(ThorQLResponse { columns, rows, row_count, rows_scanned }))
}

// ─── Handler: ListArtifacts ───────────────────────────────────────────────────

/// List all available forensic artifacts.
///
/// # Route
/// `GET /api/v1/forensics/artifacts`
#[derive(Serialize)]
pub struct ArtifactListEntry {
    pub id:          String,
    pub description: String,
}

pub async fn list_artifacts(
    State(_state): State<ApiState>,
) -> Json<JsValue> {
    let registry = ArtifactRegistry::new();
    let entries: Vec<ArtifactListEntry> = registry
        .list()
        .into_iter()
        .map(|(id, desc)| ArtifactListEntry {
            id:          id.to_string(),
            description: desc.to_string(),
        })
        .collect();

    Json(json!({
        "count":     entries.len(),
        "artifacts": entries,
    }))
}

// ─── Handler: CollectFiles ────────────────────────────────────────────────────

/// Collect specified files into a sealed in-memory evidence package.
///
/// # Route
/// `POST /api/v1/forensics/collect`
///
/// # Security
/// Requires Admin JWT.  Archive bytes are returned as base64-encoded JSON to
/// prevent binary encoding issues over REST.
pub async fn collect_files(
    State(_state): State<ApiState>,
    Json(req):     Json<CollectFilesRequest>,
) -> Result<impl IntoResponse, ForensicsError> {
    if req.paths.is_empty() {
        return Err(forensics_err!(400, "no_paths", "paths array must not be empty"));
    }
    if req.paths.len() > 100 {
        return Err(forensics_err!(400, "too_many_paths", "Maximum 100 paths per request"));
    }

    let paths: Vec<PathBuf> = req.paths.iter().map(PathBuf::from).collect();
    let case_label = req.case_label.clone();

    // Basic path traversal guard — reject anything with ".."
    for path in &paths {
        if path.components().any(|c| c.as_os_str() == "..") {
            return Err(forensics_err!(
                400, "path_traversal",
                format!("Path traversal detected in: {}", path.display())
            ));
        }
    }

    let collect_request = CollectionRequest {
        paths,
        case_label,
        max_file_bytes:  req.max_file_bytes.or(Some(50 * 1024 * 1024)),
        follow_symlinks: req.follow_symlinks.unwrap_or(false),
    };

    info!(
        "Evidence collection: {} paths, case={:?}",
        collect_request.paths.len(),
        collect_request.case_label
    );

    let pkg = tokio::task::spawn_blocking(move || {
        ForensicCollector::new().collect_evidence(collect_request)
    })
    .await
    .map_err(|e| forensics_err!(500, "task_error", e))?
    .map_err(|e| {
        error!("Collector error: {}", e);
        forensics_err!(500, "collection_error", e)
    })?;

    // Encode archive as base64 for JSON transport
    use base64::Engine;
    let archive_b64 = base64::engine::general_purpose::STANDARD.encode(&pkg.archive_bytes);

    let manifest: Vec<ManifestEntry> = pkg
        .manifest
        .into_iter()
        .map(|e| ManifestEntry {
            path:      e.path,
            sha256:    e.sha256,
            size:      e.size,
            truncated: e.truncated,
        })
        .collect();

    let response = json!({
        "file_count":     pkg.file_count,
        "package_sha256": pkg.package_sha256,
        "collected_at":   pkg.collected_at,
        "hostname":       pkg.hostname,
        "manifest":       manifest,
        "archive_base64": archive_b64,
        "archive_bytes":  pkg.archive_bytes.len(),
    });

    Ok((StatusCode::OK, Json(response)))
}

// ─── Handler: ScanProcessMemory ───────────────────────────────────────────────

/// Scan a process's memory with YARA rules.
///
/// # Route
/// `POST /api/v1/forensics/scan/memory`
///
/// # Security
/// Requires Admin JWT.  CAP_SYS_PTRACE is required on the host for non-self
/// scans.  Permission errors are returned as structured 403 responses.
pub async fn scan_process_memory(
    State(_state): State<ApiState>,
    Json(req):     Json<ScanMemoryRequest>,
) -> Result<Json<ScanMemoryResponse>, ForensicsError> {
    let pid = req.pid;
    if pid == 0 {
        return Err(forensics_err!(400, "invalid_pid", "PID 0 cannot be scanned"));
    }

    // Validate custom YARA rules if provided
    let custom_rules: Vec<String> = req.yara_rules.clone().unwrap_or_default();
    let use_builtins = custom_rules.is_empty();

    info!(
        "Memory scan: PID {}, {} rules",
        pid,
        if use_builtins { "builtin".to_string() } else { format!("{} custom", custom_rules.len()) }
    );

    let result = tokio::task::spawn_blocking(move || {
        let scanner = MemoryScanner::new();
        if use_builtins {
            let rules = builtin_memory_rules();
            scanner.scan_process(pid, &rules)
        } else {
            let rule_refs: Vec<&str> = custom_rules.iter().map(|s| s.as_str()).collect();
            scanner.scan_process(pid, &rule_refs)
        }
    })
    .await
    .map_err(|e| forensics_err!(500, "task_error", e))?
    .map_err(|e| {
        use crate::forensics::memory_scanner::ScanError;
        match &e {
            ScanError::PermissionDenied        => forensics_err!(403, "permission_denied", e),
            ScanError::ProcessNotFound         => forensics_err!(404, "process_not_found", e),
            ScanError::RuleCompilationError(_) => forensics_err!(400, "rule_compile_error", e),
            ScanError::IoError(_)              => forensics_err!(500, "io_error", e),
        }
    })?;

    let matches: Vec<MemoryMatchDto> = result
        .matches
        .iter()
        .map(|m| MemoryMatchDto {
            rule_name:    m.rule_name.clone(),
            match_offset: format!("0x{:x}", m.match_offset),
            region_start: format!("0x{:x}", m.region.start),
            region_end:   format!("0x{:x}", m.region.end),
            permissions:  m.region.permissions.clone(),
            pathname:     m.region.pathname.clone(),
            tags:         m.tags.clone(),
        })
        .collect();

    if !matches.is_empty() {
        warn!(
            "🚨 Memory scan PID {}: {} YARA matches found",
            pid, matches.len()
        );
    }

    Ok(Json(ScanMemoryResponse {
        pid:             result.pid,
        process_name:    result.process_name,
        match_count:     matches.len(),
        regions_scanned: result.regions_scanned,
        regions_skipped: result.regions_skipped,
        bytes_read:      result.bytes_read,
        completed:       result.completed,
        matches,
    }))
}
