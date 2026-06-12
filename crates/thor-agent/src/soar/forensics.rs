//! Forensic Collector — concurrent /proc snapshot for incident response

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tracing::info;

#[derive(Debug, Serialize, Deserialize)]
pub struct ForensicCapture {
    pub pid: u32,
    pub captured_at: String,
    pub cmdline: Option<String>,
    pub exe_path: Option<String>,
    pub cwd: Option<String>,
    pub open_fds: Vec<String>,
    pub maps: Option<String>,
    pub net_tcp: Option<String>,
    pub environ_vars: usize,
    pub dump_path: String,
}

pub struct ForensicCollector {
    output_dir: PathBuf,
}

impl ForensicCollector {
    pub fn new(output_dir: impl Into<PathBuf>) -> Self {
        Self { output_dir: output_dir.into() }
    }

    /// Concurrent /proc capture — uses rayon for parallel file reads
    pub async fn capture(&self, pid: u32) -> Result<String> {
        info!("🔬 Starting forensic capture for PID {}", pid);
        let out_dir = self.output_dir.clone();

        tokio::task::spawn_blocking(move || {
            fs::create_dir_all(&out_dir).context("Cannot create forensics dir")?;

            let proc_path = PathBuf::from(format!("/proc/{}", pid));
            if !proc_path.exists() {
                return Err(anyhow::anyhow!("Process {} no longer exists", pid));
            }

            // Collect /proc entries concurrently
            use rayon::prelude::*;

            let entries = vec!["cmdline", "status", "maps", "net/tcp", "net/udp", "environ", "fd"];
            let results: Vec<(String, Option<String>)> = entries.par_iter().map(|entry| {
                let path = proc_path.join(entry);
                let content = if *entry == "cmdline" {
                    fs::read(&path).ok().map(|b| {
                        b.iter().map(|&c| if c == 0 { ' ' } else { c as char }).collect()
                    })
                } else {
                    fs::read_to_string(&path).ok()
                };
                (entry.to_string(), content)
            }).collect();

            // List open file descriptors
            let fd_dir = proc_path.join("fd");
            let open_fds: Vec<String> = fs::read_dir(&fd_dir)
                .map(|entries| {
                    entries.filter_map(|e| e.ok())
                        .filter_map(|e| fs::read_link(e.path()).ok())
                        .map(|l| l.to_string_lossy().to_string())
                        .collect()
                })
                .unwrap_or_default();

            let mut capture = ForensicCapture {
                pid,
                captured_at: Utc::now().to_rfc3339(),
                cmdline: None, exe_path: None, cwd: None,
                open_fds: open_fds.iter().take(100).cloned().collect(),
                maps: None, net_tcp: None,
                environ_vars: 0,
                dump_path: String::new(),
            };

            for (key, val) in &results {
                match key.as_str() {
                    "cmdline" => capture.cmdline = val.clone(),
                    "maps" => capture.maps = val.as_ref().map(|s| s.chars().take(4096).collect()),
                    "net/tcp" => capture.net_tcp = val.as_ref().map(|s| s.chars().take(2048).collect()),
                    "environ" => capture.environ_vars = val.as_ref().map(|s| s.split('\0').count()).unwrap_or(0),
                    _ => {}
                }
            }

            // exe symlink
            capture.exe_path = fs::read_link(proc_path.join("exe"))
                .ok().map(|p| p.to_string_lossy().to_string());
            // cwd symlink
            capture.cwd = fs::read_link(proc_path.join("cwd"))
                .ok().map(|p| p.to_string_lossy().to_string());

            // Write dump
            let ts = Utc::now().format("%Y%m%d_%H%M%S");
            let dump_file = out_dir.join(format!("forensic_pid{}_{}.json", pid, ts));
            let json = serde_json::to_string_pretty(&capture)?;
            fs::write(&dump_file, &json).context("Failed to write forensic dump")?;
            capture.dump_path = dump_file.to_string_lossy().to_string();

            info!("✅ Forensic capture complete: {} bytes → {}", json.len(), dump_file.display());
            Ok(capture.dump_path)
        }).await.context("spawn_blocking failed")?
    }
}
