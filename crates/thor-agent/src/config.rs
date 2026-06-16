//! Thor Agent Configuration — CLI + YAML + Environment Variables

use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "thor-agent", about = "Thor Firewall Smart — Production Security Agent")]
struct Cli {
    #[arg(short, long, env = "THOR_INTERFACE", default_value = "eth0")]
    interface: String,

    #[arg(short, long, env = "THOR_CONFIG", default_value = "thor.yaml")]
    config: PathBuf,

    #[arg(long, env = "THOR_API_ADDR", default_value = "0.0.0.0:8080")]
    api_addr: SocketAddr,

    #[arg(long, env = "THOR_SIGMA_DIR", default_value = "rules/sigma")]
    sigma_rules_dir: PathBuf,

    #[arg(long, env = "THOR_YARA_DIR", default_value = "rules/yara")]
    yara_rules_dir: PathBuf,

    #[arg(long, env = "THOR_IDS_DIR", default_value = "rules/ids")]
    ids_rules_dir: PathBuf,

    #[arg(long, env = "THOR_MODEL", default_value = "models/thor_ueba_model.onnx")]
    model_path: PathBuf,

    #[arg(long, env = "THEHIVE_URL")]
    thehive_url: Option<String>,

    /// FIM database path
    #[arg(long, env = "THOR_FIM_DB", default_value = "/var/lib/thor/fim.db")]
    fim_db_path: String,

    /// FIM scan interval in seconds
    #[arg(long, env = "THOR_FIM_INTERVAL", default_value = "30")]
    fim_interval_secs: u64,

    /// Enable FIM module
    #[arg(long, env = "THOR_FIM_ENABLED", default_value = "true")]
    fim_enabled: bool,

    /// Enable Threat Intel sync
    #[arg(long, env = "THOR_INTEL_ENABLED", default_value = "true")]
    intel_enabled: bool,

    /// AlienVault OTX API key (optional)
    #[arg(long, env = "THOR_OTX_API_KEY")]
    otx_api_key: Option<String>,

    /// Audit log path
    #[arg(long, env = "THOR_AUDIT_DB_PATH", default_value = "/var/lib/thor/audit.db")]
    audit_db_path: String,

    /// Metrics bind address
    #[arg(long, env = "THOR_METRICS_BIND", default_value = "0.0.0.0:9090")]
    metrics_bind: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThorConfig {
    pub interface:        String,
    pub api_addr:         SocketAddr,
    pub metrics_bind:     SocketAddr,
    pub sigma_rules_dir:  PathBuf,
    pub yara_rules_dir:   PathBuf,
    pub ids_rules_dir:    PathBuf,
    pub model_path:       PathBuf,
    pub thehive_url:      Option<String>,
    pub audit_db_path:    String,

    // FIM
    pub fim_db_path:       String,
    pub fim_interval_secs: u64,
    pub fim_enabled:       bool,

    // Intel
    pub intel_enabled: bool,
    pub otx_api_key:   Option<String>,

    // Performance tuning
    pub flow_map_shards:     usize,
    pub ioc_bloom_capacity:  usize,
    pub ioc_bloom_fpr:       f64,
    pub xdp_rate_limit_pps:  u32,
    pub max_ws_clients:      usize,
    pub dedup_window_secs:   u64,
}

impl ThorConfig {
    pub fn load() -> Result<Self> {
        let cli = Cli::parse();
        Ok(Self {
            interface:        cli.interface,
            api_addr:         cli.api_addr,
            metrics_bind:     cli.metrics_bind,
            sigma_rules_dir:  cli.sigma_rules_dir,
            yara_rules_dir:   cli.yara_rules_dir,
            ids_rules_dir:    cli.ids_rules_dir,
            model_path:       cli.model_path,
            thehive_url:      cli.thehive_url,
            audit_db_path:    cli.audit_db_path,
            fim_db_path:      cli.fim_db_path,
            fim_interval_secs: cli.fim_interval_secs,
            fim_enabled:      cli.fim_enabled,
            intel_enabled:    cli.intel_enabled,
            otx_api_key:      cli.otx_api_key,
            // Computed from CPU count
            flow_map_shards:    num_cpus::get() * 4,
            ioc_bloom_capacity: 10_000_000,   // 10M IOC capacity
            ioc_bloom_fpr:      0.001,
            xdp_rate_limit_pps: 10_000,
            max_ws_clients:     100,
            dedup_window_secs:  60,
        })
    }
}
