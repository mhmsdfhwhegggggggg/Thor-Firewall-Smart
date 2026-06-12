//! Thor Agent configuration — CLI args + YAML file + env var overrides
use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "thor-agent", about = "Thor Firewall Smart Agent")]
struct Cli {
    /// Network interface to attach XDP program to
    #[arg(short, long, env = "THOR_INTERFACE", default_value = "eth0")]
    interface: String,
    /// Config file path
    #[arg(short, long, env = "THOR_CONFIG", default_value = "thor.yaml")]
    config: PathBuf,
    /// API server bind address
    #[arg(long, env = "THOR_API_ADDR", default_value = "0.0.0.0:8080")]
    api_addr: SocketAddr,
    /// Sigma rules directory
    #[arg(long, env = "THOR_SIGMA_DIR", default_value = "rules/sigma")]
    sigma_rules_dir: PathBuf,
    /// YARA rules directory
    #[arg(long, env = "THOR_YARA_DIR", default_value = "rules/yara")]
    yara_rules_dir: PathBuf,
    /// ONNX model path
    #[arg(long, env = "THOR_MODEL", default_value = "models/thor_ueba_model.onnx")]
    model_path: PathBuf,
    /// TheHive URL for SOAR integration
    #[arg(long, env = "THEHIVE_URL")]
    thehive_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThorConfig {
    pub interface: String,
    pub api_addr: SocketAddr,
    pub sigma_rules_dir: PathBuf,
    pub yara_rules_dir: PathBuf,
    pub model_path: PathBuf,
    pub thehive_url: Option<String>,
    /// Number of DashMap shards for flow table (power of 2)
    pub flow_map_shards: usize,
    /// Bloom filter capacity for IOC negative checks
    pub ioc_bloom_capacity: usize,
    /// Bloom filter false positive rate
    pub ioc_bloom_fpr: f64,
    /// Rate limit: packets per second per IP
    pub xdp_rate_limit_pps: u32,
    /// Max concurrent WebSocket clients
    pub max_ws_clients: usize,
    /// Event dedup window (seconds)
    pub dedup_window_secs: u64,
}

impl ThorConfig {
    pub fn load() -> Result<Self> {
        let cli = Cli::parse();
        Ok(Self {
            interface: cli.interface,
            api_addr: cli.api_addr,
            sigma_rules_dir: cli.sigma_rules_dir,
            yara_rules_dir: cli.yara_rules_dir,
            model_path: cli.model_path,
            thehive_url: cli.thehive_url,
            flow_map_shards: num_cpus::get() * 4,
            ioc_bloom_capacity: 5_000_000,
            ioc_bloom_fpr: 0.001,
            xdp_rate_limit_pps: 10_000,
            max_ws_clients: 100,
            dedup_window_secs: 60,
        })
    }
}
