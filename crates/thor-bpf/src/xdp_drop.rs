//! XDP Threat Dropper — user-space loader + map manager using Aya
use aya::maps::{LpmTrie, LruHashMap, PerCpuArray, MapData};
use aya::programs::Xdp;
use aya::Ebpf;
use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{info, warn};
use thor_common::{LpmKey, ThorStats, RateLimitConfig, STATS_MAP_KEY, DEFAULT_RATE_LIMIT_PPS, DEFAULT_RATE_WINDOW_NS};

pub struct XdpThreatDropper {
    interface: String,
    blocklist_ips: LpmTrie<MapData, LpmKey, u8>,
    blocklist_ports: LruHashMap<MapData, u16, u8>,
    stats: PerCpuArray<MapData, ThorStats>,
    rate_limit_config: RateLimitConfig,
}

impl XdpThreatDropper {
    pub fn load_and_attach(bpf: &mut Ebpf, interface: &str) -> Result<Self> {
        info!("🔧 Loading XDP program on interface: {}", interface);
        let program: &mut Xdp = bpf
            .program_mut("thor_xdp_drop")
            .context("XDP program 'thor_xdp_drop' not found in ELF")?
            .try_into()
            .context("Failed to cast to XDP")?;
        program.load().context("Failed to load XDP program")?;
        let attach_result = program.attach(interface, aya::programs::XdpFlags::DRV_MODE)
            .or_else(|e| { warn!("DRV mode failed ({}), trying SKB", e); program.attach(interface, aya::programs::XdpFlags::SKB_MODE) })
            .or_else(|e| { warn!("SKB mode failed ({}), trying generic", e); program.attach(interface, aya::programs::XdpFlags::UPDATE_IF_NOEXIST) });
        attach_result.with_context(|| format!("Failed to attach XDP to '{}'", interface))?;
        info!("✅ XDP program attached to {}", interface);
        let blocklist_ips = LpmTrie::try_from(bpf.take_map("thor_blocklist_ips").context("Map not found")?).context("LpmTrie cast failed")?;
        let blocklist_ports = LruHashMap::try_from(bpf.take_map("thor_blocklist_ports").context("Map not found")?).context("LruHashMap cast failed")?;
        let stats = PerCpuArray::try_from(bpf.take_map("thor_stats").context("Map not found")?).context("PerCpuArray cast failed")?;
        Ok(Self { interface: interface.to_string(), blocklist_ips, blocklist_ports, stats, rate_limit_config: RateLimitConfig::default() })
    }

    pub fn block_ip(&mut self, ip: Ipv4Addr) -> Result<()> {
        let key = LpmKey { prefixlen: 32, ip: u32::from(ip) };
        self.blocklist_ips.insert(&key, &1, 0).with_context(|| format!("Failed to block IP {}", ip))?;
        info!("🚫 Blocked IP: {} at XDP level", ip); Ok(())
    }

    pub fn block_cidr(&mut self, network: ipnetwork::Ipv4Network) -> Result<()> {
        let key = LpmKey { prefixlen: network.prefix() as u32, ip: u32::from(network.ip()) };
        self.blocklist_ips.insert(&key, &1, 0).with_context(|| format!("Failed to block CIDR {}", network))?;
        info!("🚫 Blocked CIDR: {} at XDP level", network); Ok(())
    }

    pub fn unblock_ip(&mut self, ip: Ipv4Addr) -> Result<()> {
        let key = LpmKey { prefixlen: 32, ip: u32::from(ip) };
        self.blocklist_ips.remove(&key).with_context(|| format!("Failed to unblock IP {}", ip))?;
        info!("✅ Unblocked IP: {}", ip); Ok(())
    }

    pub fn block_port(&mut self, port: u16) -> Result<()> {
        self.blocklist_ports.insert(&port, &1, 0).with_context(|| format!("Failed to block port {}", port))?;
        info!("🚫 Blocked port: {} at XDP level", port); Ok(())
    }

    pub fn unblock_port(&mut self, port: u16) -> Result<()> {
        self.blocklist_ports.remove(&port).with_context(|| format!("Failed to unblock port {}", port))?;
        info!("✅ Unblocked port: {}", port); Ok(())
    }

    pub fn load_ip_blocklist<I: IntoIterator<Item = Ipv4Addr>>(&mut self, ips: I) -> Result<usize> {
        let mut count = 0;
        for ip in ips { if self.block_ip(ip).is_ok() { count += 1; } }
        info!("📥 Loaded {} IPs into XDP blocklist", count); Ok(count)
    }

    pub fn get_stats(&self) -> Result<ThorStats> {
        let per_cpu: Vec<ThorStats> = self.stats.get(&STATS_MAP_KEY, 0).context("Failed to read stats")?;
        Ok(per_cpu.iter().fold(ThorStats::default(), |acc, s| ThorStats {
            packets_processed: acc.packets_processed.saturating_add(s.packets_processed),
            packets_dropped: acc.packets_dropped.saturating_add(s.packets_dropped),
            events_generated: acc.events_generated.saturating_add(s.events_generated),
            ip_blocklist_hits: acc.ip_blocklist_hits.saturating_add(s.ip_blocklist_hits),
            port_blocklist_hits: acc.port_blocklist_hits.saturating_add(s.port_blocklist_hits),
            rate_limit_hits: acc.rate_limit_hits.saturating_add(s.rate_limit_hits),
            malformed_packets: acc.malformed_packets.saturating_add(s.malformed_packets),
            process_exec_events: acc.process_exec_events.saturating_add(s.process_exec_events),
            process_exit_events: acc.process_exit_events.saturating_add(s.process_exit_events),
            network_connect_events: acc.network_connect_events.saturating_add(s.network_connect_events),
            errors: acc.errors.saturating_add(s.errors),
        }))
    }

    pub fn reset_stats(&mut self) -> Result<()> {
        self.stats.insert(&STATS_MAP_KEY, &ThorStats::default(), 0).context("Failed to reset stats")?;
        info!("🔄 Statistics reset"); Ok(())
    }

    pub fn interface(&self) -> &str { &self.interface }
}

pub struct XdpStatsMonitor {
    dropper: Arc<RwLock<XdpThreatDropper>>,
    interval: Duration,
}

impl XdpStatsMonitor {
    pub fn new(dropper: Arc<RwLock<XdpThreatDropper>>, interval_secs: u64) -> Self {
        Self { dropper, interval: Duration::from_secs(interval_secs) }
    }
    pub async fn run(&self) {
        let mut ticker = time::interval(self.interval);
        loop {
            ticker.tick().await;
            let dropper = self.dropper.read().await;
            match dropper.get_stats() {
                Ok(stats) => info!("📊 XDP | Processed:{} Dropped:{} IP-hits:{} Rate-limit:{} Errors:{}",
                    stats.packets_processed, stats.packets_dropped, stats.ip_blocklist_hits,
                    stats.rate_limit_hits, stats.errors),
                Err(e) => warn!("Failed to read XDP stats: {}", e),
            }
        }
    }
}
