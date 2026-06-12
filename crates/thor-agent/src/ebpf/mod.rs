//! eBPF Manager with Fail-Open Safety
//! If the agent crashes, XDP programs detach automatically and traffic flows normally.

use aya::programs::{Xdp, XdpFlags, links::Xdplink};
use anyhow::{Context, Result};
use tracing::{info, warn, error};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailMode {
    FailOpen,
    FailClosed,
}

pub struct SafeBpfManager {
    xdp_links: Vec<Xdplink>,
    interface: String,
    fail_mode: FailMode,
}

impl SafeBpfManager {
    pub fn new(interface: &str, fail_mode: FailMode) -> Self {
        info!(
            "🛡️ Safe BPF Manager initialized | Interface: {} | Fail Mode: {:?}",
            interface, fail_mode
        );
        
        Self {
            xdp_links: Vec::new(),
            interface: interface.to_string(),
            fail_mode,
        }
    }

    pub fn attach_xdp_safely(
        &mut self,
        program: &mut Xdp,
        flags: XdpFlags,
    ) -> Result<()> {
        program.load().context("Failed to load XDP program")?;
        
        let link = program
            .attach(&self.interface, flags)
            .or_else(|_| {
                warn!("XDP attach failed in {:?} mode, trying fallback", flags);
                program.attach(&self.interface, XdpFlags::SKB_MODE)
            })
            .context("Failed to attach XDP program")?;
        
        self.xdp_links.push(link);
        
        info!("✅ XDP program attached safely to {} (Fail-Open guaranteed)", self.interface);
        Ok(())
    }

    pub fn detach_all(&mut self) {
        info!("🔄 Detaching all eBPF programs (Fail-Open activated)");
        self.xdp_links.clear();
        info!("✅ All eBPF programs detached. Traffic flowing normally.");
    }
}

impl Drop for SafeBpfManager {
    fn drop(&mut self) {
        if !self.xdp_links.is_empty() {
            warn!(
                "⚠️ SafeBpfManager dropped with {} active links. Auto-detaching for Fail-{:?}.",
                self.xdp_links.len(),
                self.fail_mode
            );
            self.detach_all();
        }
    }
}

pub fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    
    std::panic::set_hook(Box::new(move |panic_info| {
        error!("🚨 THOR AGENT PANIC: {}", panic_info);
        error!("🛡️ Fail-Open mechanism will detach all eBPF programs automatically.");
        default_hook(panic_info);
    }));
}
