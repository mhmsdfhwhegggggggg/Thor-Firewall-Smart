use aya::{include_bytes_aligned, Ebpf};
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};

#[derive(Debug, Parser)]
struct Args {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let args = Args::parse();
    
    // تحميل البرنامج
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/debug/thor-xdp-ebpf"
    ))?;
    
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/release/thor-xdp-ebpf"
    ))?;
    
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }
    
    // تحميل IPs من ملف
    let mut blocked_ips: HashMap<_, u32, u8> = 
        HashMap::try_from(bpf.map_mut("BLOCKED_IPS").unwrap())?;
    
    if let Ok(ips) = std::fs::read_to_string("/etc/thor/blocked-ips.txt") {
        for line in ips.lines() {
            if let Ok(ip) = line.parse::<u32>() {
                if let Err(e) = blocked_ips.insert(ip, 1, 0) {
                    warn!("Failed to insert blocked IP {}: {}", ip, e);
                }
            }
        }
    } else {
        warn!("/etc/thor/blocked-ips.txt not found. Continuing with empty blocked IPs.");
    }
    
    // تفعيل XDP
    let program: &mut Xdp = bpf.program_mut("thor_xdp").unwrap().try_into()?;
    program.load()?;
    program.attach(&args.iface, XdpFlags::default())
        .map_err(|e| anyhow::anyhow!("Failed to attach XDP: {}", e))?;
    
    info!("Thor XDP active on {}", args.iface);
    
    tokio::signal::ctrl_c().await?;
    info!("Stopping...");
    
    Ok(())
}
