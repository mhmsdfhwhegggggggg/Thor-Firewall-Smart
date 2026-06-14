#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    programs::XdpContext,
    maps::HashMap,
};
use aya_log_ebpf::info;

// قاعدة بيانات IPs من SOC
#[map(name = "BLOCKED_IPS")]
static BLOCKED_IPS: HashMap<u32, u8> = HashMap::with_max_entries(100000, 0);

#[map(name = "RATE_LIMIT")]
static RATE_LIMIT: HashMap<u32, u64> = HashMap::with_max_entries(1000000, 0);

#[xdp(name = "thor_xdp")]
pub fn thor_xdp(ctx: XdpContext) -> u32 {
    match try_thor(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_thor(ctx: XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    
    // Ethernet header (14 bytes)
    if data + 14 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    
    // IP header (20 bytes min)
    let ip_header = data + 14;
    if ip_header + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    
    // استخراج IP المصدر
    let src_ip = unsafe {
        let ip = ip_header as *const u8;
        u32::from_be_bytes([
            *ip.add(12),
            *ip.add(13),
            *ip.add(14),
            *ip.add(15),
        ])
    };
    
    // فحص القائمة السوداء
    unsafe {
        if BLOCKED_IPS.get(&src_ip).is_some() {
            info!(&ctx, "Thor: Blocked IP {}", src_ip);
            return Ok(xdp_action::XDP_DROP);
        }
    }
    
    // Rate Limiting (Token Bucket بسيط)
    let now = unsafe { core::arch::x86_64::_rdtsc() };
    unsafe {
        if let Some(last) = RATE_LIMIT.get(&src_ip) {
            if now - *last < 1_000_000_000 { // 1 ثانية
                return Ok(xdp_action::XDP_DROP);
            }
        }
        let _ = RATE_LIMIT.insert(&src_ip, &now, 0);
    }
    
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
