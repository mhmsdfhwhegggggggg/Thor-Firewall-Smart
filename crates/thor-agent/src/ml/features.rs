//! Feature extraction for ML scoring — 28 features per event

use crate::events::enrichment::EnrichedEvent;
use crate::events::RawEvent;
use chrono::Timelike;

pub const N_FEATURES: usize = 28;

pub fn extract_features(event: &EnrichedEvent) -> Vec<f32> {
    let mut f = vec![0.0f32; N_FEATURES];
    let now = chrono::Utc::now();
    let hour = now.hour() as f32;

    match &event.raw {
        RawEvent::Process(e) => {
            f[0] = (e.pid as f32) / 65535.0;
            f[1] = 0.1; // ppid placeholder
            f[2] = ((e.cmdline.len() as f32 + 1.0).ln()).min(10.0);
            f[3] = e.cmdline.split_whitespace().count() as f32;
            f[4] = if e.cmdline.contains("base64") { 1.0 } else { 0.0 };
            f[5] = if e.cmdline.contains('|') { 1.0 } else { 0.0 };
            f[6] = if e.cmdline.contains("/dev/tcp") { 1.0 } else { 0.0 };
            f[7] = if e.cmdline.starts_with("/tmp/") || e.cmdline.starts_with("/dev/shm") { 1.0 } else { 0.0 };
            let pname = e.parent_name.as_deref().unwrap_or("");
            f[8] = if pname.ends_with("bash") || pname.ends_with("sh") || pname.ends_with("zsh") { 1.0 } else { 0.0 };
            f[9] = if pname.contains("apache") || pname.contains("nginx") || pname.contains("php") { 1.0 } else { 0.0 };
            f[10] = if e.uid == 0 { 1.0 } else { 0.0 };
            f[11] = 0.0; // suid: need metadata
        }
        RawEvent::Network(e) => {
            f[12] = (e.dst_port as f32) / 65535.0;
            f[13] = if let Some(ip) = event.dst_ip_str.as_deref() {
                is_internal_ip(ip) as u8 as f32
            } else { 0.0 };
            // IOC hit
            f[15] = if event.ioc_matched { 1.0 } else { 0.0 };
            f[18] = ((e.bytes_out as f32 + 1.0).ln()).min(20.0);
            f[19] = ((e.bytes_in as f32 + 1.0).ln()).min(20.0);
            // Protocol one-hot
            match e.protocol.as_str() {
                "TCP"  => f[21] = 1.0,
                "UDP"  => f[22] = 1.0,
                "ICMP" => f[23] = 1.0,
                "DNS"  => f[24] = 1.0,
                "TLS"  => f[25] = 1.0,
                _ => {}
            }
        }
        RawEvent::Dns(e) => {
            f[12] = 53.0 / 65535.0;
            f[24] = 1.0;
        }
        _ => {}
    }

    // Temporal features (cyclical encoding)
    f[26] = (hour * 2.0 * std::f32::consts::PI / 24.0).sin();
    f[27] = (hour * 2.0 * std::f32::consts::PI / 24.0).cos();

    f
}

fn is_internal_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
        match addr {
            std::net::IpAddr::V4(v4) => {
                let octets = v4.octets();
                octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
                || octets[0] == 127
            }
            _ => false,
        }
    } else {
        false
    }
}
