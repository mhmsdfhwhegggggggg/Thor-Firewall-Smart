//! Event enrichment — adds context (hostname, GeoIP stub, flow state) to raw events

use std::net::Ipv4Addr;
use std::sync::Arc;
use crate::events::RawEvent;
use crate::state::ThorState;

pub struct EnrichedEvent {
    pub raw: RawEvent,
    pub hostname: Option<String>,
    pub src_ip_str: Option<String>,
    pub dst_ip_str: Option<String>,
    pub country_code: Option<String>,
    pub asn: Option<String>,
    pub is_internal: bool,
}

pub struct EventEnricher {
    state: Arc<ThorState>,
    local_hostname: String,
}

impl EventEnricher {
    pub fn new(state: Arc<ThorState>) -> Self {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        Self { state, local_hostname: hostname }
    }

    pub async fn enrich(&self, raw: RawEvent) -> EnrichedEvent {
        let (src_ip_str, dst_ip_str, is_internal) = match &raw {
            RawEvent::Network(e) => {
                let src = e.src_ip.to_string();
                let dst = e.dst_ip.to_string();
                let internal = is_rfc1918(e.dst_ip);
                (Some(src), Some(dst), internal)
            }
            RawEvent::XdpDrop { src_ip, dst_ip, .. } => {
                let src = Ipv4Addr::from(*src_ip).to_string();
                let dst = Ipv4Addr::from(*dst_ip).to_string();
                (Some(src), Some(dst), false)
            }
            _ => (None, None, true),
        };

        EnrichedEvent {
            raw,
            hostname: Some(self.local_hostname.clone()),
            src_ip_str,
            dst_ip_str,
            country_code: None, // GeoIP2 integration stub
            asn: None,
            is_internal,
        }
    }
}

fn is_rfc1918(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10
        || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
        || (octets[0] == 192 && octets[1] == 168)
        || octets[0] == 127
}
