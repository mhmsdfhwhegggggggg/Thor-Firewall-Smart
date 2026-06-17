//! Event enrichment — adds context (hostname, GeoIP stub, flow state, IOC) to raw events

use std::net::Ipv4Addr;
use std::sync::Arc;
use crate::events::RawEvent;
use crate::state::ThorState;

#[derive(Clone)]
pub struct EnrichedEvent {
    pub raw:          RawEvent,
    pub hostname:     Option<String>,
    pub src_ip_str:   Option<String>,
    pub dst_ip_str:   Option<String>,
    pub country_code: Option<String>,
    pub asn:          Option<String>,
    pub is_internal:  bool,
    /// Whether src/dst IP or domain matched an IOC entry
    pub ioc_matched:  bool,

    // ── Phase 3 Axis 1: Sequence Detection enrichment fields ──────────────
    // These are populated by higher-level event parsers (Sysmon, Windows
    // Security Log, Linux audit) before events reach the SequenceDetector.
    // They remain `None` for raw eBPF events that lack this context.

    /// Full command line of the spawned process
    pub command_line:  Option<String>,
    /// Process executable name (basename of image path)
    pub process_name:  Option<String>,
    /// Logical event type string, e.g. "process_create", "network_connect"
    pub event_type:    Option<String>,
    /// OS user / UID that executed the action
    pub user_id:       Option<String>,
    /// Process ID of the subject process
    pub pid:           Option<u32>,
}

impl Default for EnrichedEvent {
    fn default() -> Self {
        use crate::events::RawEvent;
        // Minimal stub used by unit/integration tests that don't exercise the
        // full eBPF pipeline. The `raw` field requires a concrete variant;
        // we use a zero-value XdpDrop as the lightest-weight option.
        Self {
            raw:          RawEvent::XdpDrop {
                src_ip: 0, dst_ip: 0, src_port: 0, dst_port: 0,
                reason: 0, timestamp_ns: 0,
            },
            hostname:     None,
            src_ip_str:   None,
            dst_ip_str:   None,
            country_code: None,
            asn:          None,
            is_internal:  true,
            ioc_matched:  false,
            command_line:  None,
            process_name:  None,
            event_type:    None,
            user_id:       None,
            pid:           None,
        }
    }
}

pub struct EventEnricher {
    state:          Arc<ThorState>,
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
                let src = format!("{}", e.src_ip);
                let dst = format!("{}", e.dst_ip);
                let internal = is_rfc1918(e.dst_ip);
                (Some(src), Some(dst), internal)
            }
            RawEvent::XdpDrop { src_ip, dst_ip, .. } => {
                let src = Ipv4Addr::from(*src_ip).to_string();
                let dst = Ipv4Addr::from(*dst_ip).to_string();
                (Some(src), Some(dst), false)
            }
            RawEvent::Tls(e) => {
                let src = Ipv4Addr::from(e.src_ip).to_string();
                let dst = Ipv4Addr::from(e.dst_ip).to_string();
                (Some(src), Some(dst), false)
            }
            _ => (None, None, true),
        };

        // IOC lookup
        let ioc_matched = if let Some(dst) = &dst_ip_str {
            self.state.ioc_db.check(dst).is_some()
        } else {
            false
        };

        EnrichedEvent {
            raw,
            hostname: Some(self.local_hostname.clone()),
            src_ip_str,
            dst_ip_str,
            country_code: None,
            asn: None,
            is_internal,
            ioc_matched,
            // Phase 3 Axis 1 fields — populated by higher-level parsers,
            // not the raw eBPF enricher path.
            command_line: None,
            process_name: None,
            event_type:   None,
            user_id:      None,
            pid:          None,
        }
    }
}

fn is_rfc1918(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10
    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
    || (octets[0] == 192 && octets[1] == 168)
    || octets[0] == 127
}
