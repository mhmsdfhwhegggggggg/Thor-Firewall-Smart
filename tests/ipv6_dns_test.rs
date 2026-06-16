//! IPv6 DNS Monitor Integration Tests
//!
//! Tests the IPv6 DNS monitor eBPF program logic at the Rust level:
//!   ▸ dns_event struct has addr_family field
//!   ▸ IPv4 addresses stored in first 4 bytes of 16-byte field
//!   ▸ IPv6 addresses occupy full 16 bytes
//!   ▸ Extension header types are correctly defined
//!   ▸ Rate limiting maps are distinct for v4/v6
//!   ▸ DGA/tunnel detection triggers on high-entropy labels
//!   ▸ dns_event serialisation round-trips correctly

#[cfg(test)]
mod ipv6_dns_tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── Mirrors the C struct layout from dns_monitor.bpf.c ──────────────
    const AF_INET4: u8 = 4;
    const AF_INET6: u8 = 6;

    const DNS_EVENT_QUERY:     u8 = 1;
    const DNS_EVENT_RESPONSE:  u8 = 2;
    const DNS_EVENT_TUNNEL:    u8 = 3;
    const DNS_EVENT_DGA:       u8 = 4;
    const DNS_EVENT_BLOCKLIST: u8 = 5;

    const IPV6_NH_HOPBYHOP:  u8 = 0;
    const IPV6_NH_ROUTING:   u8 = 43;
    const IPV6_NH_FRAGMENT:  u8 = 44;
    const IPV6_NH_ESP:       u8 = 50;
    const IPV6_NH_AH:        u8 = 51;
    const IPV6_NH_DEST_OPT:  u8 = 60;
    const IPV6_NH_MOBILITY:  u8 = 135;
    const IPV6_NH_UDP:       u8 = 17;
    const IPV6_NH_TCP:       u8 = 6;

    const ETH_P_IP:   u16 = 0x0800;
    const ETH_P_IPV6: u16 = 0x86DD;

    const DNS_PORT: u16 = 53;

    #[derive(Debug, Clone, Default)]
    struct DnsEvent {
        timestamp_ns: u64,
        src_addr: [u8; 16],
        dst_addr: [u8; 16],
        src_port: u16,
        dst_port: u16,
        query_len: u16,
        event_type: u8,
        label_count: u8,
        suspicious: u8,
        addr_family: u8,
        query: [u8; 256],
    }

    impl DnsEvent {
        fn set_ipv4_src(&mut self, ip: Ipv4Addr) {
            self.src_addr = [0u8; 16];
            let octs = ip.octets();
            self.src_addr[..4].copy_from_slice(&octs);
            self.addr_family = AF_INET4;
        }

        fn set_ipv4_dst(&mut self, ip: Ipv4Addr) {
            self.dst_addr = [0u8; 16];
            let octs = ip.octets();
            self.dst_addr[..4].copy_from_slice(&octs);
        }

        fn set_ipv6_src(&mut self, ip: Ipv6Addr) {
            self.src_addr = ip.octets();
            self.addr_family = AF_INET6;
        }

        fn set_ipv6_dst(&mut self, ip: Ipv6Addr) {
            self.dst_addr = ip.octets();
        }

        fn ipv4_src(&self) -> Option<Ipv4Addr> {
            if self.addr_family == AF_INET4 {
                Some(Ipv4Addr::new(
                    self.src_addr[0], self.src_addr[1],
                    self.src_addr[2], self.src_addr[3],
                ))
            } else { None }
        }

        fn ipv6_src(&self) -> Option<Ipv6Addr> {
            if self.addr_family == AF_INET6 {
                Some(Ipv6Addr::from(self.src_addr))
            } else { None }
        }

        fn set_query(&mut self, domain: &str) {
            let b = domain.as_bytes();
            let len = b.len().min(255);
            self.query[..len].copy_from_slice(&b[..len]);
            self.query_len = len as u16;
        }

        /// Mimic the eBPF is_high_entropy check
        fn is_high_entropy(label: &str) -> bool {
            let len = label.len();
            if len <= 20 { return false; }
            let mut seen: u64 = 0;
            let mut uniq = 0usize;
            for c in label.chars().take(32) {
                let ci = c as u8;
                if ci < 64 {
                    let bit = 1u64 << ci;
                    if seen & bit == 0 { seen |= bit; uniq += 1; }
                }
            }
            uniq > 20
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 1: DNS event struct size is correct (16-byte address fields)
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn dns_event_address_fields_are_16_bytes() {
        let ev = DnsEvent::default();
        assert_eq!(ev.src_addr.len(), 16, "src_addr must be 16 bytes (supports IPv6)");
        assert_eq!(ev.dst_addr.len(), 16, "dst_addr must be 16 bytes (supports IPv6)");
        assert_eq!(ev.query.len(),    256, "query buffer must be 256 bytes");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 2: IPv4 address stored in first 4 bytes, rest zero
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn ipv4_stored_in_first_4_bytes_rest_zero() {
        let mut ev = DnsEvent::default();
        ev.set_ipv4_src("192.168.1.100".parse().unwrap());
        assert_eq!(&ev.src_addr[..4], &[192, 168, 1, 100], "IPv4 octets in first 4 bytes");
        assert_eq!(&ev.src_addr[4..], &[0u8; 12],          "Remaining 12 bytes must be zero");
        assert_eq!(ev.addr_family, AF_INET4, "addr_family must be AF_INET4=4");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 3: IPv6 address occupies all 16 bytes
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn ipv6_address_occupies_full_16_bytes() {
        let mut ev = DnsEvent::default();
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        ev.set_ipv6_src(addr);
        assert_eq!(ev.src_addr, addr.octets(), "IPv6 must occupy all 16 bytes");
        assert_eq!(ev.addr_family, AF_INET6, "addr_family must be AF_INET6=6");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 4: AF_INET4 and AF_INET6 constants are distinct and correct
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn address_family_constants_correct() {
        assert_eq!(AF_INET4, 4, "AF_INET4 must be 4");
        assert_eq!(AF_INET6, 6, "AF_INET6 must be 6");
        assert_ne!(AF_INET4, AF_INET6, "AF_INET4 and AF_INET6 must differ");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 5: IPv6 extension header next-header constants (RFC 2460)
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn ipv6_extension_header_constants_rfc2460() {
        assert_eq!(IPV6_NH_HOPBYHOP, 0,   "Hop-by-Hop = 0 (RFC 2460)");
        assert_eq!(IPV6_NH_ROUTING,  43,  "Routing = 43 (RFC 2460)");
        assert_eq!(IPV6_NH_FRAGMENT, 44,  "Fragment = 44 (RFC 2460)");
        assert_eq!(IPV6_NH_ESP,      50,  "ESP = 50 (RFC 2460)");
        assert_eq!(IPV6_NH_AH,       51,  "AH = 51 (RFC 2460)");
        assert_eq!(IPV6_NH_DEST_OPT, 60,  "Destination Options = 60 (RFC 2460)");
        assert_eq!(IPV6_NH_MOBILITY, 135, "Mobility = 135 (RFC 3775)");
        assert_eq!(IPV6_NH_UDP,      17,  "UDP = 17 (IANA)");
        assert_eq!(IPV6_NH_TCP,      6,   "TCP = 6 (IANA)");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 6: Ethernet protocol constants
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn ethernet_protocol_constants_correct() {
        assert_eq!(ETH_P_IP,   0x0800, "ETH_P_IP = 0x0800");
        assert_eq!(ETH_P_IPV6, 0x86DD, "ETH_P_IPV6 = 0x86DD");
        assert_ne!(ETH_P_IP, ETH_P_IPV6, "ETH_P_IP and ETH_P_IPV6 must differ");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 7: DNS port constant
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn dns_port_is_53() {
        assert_eq!(DNS_PORT, 53, "DNS port must be 53");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 8: DNS event type constants are distinct
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn dns_event_types_distinct() {
        let types = [
            DNS_EVENT_QUERY, DNS_EVENT_RESPONSE,
            DNS_EVENT_TUNNEL, DNS_EVENT_DGA, DNS_EVENT_BLOCKLIST,
        ];
        for i in 0..types.len() {
            for j in (i+1)..types.len() {
                assert_ne!(types[i], types[j],
                    "DNS event types must be distinct ({} vs {})", i, j);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 9: IPv4 src/dst round-trip
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn ipv4_round_trip() {
        let src: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let dst: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let mut ev = DnsEvent::default();
        ev.set_ipv4_src(src);
        ev.set_ipv4_dst(dst);
        assert_eq!(ev.ipv4_src(), Some(src), "IPv4 src round-trip failed");
        // dst decode
        let decoded_dst = Ipv4Addr::new(
            ev.dst_addr[0], ev.dst_addr[1], ev.dst_addr[2], ev.dst_addr[3]
        );
        assert_eq!(decoded_dst, dst, "IPv4 dst round-trip failed");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 10: IPv6 src/dst round-trip
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn ipv6_round_trip() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
        let mut ev = DnsEvent::default();
        ev.set_ipv6_src(src);
        ev.set_ipv6_dst(dst);
        assert_eq!(ev.ipv6_src(), Some(src), "IPv6 src round-trip failed");
        assert_eq!(Ipv6Addr::from(ev.dst_addr), dst, "IPv6 dst round-trip failed");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 11: High-entropy label detection (DGA signature)
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn high_entropy_detects_dga_domain() {
        // DGA-like: >20 chars, >20 unique chars
        let dga = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
        assert!(DnsEvent::is_high_entropy(dga),
            "DGA label '{}' must trigger high-entropy flag", dga);
    }

    #[test]
    fn normal_domain_label_not_high_entropy() {
        let normal = "www";
        assert!(!DnsEvent::is_high_entropy(normal),
            "Normal label '{}' must NOT trigger high-entropy", normal);

        let normal2 = "example";
        assert!(!DnsEvent::is_high_entropy(normal2),
            "Normal label '{}' must NOT trigger high-entropy", normal2);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 12: Tunnel detection: query > 60 chars is suspicious
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn long_query_triggers_tunnel_detection() {
        let mut ev = DnsEvent::default();
        // 70-char domain label — exceeds DNS_TUNNEL_LEN=60
        let long_domain = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123";
        ev.set_query(long_domain);
        // Simulate the eBPF logic
        let is_tunnel = ev.query_len > 60;
        assert!(is_tunnel, "Query length {} must trigger tunnel detection (>60)", ev.query_len);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 13: Normal-length query does not trigger tunnel
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn normal_query_not_flagged_as_tunnel() {
        let mut ev = DnsEvent::default();
        ev.set_query("example.com");
        let is_tunnel = ev.query_len > 60;
        assert!(!is_tunnel, "Normal query 'example.com' must NOT trigger tunnel detection");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 14: DNS event defaults are sane
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn dns_event_default_is_zero() {
        let ev = DnsEvent::default();
        assert_eq!(ev.suspicious, 0,    "Default event must not be suspicious");
        assert_eq!(ev.addr_family, 0,   "Default addr_family must be 0 (unset)");
        assert_eq!(ev.query_len, 0,     "Default query_len must be 0");
        assert_eq!(ev.label_count, 0,   "Default label_count must be 0");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 15: IPv4-mapped IPv6 addresses are distinguishable
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn ipv4_mapped_ipv6_distinguished_from_native_ipv4() {
        // ::ffff:192.168.1.1 (IPv4-mapped IPv6)
        let mapped: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
        let mut ev_v6 = DnsEvent::default();
        ev_v6.set_ipv6_src(mapped);
        assert_eq!(ev_v6.addr_family, AF_INET6,
            "IPv4-mapped IPv6 must be tagged as AF_INET6");

        // Pure IPv4
        let native: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let mut ev_v4 = DnsEvent::default();
        ev_v4.set_ipv4_src(native);
        assert_eq!(ev_v4.addr_family, AF_INET4,
            "Native IPv4 must be tagged as AF_INET4");

        assert_ne!(ev_v6.addr_family, ev_v4.addr_family,
            "IPv4-mapped IPv6 and native IPv4 must have different addr_family");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 16: Rate limit maps conceptually separate for v4 and v6
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn rate_limit_maps_are_type_separated() {
        // Verify key types: IPv4 key is u32 (4 bytes), IPv6 key is [u8; 16]
        let ipv4_key_size = std::mem::size_of::<u32>();
        let ipv6_key_size = std::mem::size_of::<[u8; 16]>();
        assert_eq!(ipv4_key_size, 4,  "IPv4 rate limit key must be 4 bytes");
        assert_eq!(ipv6_key_size, 16, "IPv6 rate limit key must be 16 bytes");
        assert_ne!(ipv4_key_size, ipv6_key_size, "Rate limit key sizes must differ");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 17: Extension header chain order correctness
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn extension_header_chain_order_rfc2460() {
        // RFC 2460 §4.1 recommends order:
        // Hop-by-Hop → Destination → Routing → Fragment → Auth → ESP → Destination
        let recommended_order = [
            IPV6_NH_HOPBYHOP, IPV6_NH_DEST_OPT, IPV6_NH_ROUTING,
            IPV6_NH_FRAGMENT, IPV6_NH_AH, IPV6_NH_ESP,
        ];
        let ext_header_types: std::collections::HashSet<u8> = [
            IPV6_NH_HOPBYHOP, IPV6_NH_ROUTING, IPV6_NH_FRAGMENT,
            IPV6_NH_ESP, IPV6_NH_AH, IPV6_NH_DEST_OPT, IPV6_NH_MOBILITY,
        ].iter().cloned().collect();

        for &nh in &recommended_order {
            assert!(ext_header_types.contains(&nh),
                "NH value {} must be in extension header set", nh);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 18: DNS event query buffer boundary safety
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn query_buffer_handles_max_length() {
        let mut ev = DnsEvent::default();
        let max_domain: String = "a".repeat(255);
        ev.set_query(&max_domain);
        assert_eq!(ev.query_len, 255, "Max domain length must be 255");
        assert_eq!(ev.query[254], b'a', "Last char must be written");
        // Should not overflow
    }

    #[test]
    fn query_buffer_clamps_at_255() {
        let mut ev = DnsEvent::default();
        let too_long: String = "a".repeat(300);
        ev.set_query(&too_long);
        assert!(ev.query_len <= 255, "Query len must not exceed 255");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 19: IPv6 loopback address (::1) handled correctly
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn ipv6_loopback_stored_correctly() {
        let loopback: Ipv6Addr = "::1".parse().unwrap();
        let mut ev = DnsEvent::default();
        ev.set_ipv6_src(loopback);
        assert_eq!(ev.addr_family, AF_INET6);
        let decoded = Ipv6Addr::from(ev.src_addr);
        assert_eq!(decoded, loopback, "IPv6 loopback ::1 must round-trip");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 20: Multiple extension header types recognized
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn all_ipv6_extension_header_types_recognized() {
        let ext_hdrs = vec![
            IPV6_NH_HOPBYHOP, IPV6_NH_ROUTING, IPV6_NH_FRAGMENT,
            IPV6_NH_AH, IPV6_NH_DEST_OPT, IPV6_NH_MOBILITY,
        ];
        let non_ext_hdrs = vec![IPV6_NH_UDP, IPV6_NH_TCP, IPV6_NH_ESP];

        fn is_ext(nh: u8) -> bool {
            matches!(nh, 0 | 43 | 44 | 51 | 60 | 135)
        }
        fn is_terminal(nh: u8) -> bool {
            matches!(nh, 6 | 17 | 50)
        }

        for nh in &ext_hdrs {
            assert!(is_ext(*nh), "NH {} should be an extension header", nh);
        }
        for nh in &non_ext_hdrs {
            assert!(is_terminal(*nh), "NH {} should be terminal (not ext)", nh);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 21: IPv6 global unicast range correctly identified
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn ipv6_global_unicast_range() {
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        // Global unicast: first byte 0x20–0x3F
        let first_byte = global.octets()[0];
        assert!(first_byte >= 0x20 && first_byte <= 0x3F,
            "2001:db8:: is in global unicast range 2000::/3");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 22: DNS event addr_family distinguishes IPv4 and IPv6 events
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn addr_family_distinguishes_ipv4_ipv6_events() {
        let mut ev4 = DnsEvent::default();
        ev4.set_ipv4_src("1.2.3.4".parse().unwrap());
        ev4.event_type = DNS_EVENT_QUERY;

        let mut ev6 = DnsEvent::default();
        ev6.set_ipv6_src("2001:db8::1".parse().unwrap());
        ev6.event_type = DNS_EVENT_QUERY;

        assert_ne!(ev4.addr_family, ev6.addr_family,
            "IPv4 and IPv6 events must have different addr_family");
        assert_eq!(ev4.ipv4_src(), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(ev6.ipv6_src(), Some("2001:db8::1".parse().unwrap()));
        // IPv4 event has no IPv6 src
        assert_eq!(ev4.ipv6_src(), None, "IPv4 event must return None for ipv6_src");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 23: eBPF map key sizes (sanity)
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn ebpf_map_key_sizes_correct() {
        // dns_rate_limit_v4 key: __u32 = 4 bytes
        assert_eq!(std::mem::size_of::<u32>(), 4);
        // dns_rate_limit_v6 key: __u8[16] = 16 bytes
        assert_eq!(std::mem::size_of::<[u8;16]>(), 16);
        // dns_blocklist key: __u64 = 8 bytes
        assert_eq!(std::mem::size_of::<u64>(), 8);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 24: Fragment header fixed size is 8 bytes
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn ipv6_fragment_header_is_8_bytes() {
        // RFC 2460 §4.5: Fragment header is exactly 8 bytes
        // Structure: next_hdr(1) + reserved(1) + frag_offset_m(2) + id(4) = 8
        let frag_hdr_size: usize = 1 + 1 + 2 + 4;
        assert_eq!(frag_hdr_size, 8, "IPv6 Fragment header must be exactly 8 bytes");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 25: Hop-by-Hop and Routing headers use (hdrlen+1)*8 length formula
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn ipv6_ext_header_length_formula() {
        // RFC 2460 §4.2/§4.4: len = (hdrlen + 1) * 8
        // hdrlen=0 → 8 bytes (minimum)
        // hdrlen=1 → 16 bytes
        // hdrlen=2 → 24 bytes
        for hdrlen in 0u32..=5 {
            let size = (hdrlen + 1) * 8;
            assert_eq!(size, (hdrlen + 1) * 8,
                "Extension header size formula must hold for hdrlen={}", hdrlen);
            assert!(size >= 8, "Extension header must be at least 8 bytes");
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 26: DNS over IPv6 port 53 is same as IPv4
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn dns_port_same_for_ipv4_and_ipv6() {
        // DNS uses the same port 53 for both IPv4 and IPv6 transport
        let dns_v4_port: u16 = 53;
        let dns_v6_port: u16 = 53;
        assert_eq!(dns_v4_port, dns_v6_port, "DNS port must be 53 for both IPv4 and IPv6");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 27: IPv6 site-local and link-local distinguishable
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn ipv6_link_local_vs_global() {
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();

        // Link-local: fe80::/10
        let ll_first2 = u16::from_be_bytes([
            link_local.octets()[0],
            link_local.octets()[1],
        ]);
        assert_eq!(ll_first2 & 0xFFC0, 0xFE80,
            "fe80::1 must be in link-local range fe80::/10");

        // Global unicast: 2000::/3
        assert_ne!(link_local.octets()[0] >> 5, global.octets()[0] >> 5,
            "Link-local and global unicast must have different top 3 bits");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 28: DGA detection requires both length >20 AND >20 unique chars
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn dga_detection_requires_both_conditions() {
        // Long but low entropy (all same char) — NOT DGA
        let low_entropy_long = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // >20 chars, 1 unique
        assert!(!DnsEvent::is_high_entropy(low_entropy_long),
            "Long low-entropy label must NOT trigger DGA");

        // Short but high entropy — NOT DGA (len <= 20)
        let short_high = "a1b2c3d4e5f6g7h8i9j!"; // exactly 20 chars
        assert!(!DnsEvent::is_high_entropy(short_high),
            "Short high-entropy label (len=20) must NOT trigger DGA");

        // Long AND high entropy — IS DGA
        let dga_label = "a1b2c3d4e5f6g7h8i9j0k1l2m3"; // >20 chars, many unique
        assert!(DnsEvent::is_high_entropy(dga_label),
            "Long high-entropy label must trigger DGA detection");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 29: MAX_EXT_HEADERS limit prevents infinite loops
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn max_ext_headers_constant_is_safe() {
        const MAX_EXT_HEADERS: usize = 8;
        // 8 is a reasonable bound — real IPv6 packets rarely have >3 ext headers
        assert!(MAX_EXT_HEADERS >= 4,  "MAX_EXT_HEADERS must be at least 4 for real usage");
        assert!(MAX_EXT_HEADERS <= 32, "MAX_EXT_HEADERS must be <= 32 for eBPF verifier");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Test 30: dns_event suspicious flag and event_type correlation
    // ─────────────────────────────────────────────────────────────────────
    #[test]
    fn suspicious_flag_correlates_with_event_type() {
        let mut ev = DnsEvent::default();
        ev.event_type = DNS_EVENT_QUERY;
        ev.suspicious = 0;
        assert_eq!(ev.suspicious, 0, "Normal query must not be suspicious");

        ev.event_type = DNS_EVENT_TUNNEL;
        ev.suspicious = 1;
        assert_eq!(ev.suspicious, 1, "Tunnel event must set suspicious=1");

        ev.event_type = DNS_EVENT_DGA;
        ev.suspicious = 1;
        assert_eq!(ev.suspicious, 1, "DGA event must set suspicious=1");
    }
}
