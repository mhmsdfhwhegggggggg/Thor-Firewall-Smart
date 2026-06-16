//! Packet Encoder — extracts 128-dimensional feature vectors from raw packet bytes.
//!
//! Features are grouped into 6 semantic blocks:
//! - [0..15]   IP header features (version, TTL, flags, fragment offset, protocol, lengths)
//! - [16..31]  Transport header features (ports, flags, window, sequence deltas)
//! - [32..47]  Payload entropy and byte distribution statistics
//! - [48..79]  Byte frequency histogram (sampled at 32 evenly-spaced positions)
//! - [80..95]  N-gram frequency features (2-gram, 3-gram fingerprints)
//! - [96..127] Protocol anomaly indicators (invalid values, unusual combinations)

use std::collections::HashMap;

/// Size of the feature vector produced by this encoder.
pub const FEATURE_DIM: usize = 128;

/// Encode a raw packet (starting from IP header) into a 128-float feature vector.
///
/// Accepts raw bytes starting from the Ethernet payload (IP header).
/// Returns [`None`] if the packet is too short to parse meaningfully (< 20 bytes).
///
/// # Example
/// ```
/// # use thor_ids::dpi::packet_encoder::encode_packet;
/// let pkt = vec![0x45u8; 40]; // minimal IPv4 stub
/// if let Some(features) = encode_packet(&pkt) {
///     assert_eq!(features.len(), 128);
/// }
/// ```
pub fn encode_packet(raw: &[u8]) -> Option<[f32; FEATURE_DIM]> {
    if raw.len() < 20 {
        return None;
    }
    let mut feat = [0.0f32; FEATURE_DIM];

    // ── Block A: IP header features [0..16] ──────────────────────────────────
    feat[0] = ((raw[0] >> 4) & 0xF) as f32; // IP version (4 or 6)
    feat[1] = (raw[0] & 0xF) as f32;         // IHL (header length in 32-bit words)
    feat[2] = raw[1] as f32 / 255.0;          // DSCP/ECN field (normalized)
    let total_len = u16::from_be_bytes([raw[2], raw[3]]) as f32;
    feat[3] = total_len / 65535.0;            // Total length (normalized)
    feat[4] = raw[8] as f32 / 255.0;          // TTL (normalized)
    feat[5] = raw[9] as f32;                  // Protocol (6=TCP, 17=UDP, 1=ICMP, ...)
    feat[6] = ((raw[6] >> 5) & 0x7) as f32;  // IP flags (DF, MF)
    let frag_offset = ((u16::from_be_bytes([raw[6], raw[7]]) & 0x1FFF)) as f32;
    feat[7] = frag_offset / 8191.0;           // Fragment offset (normalized)

    // Source IP octets as normalized floats
    feat[8]  = raw[12] as f32 / 255.0;
    feat[9]  = raw[13] as f32 / 255.0;
    feat[10] = raw[14] as f32 / 255.0;
    feat[11] = raw[15] as f32 / 255.0;
    // Destination IP octets
    feat[12] = raw[16] as f32 / 255.0;
    feat[13] = raw[17] as f32 / 255.0;
    feat[14] = raw[18] as f32 / 255.0;
    feat[15] = raw[19] as f32 / 255.0;

    // ── Block B: Transport header [16..32] ────────────────────────────────────
    let ihl = ((raw[0] & 0xF) * 4) as usize;
    if raw.len() >= ihl + 4 {
        let src_port = u16::from_be_bytes([raw[ihl], raw[ihl + 1]]) as f32;
        let dst_port = u16::from_be_bytes([raw[ihl + 2], raw[ihl + 3]]) as f32;
        feat[16] = src_port / 65535.0;
        feat[17] = dst_port / 65535.0;
        // Known-port flags
        feat[18] = if dst_port <= 1024.0 { 1.0 } else { 0.0 };
        feat[19] = if src_port > 49151.0 { 1.0 } else { 0.0 }; // ephemeral source port

        // TCP flags if protocol == 6
        if raw[9] == 6 && raw.len() >= ihl + 14 {
            let tcp_flags = raw[ihl + 13];
            feat[20] = ((tcp_flags >> 1) & 1) as f32; // SYN
            feat[21] = ((tcp_flags >> 0) & 1) as f32; // FIN
            feat[22] = ((tcp_flags >> 2) & 1) as f32; // RST
            feat[23] = ((tcp_flags >> 3) & 1) as f32; // PSH
            feat[24] = ((tcp_flags >> 4) & 1) as f32; // ACK
            feat[25] = ((tcp_flags >> 5) & 1) as f32; // URG
            let win = u16::from_be_bytes([raw[ihl + 14], raw[ihl + 15]]) as f32;
            feat[26] = win / 65535.0; // TCP window size
        }
        feat[27] = (raw.len() as f32 - ihl as f32).max(0.0) / 1500.0; // payload ratio
    }

    // ── Block C: Payload entropy [32..48] ────────────────────────────────────
    let payload_start = ihl + if raw[9] == 6 { ((raw[ihl + 12] >> 4) * 4) as usize } else { 8 };
    let payload = if payload_start < raw.len() { &raw[payload_start..] } else { &[] };

    feat[32] = shannon_entropy(payload);
    feat[33] = byte_mean(payload);
    feat[34] = byte_variance(payload);
    feat[35] = printable_ratio(payload);
    feat[36] = null_byte_ratio(payload);
    feat[37] = high_byte_ratio(payload);  // bytes > 127
    feat[38] = repetition_score(payload); // measures byte repetition
    feat[39] = longest_run(payload);      // longest consecutive identical byte run

    // ── Block D: Byte frequency histogram [48..80] ────────────────────────────
    // Sample 32 evenly-spaced byte positions
    if !payload.is_empty() {
        for i in 0..32 {
            let pos = (i * payload.len()) / 32;
            feat[48 + i] = payload[pos] as f32 / 255.0;
        }
    }

    // ── Block E: N-gram fingerprints [80..96] ────────────────────────────────
    if payload.len() >= 2 {
        let (bigram_score, trigram_score) = ngram_features(payload);
        feat[80] = bigram_score;
        feat[81] = trigram_score;
    }
    // HTTP magic bytes
    feat[82] = if payload.starts_with(b"GET ") || payload.starts_with(b"POST") { 1.0 } else { 0.0 };
    feat[83] = if payload.starts_with(b"HTTP") { 1.0 } else { 0.0 };
    // TLS magic
    feat[84] = if !payload.is_empty() && payload[0] == 0x16 { 1.0 } else { 0.0 };
    // DNS magic (transaction ID check)
    feat[85] = if payload.len() >= 12 && (payload[2] & 0x80) == 0 { 1.0 } else { 0.0 };
    // SSH banner
    feat[86] = if payload.starts_with(b"SSH-") { 1.0 } else { 0.0 };
    // SMB magic
    feat[87] = if payload.len() >= 4 && &payload[..4] == b"\xFFSMB" { 1.0 } else { 0.0 };

    // ── Block F: Anomaly indicators [96..128] ────────────────────────────────
    feat[96]  = if raw[9] == 0 { 1.0 } else { 0.0 };  // Protocol 0 (unusual)
    feat[97]  = if frag_offset > 0.0 { 1.0 } else { 0.0 }; // Fragmented packet
    feat[98]  = if feat[4] < 0.039 { 1.0 } else { 0.0 }; // Very low TTL (< 10)
    feat[99]  = if total_len < 40.0 / 65535.0 { 1.0 } else { 0.0 }; // Abnormally small
    feat[100] = if feat[32] > 0.95 { 1.0 } else { 0.0 }; // Near-max entropy (likely encrypted/compressed)
    feat[101] = if feat[32] < 0.1 { 1.0 } else { 0.0 };  // Very low entropy (likely padding/nop sled)
    feat[102] = if feat[35] > 0.95 { 1.0 } else { 0.0 }; // Almost all printable (text payload)
    feat[103] = if raw[9] == 6 && feat[20] == 1.0 && feat[24] == 1.0 { 1.0 } else { 0.0 }; // SYN+ACK
    feat[104] = if raw[9] == 6 && feat[20] == 1.0 && feat[21] == 1.0 { 1.0 } else { 0.0 }; // SYN+FIN (invalid)
    feat[105] = port_category(feat[17] * 65535.0); // destination port category

    Some(feat)
}

// ─── Helper functions ─────────────────────────────────────────────────────────

/// Shannon entropy of a byte slice, normalized to [0, 1].
pub fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f32;
    let entropy: f32 = counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / len;
            -p * p.log2()
        })
        .sum();
    // Max entropy for 256 symbols is log2(256) = 8 bits
    entropy / 8.0
}

fn byte_mean(data: &[u8]) -> f32 {
    if data.is_empty() { return 0.0; }
    data.iter().map(|&b| b as f32).sum::<f32>() / data.len() as f32 / 255.0
}

fn byte_variance(data: &[u8]) -> f32 {
    if data.len() < 2 { return 0.0; }
    let mean = data.iter().map(|&b| b as f32).sum::<f32>() / data.len() as f32;
    let var = data.iter()
        .map(|&b| { let d = b as f32 - mean; d * d })
        .sum::<f32>() / data.len() as f32;
    // Max variance for uniform [0,255] is ~5418; normalize
    (var / 5418.0).min(1.0)
}

fn printable_ratio(data: &[u8]) -> f32 {
    if data.is_empty() { return 0.0; }
    data.iter().filter(|&&b| b >= 0x20 && b <= 0x7E).count() as f32 / data.len() as f32
}

fn null_byte_ratio(data: &[u8]) -> f32 {
    if data.is_empty() { return 0.0; }
    data.iter().filter(|&&b| b == 0).count() as f32 / data.len() as f32
}

fn high_byte_ratio(data: &[u8]) -> f32 {
    if data.is_empty() { return 0.0; }
    data.iter().filter(|&&b| b > 127).count() as f32 / data.len() as f32
}

fn repetition_score(data: &[u8]) -> f32 {
    if data.len() < 2 { return 0.0; }
    let reps = data.windows(2).filter(|w| w[0] == w[1]).count();
    reps as f32 / (data.len() - 1) as f32
}

fn longest_run(data: &[u8]) -> f32 {
    if data.is_empty() { return 0.0; }
    let mut max_run = 1usize;
    let mut cur_run = 1usize;
    for i in 1..data.len() {
        if data[i] == data[i - 1] { cur_run += 1; max_run = max_run.max(cur_run); }
        else { cur_run = 1; }
    }
    (max_run as f32 / data.len() as f32).min(1.0)
}

/// Returns (bigram_entropy_normalized, trigram_entropy_normalized).
fn ngram_features(data: &[u8]) -> (f32, f32) {
    if data.len() < 3 { return (0.0, 0.0); }

    let mut bigram_counts: HashMap<u16, u32> = HashMap::new();
    let mut trigram_counts: HashMap<u32, u32> = HashMap::new();

    for w in data.windows(2) {
        *bigram_counts.entry(u16::from_le_bytes([w[0], w[1]])).or_insert(0) += 1;
    }
    for w in data.windows(3) {
        *trigram_counts.entry((w[0] as u32) << 16 | (w[1] as u32) << 8 | w[2] as u32).or_insert(0) += 1;
    }

    let n2 = (data.len() - 1) as f32;
    let bi_entropy: f32 = bigram_counts.values()
        .map(|&c| { let p = c as f32 / n2; -p * p.log2() })
        .sum::<f32>() / 16.0; // max 16 bits for bigrams

    let n3 = (data.len() - 2) as f32;
    let tri_entropy: f32 = trigram_counts.values()
        .map(|&c| { let p = c as f32 / n3; -p * p.log2() })
        .sum::<f32>() / 24.0; // max 24 bits for trigrams

    (bi_entropy.min(1.0), tri_entropy.min(1.0))
}

/// Classify destination port into a category float [0.0, 1.0].
fn port_category(port: f32) -> f32 {
    match port as u16 {
        0..=1023   => 0.1,  // Well-known
        1024..=49151 => 0.5, // Registered
        _          => 0.9,  // Ephemeral/dynamic
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_ipv4_tcp(payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![
            0x45, 0x00, 0x00, 0x00, // ver+ihl, dscp, total_len (placeholder)
            0x00, 0x01, 0x40, 0x00, // id, flags, frag_offset
            0x40, 0x06, 0x00, 0x00, // TTL=64, proto=TCP(6), checksum
            0x7f, 0x00, 0x00, 0x01, // src=127.0.0.1
            0x7f, 0x00, 0x00, 0x01, // dst=127.0.0.1
            // TCP header (20 bytes)
            0x1f, 0x90, 0x00, 0x50, // src_port=8080, dst_port=80
            0x00, 0x00, 0x00, 0x00, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0xff, 0xff, // data_offset=5, SYN flag
            0x00, 0x00, 0x00, 0x00, // checksum, urgent
        ];
        pkt.extend_from_slice(payload);
        // Fix total length
        let len = pkt.len() as u16;
        pkt[2] = (len >> 8) as u8;
        pkt[3] = (len & 0xff) as u8;
        pkt
    }

    #[test]
    fn test_feature_dim() {
        let pkt = minimal_ipv4_tcp(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let feat = encode_packet(&pkt).expect("Should encode valid packet");
        assert_eq!(feat.len(), FEATURE_DIM);
    }

    #[test]
    fn test_none_on_short_packet() {
        assert!(encode_packet(&[0x45u8; 10]).is_none());
        assert!(encode_packet(&[]).is_none());
    }

    #[test]
    fn test_entropy_bounds() {
        // All same bytes → near-zero entropy
        let low = shannon_entropy(&[0xAAu8; 100]);
        assert!(low < 0.01, "Expected ~0 entropy for uniform bytes, got {}", low);

        // Random-looking bytes → higher entropy
        let data: Vec<u8> = (0u8..=255).collect();
        let high = shannon_entropy(&data);
        assert!(high > 0.9, "Expected high entropy for all-distinct bytes, got {}", high);
    }

    #[test]
    fn test_http_magic_detected() {
        let pkt = minimal_ipv4_tcp(b"GET /malicious HTTP/1.1\r\nHost: attacker.com\r\n\r\n");
        let feat = encode_packet(&pkt).unwrap();
        assert_eq!(feat[82], 1.0, "HTTP GET magic should be detected at feat[82]");
    }

    #[test]
    fn test_syn_flag_detected() {
        let pkt = minimal_ipv4_tcp(b"");
        let feat = encode_packet(&pkt).unwrap();
        // SYN flag is set in our minimal_ipv4_tcp (flags=0x02)
        assert_eq!(feat[20], 1.0, "SYN flag should be 1.0");
        assert_eq!(feat[24], 0.0, "ACK flag should be 0.0");
    }
}
