#!/usr/bin/env python3
import sys
import numpy as np
try:
    from scapy.all import PcapReader, IP, TCP, UDP
except ImportError:
    print("Please install scapy: pip install scapy")
    sys.exit(1)

def extract_features(pkt):
    # محاذاة رياضية دقيقة مع مستخرج الميزات في Rust (32 بعداً)
    features = np.zeros(32, dtype=np.float32)
    if IP not in pkt:
        return None
    
    ip_layer = pkt[IP]
    
    # ميزات IP (0-3)
    src_parts = [int(x) for x in ip_layer.src.split('.')]
    dst_parts = [int(x) for x in ip_layer.dst.split('.')]
    
    features[0] = src_parts[0] / 255.0
    features[1] = src_parts[1] / 255.0
    features[2] = dst_parts[0] / 255.0
    features[3] = dst_parts[1] / 255.0
    
    # البروتوكولات (6-7)
    features[6] = 1.0 if ip_layer.proto == 6 else 0.0 # TCP
    features[7] = 1.0 if ip_layer.proto == 17 else 0.0 # UDP
    
    # ميزات المنافذ والأعلام (4-5, 8-9)
    if TCP in pkt:
        features[4] = pkt[TCP].sport / 65535.0
        features[5] = pkt[TCP].dport / 65535.0
        features[8] = 1.0 if pkt[TCP].flags & 0x02 else 0.0 # SYN flag
        features[9] = len(pkt[TCP].payload) / 1500.0
    elif UDP in pkt:
        features[4] = pkt[UDP].sport / 65535.0
        features[5] = pkt[UDP].dport / 65535.0
        features[9] = len(pkt[UDP].payload) / 1500.0

    return features

def pcap_to_numpy(pcap_path, out_path):
    print(f"🔍 Reading production PCAP: {pcap_path}...")
    vectors = []
    
    # القراءة التتابعية (Streaming) لعدم استهلاك الذاكرة بملفات الـ PCAP الضخمة (الـ Terabytes)
    for i, pkt in enumerate(PcapReader(pcap_path)):
        vec = extract_features(pkt)
        if vec is not None:
            vectors.append(vec)
        if i > 0 and i % 10000 == 0:
            print(f"   => Processed {i} packets...")
            
    np_vectors = np.array(vectors, dtype=np.float32)
    print(f"🎯 Total resilient feature vectors extracted: {np_vectors.shape}")
    np.save(out_path, np_vectors)
    print(f"✅ Saved feature vectors to {out_path} (Ready for LSTM/TCN Training)")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python pcap_to_features.py input.pcap output.npy")
        sys.exit(1)
    pcap_to_numpy(sys.argv[1], sys.argv[2])
