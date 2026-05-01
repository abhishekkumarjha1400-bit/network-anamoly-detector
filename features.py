def extract_features(packet):
    try:
        from scapy.all import IP, TCP, UDP
        if not packet.haslayer(IP):
            return None
        ip = packet[IP]
        f = {
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "protocol": ip.proto,
            "ttl": ip.ttl,
            "pkt_size": len(packet),
            "src_port": 0,
            "dst_port": 0,
            "tcp_flags": 0
        }
        if packet.haslayer(TCP):
            f["src_port"] = packet[TCP].sport
            f["dst_port"] = packet[TCP].dport
            f["tcp_flags"] = int(packet[TCP].flags)
        elif packet.haslayer(UDP):
            f["src_port"] = packet[UDP].sport
            f["dst_port"] = packet[UDP].dport
        return f
    except:
        return None

def features_to_vector(f):
    return [
        f.get("protocol", 0),
        f.get("ttl", 0),
        f.get("pkt_size", 0),
        f.get("src_port", 0),
        f.get("dst_port", 0),
        f.get("tcp_flags", 0)
    ]