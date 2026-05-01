# simulate.py
import random, time
from features import features_to_vector

ATTACKS = {
    "port_scan":  lambda: {"src_ip": "1.2.3.4", "dst_ip": "10.0.0.1", "protocol": 6, "ttl": 64,
                           "pkt_size": 60, "src_port": random.randint(1024,65535), "dst_port": random.randint(1,1024), "tcp_flags": 2},
    "ddos":       lambda: {"src_ip": f"5.{random.randint(0,255)}.{random.randint(0,255)}.1", "dst_ip": "10.0.0.5",
                           "protocol": 17, "ttl": 128, "pkt_size": random.randint(1400,1500), "src_port": 53, "dst_port": 80, "tcp_flags": 0},
    "normal_http":lambda: {"src_ip": f"192.168.1.{random.randint(2,254)}", "dst_ip": "8.8.8.8",
                           "protocol": 6, "ttl": 64, "pkt_size": random.randint(200,1200), "src_port": random.randint(1024,65535), "dst_port": 80, "tcp_flags": 24},
}

def generate_batch(n=200, attack_ratio=0.05):
    packets = []
    for _ in range(n):
        kind = random.choices(
            ["normal_http", "port_scan", "ddos"],
            weights=[1 - attack_ratio, attack_ratio/2, attack_ratio/2]
        )[0]
        f = ATTACKS[kind]()
        packets.append((f, features_to_vector(f)))
    return packets