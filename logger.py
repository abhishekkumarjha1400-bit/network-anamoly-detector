import csv, os
from datetime import datetime

LOG_FILE = "anomalies.csv"

def init_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            csv.writer(f).writerow(["timestamp","src_ip","dst_ip",
                                    "protocol","src_port","dst_port",
                                    "pkt_size","model","score"])

def log_anomaly(features, model_name, score):
    with open(LOG_FILE, "a", newline="") as f:
        csv.writer(f).writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            features.get("src_ip","?"),
            features.get("dst_ip","?"),
            features.get("protocol","?"),
            features.get("src_port",0),
            features.get("dst_port",0),
            features.get("pkt_size",0),
            model_name,
            round(score,4)
        ])