import requests, os

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY")

# Known dangerous ports
THREAT_PORTS = {
    22: "SSH Brute Force", 23: "Telnet", 3389: "RDP Attack",
    445: "SMB/WannaCry", 135: "RPC Exploit", 1433: "MSSQL Attack",
    3306: "MySQL Attack", 6379: "Redis Attack", 9200: "Elasticsearch",
    4444: "Metasploit", 8080: "Alt HTTP Scan", 53: "DNS Abuse"
}

def is_private_ip(ip: str) -> bool:
    return ip.startswith((
        "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
        "127.", "0.", "224.", "239.", "169.254."
    ))

def check_port_threat(port: int) -> dict:
    if port in THREAT_PORTS:
        return {"is_threat": True, "reason": THREAT_PORTS[port]}
    return {"is_threat": False, "reason": ""}

def get_risk_level(score: float) -> str:
    if score >= 80:   return "CRITICAL"
    elif score >= 50: return "HIGH"
    elif score >= 25: return "MEDIUM"
    elif score >= 10: return "LOW"
    else:             return "SAFE"

def check_ip_reputation(ip: str) -> dict:
    if not ABUSEIPDB_KEY or is_private_ip(ip):
        return {"is_malicious": False, "risk_score": 0,
                "reason": "", "country": "Unknown", "isp": "Unknown"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=3
        )
        d = r.json()["data"]
        score = d["abuseConfidenceScore"]
        return {
            "is_malicious": score >= 50,
            "risk_score":   score,
            "reason":       f"AbuseIPDB: {d['totalReports']} reports",
            "country":      d.get("countryCode", "Unknown"),
            "isp":          d.get("isp", "Unknown")
        }
    except:
        return {"is_malicious": False, "risk_score": 0,
                "reason": "", "country": "Unknown", "isp": "Unknown"}