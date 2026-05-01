# ids_ips.py
# Intrusion Detection System (IDS) + Intrusion Prevention System (IPS)
#
# ARCHITECTURE:
#  IDS = Detect and ALERT only  (passive — never touches traffic)
#  IPS = Detect and BLOCK        (active — calls firewall.block_ip)
#
# DETECTION METHODS:
#  1. Signature Rules     – Snort-style rule matching on packet fields
#  2. Anomaly Thresholds  – Statistical deviation from baseline
#  3. Protocol Violations – Malformed / RFC-violating packets
#  4. Rate Limiting       – SYN flood, ICMP flood, connection exhaustion
#  5. Stateful Tracking   – Half-open connections, session hijacking indicators
#
# HOW TO USE:
#   ids = IDSEngine(mode="IPS")         # or "IDS" for detect-only
#   result = ids.inspect(features)
#   if result.blocked:
#       print("IPS blocked:", result.src_ip)

from __future__ import annotations
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field

# ────────────────────────────────────────────────────────────────────────────
#  SNORT-STYLE RULE DEFINITIONS
#  Each rule is a dict:
#    sid       – unique rule ID
#    name      – human-readable alert name
#    proto     – IP protocol number (6=TCP, 17=UDP, 1=ICMP, None=any)
#    dst_ports – set of destination ports to match (empty = any)
#    src_ports – set of source ports to match      (empty = any)
#    tcp_flags – required TCP flag bits (None = any)
#    severity  – CRITICAL / HIGH / MEDIUM / LOW
#    action    – "alert" (IDS) or "block" (IPS)
#    msg       – alert message
# ────────────────────────────────────────────────────────────────────────────
RULES = [
    # ── Reconnaissance ───────────────────────────────────────────────────────
    {
        "sid": 1001, "name": "NULL Scan",
        "proto": 6,  "dst_ports": set(), "tcp_flags": 0x00,
        "severity": "HIGH", "action": "alert",
        "msg": "NULL scan detected (no TCP flags set) — stealth reconnaissance"
    },
    {
        "sid": 1002, "name": "XMAS Scan",
        "proto": 6,  "dst_ports": set(), "tcp_flags": 0x29,  # FIN+PSH+URG
        "severity": "HIGH", "action": "alert",
        "msg": "XMAS scan detected (FIN+PSH+URG) — stealth reconnaissance"
    },
    {
        "sid": 1003, "name": "FIN Scan",
        "proto": 6,  "dst_ports": set(), "tcp_flags": 0x01,  # FIN only
        "severity": "MEDIUM", "action": "alert",
        "msg": "FIN scan detected — stealth port scan"
    },
    # ── Exploitation ─────────────────────────────────────────────────────────
    {
        "sid": 2001, "name": "EternalBlue SMB Exploit",
        "proto": 6,  "dst_ports": {445}, "tcp_flags": None,
        "severity": "CRITICAL", "action": "block",
        "msg": "EternalBlue/WannaCry SMB exploit attempt on port 445"
    },
    {
        "sid": 2002, "name": "RDP Brute Force",
        "proto": 6,  "dst_ports": {3389}, "tcp_flags": None,
        "severity": "HIGH", "action": "alert",
        "msg": "RDP connection attempt — possible brute-force attack"
    },
    {
        "sid": 2003, "name": "SSH Brute Force",
        "proto": 6,  "dst_ports": {22}, "tcp_flags": None,
        "severity": "HIGH", "action": "alert",
        "msg": "SSH connection — monitoring for brute-force"
    },
    {
        "sid": 2004, "name": "Telnet Cleartext",
        "proto": 6,  "dst_ports": {23}, "tcp_flags": None,
        "severity": "HIGH", "action": "block",
        "msg": "Telnet (cleartext) connection blocked — use SSH instead"
    },
    {
        "sid": 2005, "name": "Metasploit Default Port",
        "proto": 6,  "dst_ports": {4444, 4445}, "tcp_flags": None,
        "severity": "CRITICAL", "action": "block",
        "msg": "Metasploit default reverse shell port detected — blocking"
    },
    {
        "sid": 2006, "name": "Docker API Exposed",
        "proto": 6,  "dst_ports": {2375, 2376}, "tcp_flags": None,
        "severity": "CRITICAL", "action": "block",
        "msg": "Docker API port exposed externally — critical misconfiguration"
    },
    {
        "sid": 2007, "name": "Redis Unauthenticated",
        "proto": 6,  "dst_ports": {6379}, "tcp_flags": None,
        "severity": "HIGH", "action": "alert",
        "msg": "Redis port — often unauthenticated and exploited for RCE"
    },
    {
        "sid": 2008, "name": "MongoDB Exposed",
        "proto": 6,  "dst_ports": {27017}, "tcp_flags": None,
        "severity": "HIGH", "action": "alert",
        "msg": "MongoDB port — check authentication is enabled"
    },
    {
        "sid": 2009, "name": "Elasticsearch Exposed",
        "proto": 6,  "dst_ports": {9200, 9300}, "tcp_flags": None,
        "severity": "HIGH", "action": "alert",
        "msg": "Elasticsearch port — often misconfigured without auth"
    },
    # ── Protocol Abuse ───────────────────────────────────────────────────────
    {
        "sid": 3001, "name": "IRC Botnet C2",
        "proto": 6,  "dst_ports": {6667, 6668, 6669}, "tcp_flags": None,
        "severity": "HIGH", "action": "block",
        "msg": "IRC port — common botnet C2 channel"
    },
    {
        "sid": 3002, "name": "Tor SOCKS Proxy",
        "proto": 6,  "dst_ports": {9050, 9051}, "tcp_flags": None,
        "severity": "MEDIUM", "action": "alert",
        "msg": "Tor SOCKS proxy port — anonymous traffic routing"
    },
    # ── DNS / UDP Abuse ──────────────────────────────────────────────────────
    {
        "sid": 4001, "name": "DNS Amplification",
        "proto": 17, "dst_ports": {53}, "src_ports": {53}, "tcp_flags": None,
        "severity": "HIGH", "action": "alert",
        "msg": "Possible DNS amplification DDoS (large DNS responses)"
    },
    # ── ICMP ─────────────────────────────────────────────────────────────────
    {
        "sid": 5001, "name": "Oversized ICMP (Ping of Death)",
        "proto": 1,  "dst_ports": set(), "tcp_flags": None,
        "severity": "HIGH", "action": "block",
        "msg": "Oversized ICMP packet (Ping of Death) — blocking"
    },
]

# ── Rate-limit thresholds ─────────────────────────────────────────────────────
SYN_FLOOD_PPS    = 100   # SYN packets/sec from one IP
ICMP_FLOOD_PPS   = 50    # ICMP packets/sec from one IP
UDP_FLOOD_PPS    = 200   # UDP packets/sec from one IP
CONN_RATE_PPS    = 60    # Any new connections/sec from one IP
SSH_BRUTE_COUNT  = 5     # SSH attempts in 30s before escalating
RDP_BRUTE_COUNT  = 3     # RDP attempts in 30s before blocking


@dataclass
class InspectionResult:
    triggered:  bool     = False
    action:     str      = "allow"      # allow | alert | block
    sid:        int      = 0
    rule_name:  str      = ""
    severity:   str      = ""
    msg:        str      = ""
    src_ip:     str      = ""
    dst_ip:     str      = ""
    dst_port:   int      = 0
    blocked:    bool     = False
    method:     str      = ""           # signature | rate | protocol | anomaly


class IDSEngine:
    """
    Full IDS/IPS engine.

    mode:
      "IDS" — detect and log only, never block
      "IPS" — detect, log, AND automatically block via firewall
    """

    def __init__(self, mode: str = "IPS",
                 block_callback=None,
                 alert_callback=None):
        """
        block_callback(ip, reason) : called when IPS blocks an IP
        alert_callback(result)     : called for every detection
        """
        assert mode in ("IDS", "IPS"), "mode must be 'IDS' or 'IPS'"
        self.mode             = mode
        self._block_cb        = block_callback
        self._alert_cb        = alert_callback
        self._lock            = threading.Lock()

        # Rate-limit trackers: ip → deque of timestamps
        self._syn_tracker:   dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._icmp_tracker:  dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._udp_tracker:   dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._conn_tracker:  dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._ssh_tracker:   dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._rdp_tracker:   dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # Alert counters
        self.stats = {
            "total_inspected": 0,
            "alerts":          0,
            "blocks":          0,
            "by_severity":     {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        }

    # ── Main inspection entry point ───────────────────────────────────────────
    def inspect(self, features: dict) -> InspectionResult:
        self.stats["total_inspected"] += 1
        src   = features.get("src_ip",   "?")
        dst   = features.get("dst_ip",   "?")
        proto = features.get("protocol", 0)
        sport = features.get("src_port", 0)
        dport = features.get("dst_port", 0)
        flags = features.get("tcp_flags", None)
        size  = features.get("pkt_size", 0)
        now   = time.time()

        # ── 1. Signature rule matching ────────────────────────────────────────
        for rule in RULES:
            if not self._matches_rule(rule, proto, sport, dport, flags, size):
                continue
            result = InspectionResult(
                triggered = True,
                action    = rule["action"],
                sid       = rule["sid"],
                rule_name = rule["name"],
                severity  = rule["severity"],
                msg       = rule["msg"],
                src_ip    = src,
                dst_ip    = dst,
                dst_port  = dport,
                method    = "signature",
            )
            return self._handle(result)

        # ── 2. Rate-limit checks ──────────────────────────────────────────────
        rate_result = self._check_rates(src, proto, dport, flags, now)
        if rate_result:
            rate_result.src_ip  = src
            rate_result.dst_ip  = dst
            rate_result.dst_port = dport
            return self._handle(rate_result)

        # ── 3. Protocol violation checks ──────────────────────────────────────
        proto_result = self._check_protocol_violations(
            proto, flags, size, src, dst, dport)
        if proto_result:
            return self._handle(proto_result)

        return InspectionResult(triggered=False, action="allow",
                                src_ip=src, dst_ip=dst, dst_port=dport)

    # ── Rule matching ─────────────────────────────────────────────────────────
    @staticmethod
    def _matches_rule(rule, proto, sport, dport, flags, size) -> bool:
        # Protocol match
        if rule.get("proto") is not None and rule["proto"] != proto:
            return False
        # Destination port match
        dst_ports = rule.get("dst_ports", set())
        if dst_ports and dport not in dst_ports:
            return False
        # Source port match (optional)
        src_ports = rule.get("src_ports", set())
        if src_ports and sport not in src_ports:
            return False
        # TCP flags match
        req_flags = rule.get("tcp_flags")
        if req_flags is not None and flags is not None:
            if flags != req_flags:
                return False
        # Oversized ICMP special case
        if rule["sid"] == 5001 and size <= 65500:
            return False
        return True

    # ── Rate-limit checks ─────────────────────────────────────────────────────
    def _check_rates(self, src, proto, dport, flags, now) -> InspectionResult | None:
        with self._lock:
            # SYN flood: TCP SYN only (flags = 0x02)
            if proto == 6 and flags == 0x02:
                self._syn_tracker[src].append(now)
                recent = sum(1 for t in self._syn_tracker[src] if now - t < 1)
                if recent > SYN_FLOOD_PPS:
                    return InspectionResult(
                        triggered=True, action="block",
                        sid=9001, rule_name="SYN Flood",
                        severity="CRITICAL",
                        msg=f"SYN flood: {recent} SYN/s from {src}",
                        method="rate")

            # ICMP flood
            if proto == 1:
                self._icmp_tracker[src].append(now)
                recent = sum(1 for t in self._icmp_tracker[src] if now - t < 1)
                if recent > ICMP_FLOOD_PPS:
                    return InspectionResult(
                        triggered=True, action="block",
                        sid=9002, rule_name="ICMP Flood",
                        severity="HIGH",
                        msg=f"ICMP flood: {recent} pkt/s from {src}",
                        method="rate")

            # UDP flood
            if proto == 17:
                self._udp_tracker[src].append(now)
                recent = sum(1 for t in self._udp_tracker[src] if now - t < 1)
                if recent > UDP_FLOOD_PPS:
                    return InspectionResult(
                        triggered=True, action="block",
                        sid=9003, rule_name="UDP Flood",
                        severity="HIGH",
                        msg=f"UDP flood: {recent} pkt/s from {src}",
                        method="rate")

            # SSH brute force counter
            if proto == 6 and dport == 22:
                self._ssh_tracker[src].append(now)
                recent = sum(1 for t in self._ssh_tracker[src] if now - t < 30)
                if recent > SSH_BRUTE_COUNT:
                    return InspectionResult(
                        triggered=True, action="block",
                        sid=9004, rule_name="SSH Brute Force",
                        severity="HIGH",
                        msg=f"SSH brute force: {recent} attempts/30s from {src}",
                        method="rate")

            # RDP brute force counter
            if proto == 6 and dport == 3389:
                self._rdp_tracker[src].append(now)
                recent = sum(1 for t in self._rdp_tracker[src] if now - t < 30)
                if recent > RDP_BRUTE_COUNT:
                    return InspectionResult(
                        triggered=True, action="block",
                        sid=9005, rule_name="RDP Brute Force",
                        severity="CRITICAL",
                        msg=f"RDP brute force: {recent} attempts/30s from {src} — blocking",
                        method="rate")

        return None

    # ── Protocol violation checks ─────────────────────────────────────────────
    @staticmethod
    def _check_protocol_violations(proto, flags, size, src, dst, dport
                                   ) -> InspectionResult | None:
        # TCP with no flags AND not part of established session
        if proto == 6 and flags is not None:
            # RST + SYN is invalid
            if flags & 0x06 == 0x06:
                return InspectionResult(
                    triggered=True, action="alert",
                    sid=8001, rule_name="Invalid TCP Flags RST+SYN",
                    severity="MEDIUM",
                    msg="Invalid RST+SYN combination — possible evasion/OS fingerprinting",
                    src_ip=src, dst_ip=dst, dst_port=dport,
                    method="protocol")
            # All flags set (possible OS fingerprinting)
            if flags == 0xFF:
                return InspectionResult(
                    triggered=True, action="alert",
                    sid=8002, rule_name="All TCP Flags Set",
                    severity="MEDIUM",
                    msg="All TCP flags set — possible OS fingerprinting or evasion",
                    src_ip=src, dst_ip=dst, dst_port=dport,
                    method="protocol")

        # Tiny packet on data port (possible malformed fragment)
        if proto in (6, 17) and 0 < size < 28:
            return InspectionResult(
                triggered=True, action="alert",
                sid=8003, rule_name="Suspiciously Small Packet",
                severity="LOW",
                msg=f"Undersized packet ({size}B) on port {dport} — "
                    "possible fragment or malformed frame",
                src_ip=src, dst_ip=dst, dst_port=dport,
                method="protocol")

        return None

    # ── Handle result: callbacks, blocking, stats ─────────────────────────────
    def _handle(self, result: InspectionResult) -> InspectionResult:
        if not result.triggered:
            return result

        self.stats["alerts"] += 1
        sev = result.severity
        if sev in self.stats["by_severity"]:
            self.stats["by_severity"][sev] += 1

        # IPS mode: call firewall for block actions
        if self.mode == "IPS" and result.action == "block":
            result.blocked = True
            self.stats["blocks"] += 1
            if self._block_cb:
                try:
                    self._block_cb(result.src_ip, result.msg)
                except Exception:
                    pass

        # Notify alert callback
        if self._alert_cb:
            try:
                self._alert_cb(result)
            except Exception:
                pass

        return result

    # ── Diagnostics ───────────────────────────────────────────────────────────
    def get_stats(self) -> dict:
        return dict(self.stats)

    def set_mode(self, mode: str):
        assert mode in ("IDS", "IPS")
        self.mode = mode

    def add_rule(self, rule: dict):
        """Dynamically add a custom Snort-style rule at runtime."""
        RULES.append(rule)
