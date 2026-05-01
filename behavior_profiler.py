# behavior_profiler.py
# ─────────────────────────────────────────────────────────────
# Learns what "normal" looks like for every IP address it sees,
# then scores each new packet as a deviation from that baseline.
#
# How it works:
#   1. For each source IP, we maintain a rolling profile:
#      - typical packet sizes (mean + std dev)
#      - usual protocols and destination ports
#      - hourly activity pattern (which hours it's usually active)
#      - average packets-per-second rate
#      - typical TTL values
#
#   2. When a new packet arrives, we compare it against the profile
#      and return a deviation score from 0.0 (perfectly normal)
#      to 1.0 (completely unlike anything seen before).
#
#   3. Profiles auto-save to JSON on disk so they survive restarts.
#
# Drop-in integration:
#   from behavior_profiler import BehaviorProfiler
#   profiler = BehaviorProfiler()
#   deviation, reasons = profiler.update(features)
# ─────────────────────────────────────────────────────────────

import json
import math
import os
import time
import threading
from collections import defaultdict, deque
from datetime import datetime

PROFILE_FILE    = "ip_profiles.json"
MIN_SAMPLES     = 30          # minimum packets before scoring starts
SAVE_INTERVAL   = 60          # seconds between auto-saves to disk
MAX_PORT_MEMORY = 50          # how many distinct dst ports to remember per IP
MAX_RATE_WINDOW = 30          # seconds for packet-rate calculation


class IPProfile:
    """
    Tracks behavioural statistics for a single source IP address.
    All stats update incrementally — no need to replay history.
    """

    def __init__(self):
        self.sample_count   = 0

        # Packet size stats (Welford's online algorithm)
        self._size_mean     = 0.0
        self._size_M2       = 0.0
        self.size_std       = 0.0

        # TTL stats
        self._ttl_mean      = 0.0
        self._ttl_M2        = 0.0
        self.ttl_std        = 0.0

        # Protocol distribution (proto_num -> count)
        self.proto_counts   = defaultdict(int)

        # Destination port distribution
        self.port_counts    = defaultdict(int)

        # Hourly activity pattern (0-23 -> packet count)
        self.hour_activity  = defaultdict(int)

        # Packet-rate tracking (sliding window of timestamps)
        self._timestamps    = deque()
        self.typical_rate   = 0.0       # ewma of packets/second

        # Destination IP diversity
        self.dst_ips        = set()
        self.dst_ip_count   = 0

    def _welford_update(self, mean, M2, n, value):
        """One-pass mean + variance update (Welford 1962)."""
        delta  = value - mean
        mean  += delta / n
        delta2 = value - mean
        M2    += delta * delta2
        std    = math.sqrt(M2 / n) if n > 1 else 0.0
        return mean, M2, std

    def _zscore(self, value, mean, std):
        """How many standard deviations is value from mean?"""
        if std < 1e-9:
            return 0.0 if abs(value - mean) < 1e-9 else 3.0
        return abs(value - mean) / std

    def observe(self, features: dict):
        """
        Ingest one packet's features and update all stats.
        Call this BEFORE calling score().
        """
        self.sample_count += 1
        n = self.sample_count

        pkt_size = features.get("pkt_size", 0)
        ttl      = features.get("ttl", 64)
        proto    = features.get("protocol", 0)
        dst_port = features.get("dst_port", 0)
        dst_ip   = features.get("dst_ip", "")
        now      = time.time()
        hour     = datetime.now().hour

        # Welford updates
        self._size_mean, self._size_M2, self.size_std = \
            self._welford_update(self._size_mean, self._size_M2, n, pkt_size)
        self._ttl_mean, self._ttl_M2, self.ttl_std = \
            self._welford_update(self._ttl_mean, self._ttl_M2, n, ttl)

        # Protocol + port frequency
        self.proto_counts[str(proto)] += 1
        self.port_counts[str(dst_port)] += 1

        # Trim port memory to top-N most seen
        if len(self.port_counts) > MAX_PORT_MEMORY:
            least = min(self.port_counts, key=self.port_counts.get)
            del self.port_counts[least]

        # Hour-of-day activity
        self.hour_activity[str(hour)] += 1

        # Sliding-window packet rate
        self._timestamps.append(now)
        cutoff = now - MAX_RATE_WINDOW
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
        current_rate = len(self._timestamps) / MAX_RATE_WINDOW
        alpha = 0.1  # slow adaptation — don't let a single burst rewrite the baseline
        self.typical_rate = (1 - alpha) * self.typical_rate + alpha * current_rate

        # Destination IP diversity
        self.dst_ips.add(dst_ip)

    def score(self, features: dict):
        """
        Score how anomalous this packet is vs the IP's learned profile.
        Returns (deviation_score 0.0-1.0, list_of_reason_strings).
        Returns (0.0, []) during the warm-up period.
        """
        if self.sample_count < MIN_SAMPLES:
            return 0.0, []

        signals = []  # list of (contribution 0-1, reason string)

        pkt_size = features.get("pkt_size", 0)
        ttl      = features.get("ttl", 64)
        proto    = features.get("protocol", 0)
        dst_port = features.get("dst_port", 0)
        now      = time.time()
        hour     = datetime.now().hour

        total_packets = sum(self.proto_counts.values()) or 1
        total_hours   = sum(self.hour_activity.values()) or 1

        # Signal 1: Packet size deviation
        z_size = self._zscore(pkt_size, self._size_mean, self.size_std)
        if z_size > 3.0:
            contrib = min(1.0, (z_size - 3.0) / 4.0)
            signals.append((contrib,
                f"Unusual pkt size {pkt_size}B "
                f"(typical {self._size_mean:.0f}±{self.size_std:.0f})"))

        # Signal 2: TTL deviation
        z_ttl = self._zscore(ttl, self._ttl_mean, self.ttl_std)
        if z_ttl > 3.0:
            contrib = min(1.0, (z_ttl - 3.0) / 4.0)
            signals.append((contrib,
                f"Unusual TTL {ttl} "
                f"(typical {self._ttl_mean:.0f}±{self.ttl_std:.0f})"))

        # Signal 3: Rare protocol for this IP
        proto_count = self.proto_counts.get(str(proto), 0)
        proto_ratio = proto_count / total_packets
        if proto_ratio < 0.02:
            signals.append((0.6,
                f"Rare protocol {proto} "
                f"(seen only {proto_count}x in profile)"))

        # Signal 4: Never-seen or very rare destination port
        port_count = self.port_counts.get(str(dst_port), 0)
        if dst_port > 0 and port_count == 0:
            signals.append((0.5,
                f"New dst port {dst_port} "
                f"(never seen from this IP)"))
        elif dst_port > 0:
            port_ratio = port_count / total_packets
            if port_ratio < 0.005:
                signals.append((0.3,
                    f"Very rare dst port {dst_port} "
                    f"(only {port_count}x in profile)"))

        # Signal 5: Unusual hour of activity
        hour_count = self.hour_activity.get(str(hour), 0)
        hour_ratio = hour_count / total_hours
        if hour_ratio < 0.01:
            signals.append((0.4,
                f"Unusual activity at hour {hour:02d}:xx "
                f"(only {hour_ratio*100:.1f}% of prior traffic)"))

        # Signal 6: Rate spike
        cutoff = now - MAX_RATE_WINDOW
        recent = sum(1 for t in self._timestamps if t >= cutoff)
        current_rate = recent / MAX_RATE_WINDOW
        if self.typical_rate > 0.01 and current_rate > self.typical_rate * 5:
            contrib = min(1.0, (current_rate / self.typical_rate - 5) / 10)
            signals.append((contrib,
                f"Rate spike: {current_rate:.1f} pkt/s "
                f"(baseline {self.typical_rate:.2f} pkt/s)"))

        # Signal 7: Sudden dst-IP explosion (scanner/worm behaviour)
        dst_diversity = len(self.dst_ips)
        if self.sample_count > 100 and dst_diversity > self.sample_count * 0.5:
            signals.append((0.7,
                f"High dst IP diversity: {dst_diversity} unique IPs "
                f"over {self.sample_count} packets"))

        if not signals:
            return 0.0, []

        # Combine: take the strongest signal, boost for corroboration
        max_signal  = max(s[0] for s in signals)
        boost       = min(0.3, 0.08 * (len(signals) - 1))
        final_score = min(1.0, max_signal + boost)
        reasons     = [s[1] for s in signals]

        return round(final_score, 4), reasons

    def to_dict(self) -> dict:
        return {
            "sample_count":  self.sample_count,
            "_size_mean":    self._size_mean,
            "_size_M2":      self._size_M2,
            "size_std":      self.size_std,
            "_ttl_mean":     self._ttl_mean,
            "_ttl_M2":       self._ttl_M2,
            "ttl_std":       self.ttl_std,
            "proto_counts":  dict(self.proto_counts),
            "port_counts":   dict(self.port_counts),
            "hour_activity": dict(self.hour_activity),
            "typical_rate":  self.typical_rate,
            "dst_ip_count":  len(self.dst_ips),
        }

    @classmethod
    def from_dict(cls, d: dict):
        p = cls()
        p.sample_count   = d.get("sample_count", 0)
        p._size_mean     = d.get("_size_mean", 0.0)
        p._size_M2       = d.get("_size_M2", 0.0)
        p.size_std       = d.get("size_std", 0.0)
        p._ttl_mean      = d.get("_ttl_mean", 0.0)
        p._ttl_M2        = d.get("_ttl_M2", 0.0)
        p.ttl_std        = d.get("ttl_std", 0.0)
        p.proto_counts   = defaultdict(int, d.get("proto_counts", {}))
        p.port_counts    = defaultdict(int, d.get("port_counts", {}))
        p.hour_activity  = defaultdict(int, d.get("hour_activity", {}))
        p.typical_rate   = d.get("typical_rate", 0.0)
        p.dst_ip_count   = d.get("dst_ip_count", 0)
        return p


class BehaviorProfiler:
    """
    Top-level class. Maintains one IPProfile per source IP.
    Thread-safe. Auto-saves profiles to disk periodically.

    Usage:
        profiler = BehaviorProfiler()
        deviation, reasons = profiler.update(features_dict)
        if deviation > 0.6:
            print(f"Behavioural anomaly! Reasons: {reasons}")
    """

    THRESHOLD_LOW      = 0.30
    THRESHOLD_MEDIUM   = 0.55
    THRESHOLD_HIGH     = 0.75
    THRESHOLD_CRITICAL = 0.90

    def __init__(self, profile_file: str = PROFILE_FILE):
        self.profile_file = profile_file
        self._profiles    = {}
        self._lock        = threading.Lock()
        self._load()
        self._start_autosave()

    # ── Primary API ──────────────────────────────────────────────────────

    def update(self, features: dict):
        """
        Process one packet. Scores it against the IP's prior profile,
        then updates the profile with the new observation.

        Returns (deviation_score: float 0.0-1.0, reasons: list[str]).
        Returns (0.0, []) during warm-up (first MIN_SAMPLES packets).
        """
        src = features.get("src_ip", "?")
        if src in ("?", "", "0.0.0.0"):
            return 0.0, []

        with self._lock:
            if src not in self._profiles:
                self._profiles[src] = IPProfile()
            profile = self._profiles[src]

        # Score BEFORE observing so we compare against the prior baseline
        deviation, reasons = profile.score(features)
        profile.observe(features)

        return deviation, reasons

    def get_severity(self, score: float) -> str:
        """Convert raw deviation score to a human-readable severity label."""
        if score >= self.THRESHOLD_CRITICAL: return "CRITICAL"
        if score >= self.THRESHOLD_HIGH:     return "HIGH"
        if score >= self.THRESHOLD_MEDIUM:   return "MEDIUM"
        if score >= self.THRESHOLD_LOW:      return "LOW"
        return "NORMAL"

    def get_profile_summary(self, ip: str) -> dict:
        """Return a readable summary of a specific IP's learned profile."""
        with self._lock:
            p = self._profiles.get(ip)
        if not p:
            return {"ip": ip, "status": "no profile yet"}

        top_ports = sorted(
            p.port_counts.items(), key=lambda x: x[1], reverse=True
        )[:5]

        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        top_protos = {
            proto_map.get(int(k), str(k)): v
            for k, v in p.proto_counts.items()
        }

        return {
            "ip":            ip,
            "samples":       p.sample_count,
            "avg_pkt_size":  f"{p._size_mean:.0f}B ±{p.size_std:.0f}",
            "avg_ttl":       f"{p._ttl_mean:.0f} ±{p.ttl_std:.0f}",
            "top_dst_ports": [f":{k} ({v}x)" for k, v in top_ports],
            "protocols":     top_protos,
            "typical_rate":  f"{p.typical_rate:.2f} pkt/s",
            "dst_diversity": len(p.dst_ips),
            "warm_up_done":  p.sample_count >= MIN_SAMPLES,
        }

    def known_ips(self) -> list:
        """Return all IPs that have a learned profile."""
        with self._lock:
            return list(self._profiles.keys())

    def reset_ip(self, ip: str):
        """Wipe the profile for a specific IP (e.g. after unblocking)."""
        with self._lock:
            self._profiles.pop(ip, None)

    # ── Persistence ───────────────────────────────────────────────────────

    def _save(self):
        with self._lock:
            data = {ip: p.to_dict() for ip, p in self._profiles.items()}
        try:
            with open(self.profile_file, "w") as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            print(f"[BehaviorProfiler] Save failed: {e}")

    def _load(self):
        if not os.path.exists(self.profile_file):
            return
        try:
            with open(self.profile_file) as f:
                data = json.load(f)
            with self._lock:
                for ip, d in data.items():
                    self._profiles[ip] = IPProfile.from_dict(d)
            print(f"[BehaviorProfiler] Loaded {len(self._profiles)} "
                  f"IP profiles from {self.profile_file}")
        except (OSError, json.JSONDecodeError) as e:
            print(f"[BehaviorProfiler] Load failed: {e}")

    def _autosave_loop(self):
        while True:
            time.sleep(SAVE_INTERVAL)
            self._save()

    def _start_autosave(self):
        threading.Thread(
            target=self._autosave_loop, daemon=True).start()
