# network_monitor.py
# ─────────────────────────────────────────────────────────────────────────────
# A live window that shows ALL real IPs connecting to your network with:
#   - Full IP info (country, city, ISP, org, ASN)
#   - Behaviour classification (what the connection is doing)
#   - Connection stats (packet count, ports used, first/last seen)
#   - Threat level from AbuseIPDB
#   - Whether IP belongs to a known provider (Cloudflare, Google, etc.)
# ─────────────────────────────────────────────────────────────────────────────

import tkinter as tk
from tkinter import ttk
import threading
import time
import requests
from datetime import datetime
from collections import defaultdict

# ── Colors ────────────────────────────────────────────────────────────────────
BG    = "#0f172a"
CARD  = "#1e293b"
GREEN = "#22c55e"
RED   = "#ef4444"
AMBER = "#f59e0b"
WHITE = "#f8fafc"
MUTED = "#94a3b8"
BLUE  = "#3b82f6"
CYAN  = "#06b6d4"

# ── Full IP Range → Provider mapping ─────────────────────────────────────────
KNOWN_PROVIDERS = {
    # Cloudflare — full range
    "173.245.48": "Cloudflare","103.21.244": "Cloudflare","103.22.200": "Cloudflare",
    "103.31.4":   "Cloudflare","141.101.64": "Cloudflare","108.162.192":"Cloudflare",
    "190.93.240": "Cloudflare","188.114.96": "Cloudflare","197.234.240":"Cloudflare",
    "198.41.128": "Cloudflare","162.158":    "Cloudflare",
    "104.16":     "Cloudflare","104.17":     "Cloudflare","104.18":     "Cloudflare",
    "104.19":     "Cloudflare","104.20":     "Cloudflare","104.21":     "Cloudflare",
    "104.22":     "Cloudflare","104.23":     "Cloudflare","104.24":     "Cloudflare",
    "104.25":     "Cloudflare","104.26":     "Cloudflare","104.27":     "Cloudflare",
    "172.64":     "Cloudflare","172.65":     "Cloudflare","172.66":     "Cloudflare",
    "172.67":     "Cloudflare","172.68":     "Cloudflare","172.69":     "Cloudflare",
    "172.70":     "Cloudflare","172.71":     "Cloudflare",
    # Google
    "8.8":        "Google DNS","74.125":     "Google",    "142.250":    "Google",
    "172.253":    "Google",    "216.58":     "Google",    "216.239":    "Google",
    "64.233":     "Google",    "66.102":     "Google",    "66.249":     "Googlebot",
    "209.85":     "Google",
    # Microsoft / Azure
    "13.69":      "Microsoft Azure","13.77":      "Microsoft Azure",
    "13.107":     "Microsoft",      "20.190":     "Microsoft Azure",
    "40.96":      "Microsoft",      "52.112":     "Microsoft Teams",
    "204.79":     "Microsoft",      "23.96":      "Microsoft Azure",
    # Amazon AWS / CloudFront
    "54.192":     "Amazon CloudFront","54.230":   "Amazon CloudFront",
    "99.86":      "Amazon CloudFront","205.251":  "Amazon CloudFront",
    "13.32":      "Amazon CloudFront","13.35":    "Amazon CloudFront",
    # Akamai
    "23.32":      "Akamai","23.33":      "Akamai","23.192":     "Akamai",
    "23.193":     "Akamai","23.200":     "Akamai","23.201":     "Akamai",
    "151.101":    "Fastly CDN",
    # Apple
    "17":         "Apple",
    # Meta/Facebook
    "157.240":    "Meta/Facebook","31.13":      "Meta/Facebook",
    "69.171":     "Meta/Facebook","179.60":     "Meta/Facebook",
}

# ── Port → Behaviour ──────────────────────────────────────────────────────────
PORT_BEHAVIOUR = {
    80:    "Web Browsing (HTTP)",      443:   "Secure Web (HTTPS)",
    53:    "DNS Query",                22:    "SSH Connection",
    3389:  "Remote Desktop (RDP)",    445:   "File Sharing (SMB)",
    3306:  "MySQL Database",          5432:  "PostgreSQL Database",
    6379:  "Redis Cache",             27017: "MongoDB",
    25:    "Email (SMTP)",            587:   "Email (SMTP/TLS)",
    993:   "Email (IMAP)",            995:   "Email (POP3)",
    8080:  "Web Proxy/Dev Server",    8443:  "Alt HTTPS",
    123:   "Time Sync (NTP)",         5353:  "mDNS Discovery",
    1900:  "UPnP Discovery",          5228:  "Google Push (Android)",
    5222:  "XMPP/Chat",               5060:  "VoIP (SIP)",
    1935:  "Video Stream (RTMP)",     554:   "Video Stream (RTSP)",
    6881:  "BitTorrent",              4444:  "⚠ Metasploit Shell",
    50050: "⚠ CobaltStrike C2",       23:    "⚠ Telnet (Insecure)",
    135:   "Windows RPC",             20063: "App/Game Connection",
    16280: "App Connection",
}

def get_provider(ip):
    parts = ip.split(".")
    for length in [3, 2, 1]:
        prefix = ".".join(parts[:length])
        if prefix in KNOWN_PROVIDERS:
            return KNOWN_PROVIDERS[prefix]
    return ""

def get_behaviour(port):
    if port in PORT_BEHAVIOUR:
        return PORT_BEHAVIOUR[port]
    if 20000 <= port <= 65535:
        return "High Port (App/Game/P2P)"
    if 1024 <= port <= 9999:
        return "App Connection"
    return "Unknown Service"


class NetworkMonitorWindow(tk.Toplevel):
    """
    Standalone window showing all real IPs connecting to your network
    with full details: country, ISP, org, ASN, behaviour, threat level.
    """

    def __init__(self, master=None):
        super().__init__(master)
        self.title("🌐 Real Network Connections Monitor")
        self.geometry("1400x700")
        self.configure(bg=BG)

        # Data store: ip -> info dict
        self._connections = {}
        self._lock        = threading.Lock()

        self._build_ui()
        self._refresh_loop()

    def _build_ui(self):
        # ── Title bar ─────────────────────────────────────────────────────────
        top = tk.Frame(self, bg=CARD, pady=8)
        top.pack(fill="x")
        tk.Label(top, text="🌐 Real Network Connections — Full IP Range & Behaviour",
                 bg=CARD, fg=WHITE, font=("Segoe UI", 13, "bold")).pack(side="left", padx=12)
        tk.Button(top, text="🔄 Refresh", bg=BLUE, fg=WHITE,
                  font=("Segoe UI", 9, "bold"), relief="flat",
                  command=self._manual_refresh).pack(side="right", padx=8)
        tk.Button(top, text="🗑 Clear", bg="#475569", fg=WHITE,
                  font=("Segoe UI", 9, "bold"), relief="flat",
                  command=self._clear).pack(side="right", padx=4)

        # ── Stats bar ─────────────────────────────────────────────────────────
        stats = tk.Frame(self, bg="#0f2027", pady=6)
        stats.pack(fill="x")
        self.v_total    = tk.StringVar(value="0")
        self.v_threat   = tk.StringVar(value="0")
        self.v_safe     = tk.StringVar(value="0")
        self.v_cdn      = tk.StringVar(value="0")
        for label, var, color in [
            ("Total IPs",     self.v_total,  WHITE),
            ("🚨 Threats",    self.v_threat, RED),
            ("✅ Safe",       self.v_safe,   GREEN),
            ("☁ CDN/Cloud",   self.v_cdn,    CYAN),
        ]:
            f = tk.Frame(stats, bg="#0f2027", padx=20)
            f.pack(side="left")
            tk.Label(f, textvariable=var, bg="#0f2027", fg=color,
                     font=("Segoe UI", 18, "bold")).pack()
            tk.Label(f, text=label, bg="#0f2027", fg=MUTED,
                     font=("Segoe UI", 8)).pack()

        # ── Treeview ──────────────────────────────────────────────────────────
        cols = ("IP", "Country", "City", "ISP / Organisation",
                "ASN", "Type", "Behaviour", "Ports Used",
                "Packets", "Threat Score", "First Seen", "Last Seen")
        frame = tk.Frame(self, bg=BG)
        frame.pack(fill="both", expand=True, padx=8, pady=8)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Monitor.Treeview",
            background=CARD, foreground=WHITE,
            fieldbackground=CARD, rowheight=26,
            font=("Consolas", 9))
        style.configure("Monitor.Treeview.Heading",
            background="#334155", foreground=WHITE,
            font=("Segoe UI", 9, "bold"))
        style.map("Monitor.Treeview",
            background=[("selected", "#1d4ed8")])

        vsb = ttk.Scrollbar(frame, orient="vertical")
        hsb = ttk.Scrollbar(frame, orient="horizontal")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings",
                                  style="Monitor.Treeview",
                                  yscrollcommand=vsb.set,
                                  xscrollcommand=hsb.set)
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        widths = [120, 100, 110, 200, 120, 120, 180, 130, 70, 100, 80, 80]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col,
                              command=lambda c=col: self._sort(c))
            self.tree.column(col, width=w, anchor="w")

        # Tag colors
        self.tree.tag_configure("threat",   background="#450a0a", foreground=RED)
        self.tree.tag_configure("safe",     background="#052e16", foreground=GREEN)
        self.tree.tag_configure("cdn",      background="#0c1a2e", foreground=CYAN)
        self.tree.tag_configure("unknown",  background=CARD,      foreground=MUTED)

        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True)

        # ── Detail panel ──────────────────────────────────────────────────────
        detail_frame = tk.Frame(self, bg=CARD, height=80)
        detail_frame.pack(fill="x", padx=8, pady=(0,8))
        detail_frame.pack_propagate(False)
        tk.Label(detail_frame, text="📋 Connection Detail:",
                 bg=CARD, fg=AMBER,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=2)
        self.detail_var = tk.StringVar(
            value="Click any row to see full connection details...")
        tk.Label(detail_frame, textvariable=self.detail_var,
                 bg=CARD, fg=WHITE,
                 font=("Consolas", 9), justify="left",
                 wraplength=1350).pack(anchor="w", padx=8)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    def add_connection(self, src_ip, dst_ip, port, rep: dict):
        """Called from main.py for every packet processed."""
        now  = datetime.now().strftime("%H:%M:%S")
        # Determine which IP is the external one
        ext_ip = src_ip
        from threat_intel import is_private_ip
        if is_private_ip(src_ip) and not is_private_ip(dst_ip):
            ext_ip = dst_ip
        elif is_private_ip(src_ip) and is_private_ip(dst_ip):
            return  # Both local — skip

        with self._lock:
            if ext_ip not in self._connections:
                self._connections[ext_ip] = {
                    "ip":          ext_ip,
                    "country":     rep.get("country", "?"),
                    "city":        rep.get("location", "").split(",")[0].strip(),
                    "isp":         rep.get("isp", "?"),
                    "org":         rep.get("org", ""),
                    "asn":         rep.get("asn", ""),
                    "conn_type":   rep.get("conn_type", "?"),
                    "provider":    get_provider(ext_ip),
                    "ports":       set(),
                    "packets":     0,
                    "risk":        rep.get("risk_score", 0),
                    "first_seen":  now,
                    "last_seen":   now,
                    "behaviours":  set(),
                }
            c = self._connections[ext_ip]
            c["ports"].add(port)
            c["packets"] += 1
            c["last_seen"] = now
            c["risk"] = max(c["risk"], rep.get("risk_score", 0))
            behaviour = get_behaviour(port)
            if behaviour:
                c["behaviours"].add(behaviour)

    def _refresh_loop(self):
        """Auto-refresh every 3 seconds."""
        self._render()
        self.after(3000, self._refresh_loop)

    def _manual_refresh(self):
        self._render()

    def _render(self):
        with self._lock:
            connections = dict(self._connections)

        # Update stats
        total   = len(connections)
        threats = sum(1 for c in connections.values() if c["risk"] >= 50)
        safe    = sum(1 for c in connections.values()
                      if c["risk"] < 50 and not c["provider"])
        cdns    = sum(1 for c in connections.values() if c["provider"])

        self.v_total.set(str(total))
        self.v_threat.set(str(threats))
        self.v_safe.set(str(safe))
        self.v_cdn.set(str(cdns))

        # Clear and rebuild tree
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Sort by risk score descending
        sorted_conns = sorted(connections.values(),
                              key=lambda x: x["risk"], reverse=True)

        for c in sorted_conns:
            ports_str = ", ".join(str(p) for p in sorted(c["ports"])[:5])
            if len(c["ports"]) > 5:
                ports_str += f" +{len(c['ports'])-5}"
            behaviour_str = " | ".join(list(c["behaviours"])[:2])
            if len(c["behaviours"]) > 2:
                behaviour_str += f" +{len(c['behaviours'])-2} more"

            isp_org = c["isp"]
            if c["org"] and c["org"] != c["isp"]:
                isp_org = f"{c['isp']} / {c['org']}"

            conn_type = c["provider"] if c["provider"] else c["conn_type"]
            risk_str  = f"{c['risk']}%" if c["risk"] > 0 else "✅ Safe"

            row = (
                c["ip"], c["country"], c["city"],
                isp_org, c["asn"], conn_type,
                behaviour_str, ports_str,
                str(c["packets"]), risk_str,
                c["first_seen"], c["last_seen"]
            )

            # Tag for color
            if c["risk"] >= 50:
                tag = "threat"
            elif c["provider"]:
                tag = "cdn"
            elif c["risk"] < 10:
                tag = "safe"
            else:
                tag = "unknown"

            self.tree.insert("", "end", iid=c["ip"],
                             values=row, tags=(tag,))

    def _on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        ip = sel[0]
        with self._lock:
            c = self._connections.get(ip)
        if not c:
            return
        ports_full = ", ".join(str(p) for p in sorted(c["ports"]))
        behaviours = " | ".join(c["behaviours"]) if c["behaviours"] else "Unknown"
        detail = (
            f"IP: {c['ip']}  |  Country: {c['country']}  |  "
            f"City: {c['city']}  |  ISP: {c['isp']}  |  "
            f"Org: {c['org']}  |  ASN: {c['asn']}  |  "
            f"Type: {c['conn_type']}  |  Provider: {c['provider'] or 'Unknown'}  |  "
            f"Ports: {ports_full}  |  Behaviour: {behaviours}  |  "
            f"Packets: {c['packets']}  |  "
            f"Threat Score: {c['risk']}%  |  "
            f"First: {c['first_seen']}  Last: {c['last_seen']}"
        )
        self.detail_var.set(detail)

    def _clear(self):
        with self._lock:
            self._connections.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.v_total.set("0"); self.v_threat.set("0")
        self.v_safe.set("0");  self.v_cdn.set("0")

    def _sort(self, col):
        """Sort treeview by column."""
        items = [(self.tree.set(k, col), k)
                 for k in self.tree.get_children("")]
        items.sort()
        for idx, (_, k) in enumerate(items):
            self.tree.move(k, "", idx)
