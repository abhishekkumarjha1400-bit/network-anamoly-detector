# main.py  (UPGRADED — integrates IDS/IPS + Malware Detector + Phishing Detector)
#
# NEW MODULES ADDED:
#   ids_ips.py          — Snort-style rule engine + rate limiting (IDS/IPS)
#   malware_detector.py — C2 beacon detection, DNS tunnel, payload entropy
#   phishing_detector.py— SMTP traffic + email content phishing analysis
#
# All existing functionality (IsolationForest, AIThreatEngine, firewall,
# threat intel, dashboard) is preserved and extended.

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading, time
from datetime import datetime
from collections import deque
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ── Existing modules ──────────────────────────────────────────────────────────
from capture      import PacketCapture
from model_if     import IsolationForestModel
from logger       import init_log, log_anomaly
from threat_intel import (check_ip_reputation, check_port_threat,
                           get_risk_level, is_private_ip)
from firewall     import block_ip, unblock_ip, is_blocked, get_all_blocked

# ── New advanced modules ──────────────────────────────────────────────────────
from ids_ips          import IDSEngine, InspectionResult
from malware_detector import MalwareDetector
from phishing_detector import PhishingDetector

# ── Color palette ─────────────────────────────────────────────────────────────
BG      = "#0f172a"
CARD    = "#1e293b"
GREEN   = "#22c55e"
RED     = "#ef4444"
AMBER   = "#f59e0b"
WHITE   = "#f8fafc"
MUTED   = "#94a3b8"
BLUE    = "#3b82f6"
PURPLE  = "#a855f7"    # malware colour
ORANGE  = "#f97316"    # phishing colour
CYAN    = "#06b6d4"    # IDS/IPS colour

AUTO_BLOCK_THRESHOLD = 80


# ─────────────────────────────────────────────────────────────────────────────
#  Existing AIThreatEngine (unchanged)
# ─────────────────────────────────────────────────────────────────────────────
class AIThreatEngine:
    SUSPICIOUS_PORTS = {
        22:"SSH Brute Force", 23:"Telnet Attack",
        445:"SMB/WannaCry",   3389:"RDP Attack",
        1433:"SQL Attack",    3306:"MySQL Attack",
        6379:"Redis Attack",  27017:"MongoDB Attack",
        4444:"Metasploit",    5555:"Android Backdoor",
        9200:"Elasticsearch", 2375:"Docker API",
        5432:"PostgreSQL",    6667:"IRC Botnet",
    }
    def __init__(self):
        self.ip_packet_count = {}
        self.ip_port_set     = {}
        self.ip_timestamps   = {}

    def analyze(self, features):
        src   = features.get("src_ip",  "?")
        port  = features.get("dst_port", 0)
        proto = features.get("protocol", 0)
        dst   = features.get("dst_ip",  "?")
        now   = time.time()
        self.ip_packet_count[src] = self.ip_packet_count.get(src, 0) + 1
        if src not in self.ip_timestamps:
            self.ip_timestamps[src] = deque(maxlen=200)
        self.ip_timestamps[src].append(now)
        if src not in self.ip_port_set:
            self.ip_port_set[src] = set()
        self.ip_port_set[src].add(port)
        recent = [t for t in self.ip_timestamps[src] if now - t < 5]
        if len(recent) > 100:
            return True, f"DDoS from {src} ({len(recent)} pkt/5s)", "CRITICAL"
        if len(self.ip_port_set[src]) > 20:
            return True, f"Port Scan {src} ({len(self.ip_port_set[src])} ports)", "HIGH"
        if port in self.SUSPICIOUS_PORTS:
            return True, f"{self.SUSPICIOUS_PORTS[port]}: {src}→{dst}:{port}", "HIGH"
        if proto == 1 and len(recent) > 50:
            return True, f"ICMP Flood from {src}", "MEDIUM"
        return False, "", ""


def play_alert():
    try:
        import winsound
        winsound.Beep(1200, 200)
    except:
        pass


# ─────────────────────────────────────────────────────────────────────────────
#  Main Application
# ─────────────────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🛡 Advanced Network Security Platform — IDS/IPS + Malware + Phishing")
        self.geometry("1500x900")
        self.configure(bg=BG)
        self.resizable(True, True)

        init_log()

        # ── Detection engines ─────────────────────────────────────────────────
        self.if_model         = IsolationForestModel()
        self.ai_engine        = AIThreatEngine()
        self.capture          = PacketCapture(callback=self._on_packet)

        # NEW: Advanced detection engines
        self.ids_engine       = IDSEngine(
            mode           = "IPS",
            block_callback = self._ids_block_cb,
            alert_callback = self._ids_alert_cb,
        )
        self.malware_detector = MalwareDetector()
        self.phishing_detector= PhishingDetector()

        # ── Counters ──────────────────────────────────────────────────────────
        self.total          = 0
        self.anomaly_count  = 0
        self.threat_count   = 0
        self.real_threat    = 0
        self.blocked_count  = 0
        self.malware_count  = 0      # NEW
        self.phishing_count = 0      # NEW
        self.ids_alert_count= 0      # NEW

        self.chart_normal   = deque(maxlen=60)
        self.chart_anomaly  = deque(maxlen=60)
        self._sec_n = 0
        self._sec_a = 0

        self.filter_ip    = tk.StringVar()
        self.filter_proto = tk.StringVar(value="All")
        self.auto_block   = tk.BooleanVar(value=True)
        self.ids_mode_var = tk.StringVar(value="IPS")   # NEW: IDS / IPS toggle

        self._build_ui()
        self._start_chart_loop()

    # ─────────────────────────────────────────────────────────────────────────
    #  UI CONSTRUCTION
    # ─────────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Top bar ───────────────────────────────────────────────────────────
        top = tk.Frame(self, bg=CARD, pady=8)
        top.pack(fill="x")
        tk.Label(top,
                 text="🛡  Advanced Network Security Platform",
                 font=("Segoe UI", 13, "bold"),
                 bg=CARD, fg=WHITE).pack(side="left", padx=16)

        bf = tk.Frame(top, bg=CARD)
        bf.pack(side="right", padx=16)

        # IDS/IPS mode toggle (NEW)
        tk.Label(bf, text="Mode:", bg=CARD, fg=MUTED,
                 font=("Segoe UI", 9)).pack(side="left", padx=(0, 4))
        ids_combo = ttk.Combobox(bf, textvariable=self.ids_mode_var,
                                  values=["IDS", "IPS"], width=5,
                                  state="readonly", font=("Segoe UI", 9))
        ids_combo.pack(side="left", padx=4)
        ids_combo.bind("<<ComboboxSelected>>",
                        lambda _: self.ids_engine.set_mode(self.ids_mode_var.get()))

        tk.Checkbutton(bf, text="🔥 Auto-Block",
                       variable=self.auto_block, bg=CARD, fg=AMBER,
                       selectcolor=CARD, activebackground=CARD,
                       activeforeground=AMBER,
                       font=("Segoe UI", 9, "bold"),
                       cursor="hand2").pack(side="left", padx=10)

        self.start_btn = tk.Button(bf, text="▶ Start", command=self._start,
                                    width=10, bg=GREEN, fg="white",
                                    font=("Segoe UI", 10, "bold"),
                                    relief="flat", cursor="hand2")
        self.start_btn.pack(side="left", padx=4)

        self.stop_btn = tk.Button(bf, text="⏹ Stop", command=self._stop,
                                   width=9, bg="#475569", fg="white",
                                   font=("Segoe UI", 10), relief="flat",
                                   cursor="hand2", state="disabled")
        self.stop_btn.pack(side="left", padx=4)

        tk.Button(bf, text="🗑 Clear", command=self._clear,
                  width=9, bg="#334155", fg=MUTED,
                  font=("Segoe UI", 10), relief="flat",
                  cursor="hand2").pack(side="left", padx=4)

        # ── Stat cards row (EXPANDED with 3 new cards) ─────────────────────
        sf = tk.Frame(self, bg=BG, pady=8)
        sf.pack(fill="x", padx=16)
        self.v_total    = self._card(sf, "Total Packets",  WHITE)
        self.v_anomaly  = self._card(sf, "IF Anomalies",   RED)
        self.v_threat   = self._card(sf, "AI Threats",     AMBER)
        self.v_real     = self._card(sf, "Real Malicious", RED)
        self.v_blocked  = self._card(sf, "Auto Blocked",   "#ff6b6b")
        self.v_malware  = self._card(sf, "Malware/C2",     PURPLE)   # NEW
        self.v_phishing = self._card(sf, "Phishing",       ORANGE)   # NEW
        self.v_ids      = self._card(sf, "IDS/IPS Alerts", CYAN)     # NEW
        self.v_status   = self._card(sf, "Status",         GREEN, start="Idle")

        # ── Filter bar ────────────────────────────────────────────────────────
        ff = tk.Frame(self, bg=CARD, pady=6)
        ff.pack(fill="x", padx=16, pady=(0, 4))
        tk.Label(ff, text="🔍 Filter IP:", bg=CARD, fg=MUTED,
                 font=("Segoe UI", 9)).pack(side="left", padx=8)
        tk.Entry(ff, textvariable=self.filter_ip, width=16,
                 bg="#0f172a", fg=WHITE, insertbackground=WHITE,
                 relief="flat", font=("Segoe UI", 9)).pack(side="left", padx=4)
        tk.Label(ff, text="  Protocol:", bg=CARD, fg=MUTED,
                 font=("Segoe UI", 9)).pack(side="left", padx=4)
        ttk.Combobox(ff, textvariable=self.filter_proto,
                     values=["All", "TCP", "UDP", "ICMP"],
                     width=7, state="readonly",
                     font=("Segoe UI", 9)).pack(side="left")
        tk.Button(ff, text="Apply", command=self._apply_filter,
                  bg=BLUE, fg="white", relief="flat",
                  font=("Segoe UI", 9), cursor="hand2", padx=8).pack(side="left", padx=8)
        tk.Button(ff, text="Clear Filter", command=self._clear_filter,
                  bg="#334155", fg=MUTED, relief="flat",
                  font=("Segoe UI", 9), cursor="hand2", padx=8).pack(side="left")

        # ── Main area ─────────────────────────────────────────────────────────
        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        left = tk.Frame(main, bg=CARD)
        left.pack(side="left", fill="both", expand=True)

        nb = ttk.Notebook(left)
        nb.pack(fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=CARD,
                         fieldbackground=CARD, foreground=WHITE,
                         rowheight=22)
        style.configure("TNotebook", background=BG)
        style.configure("TNotebook.Tab", background=CARD, foreground=MUTED,
                         padding=[10, 4])
        style.map("TNotebook.Tab", background=[("selected", "#334155")],
                  foreground=[("selected", WHITE)])

        # ── Tab 1: Packet Table ───────────────────────────────────────────────
        tab_packets = tk.Frame(nb, bg=CARD)
        nb.add(tab_packets, text="📡 Packets")

        cols = ("Time","Src IP","Country","Dst IP","Proto","Port",
                "Size","Risk","IF","IDS","Malware","Phishing","Action")
        self.tree = ttk.Treeview(tab_packets, columns=cols,
                                  show="headings", height=18)
        widths = [70, 110, 60, 110, 50, 55, 55, 70, 70, 90, 100, 80, 90]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="center")

        self.tree.tag_configure("normal",   background=CARD,   foreground=WHITE)
        self.tree.tag_configure("anomaly",  background="#1e3a2e", foreground=GREEN)
        self.tree.tag_configure("threat",   background="#3b1f1f", foreground=RED)
        self.tree.tag_configure("blocked",  background="#2d1a1a", foreground="#ff6b6b")
        self.tree.tag_configure("malware",  background="#2a1a3e", foreground=PURPLE)  # NEW
        self.tree.tag_configure("phishing", background="#3a2000", foreground=ORANGE)  # NEW
        self.tree.tag_configure("ids",      background="#003344", foreground=CYAN)    # NEW
        self.tree.tag_configure("warmup",   background=CARD,    foreground=MUTED)

        vsb = ttk.Scrollbar(tab_packets, orient="vertical",
                             command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # ── Tab 2: IDS/IPS Alerts (NEW) ───────────────────────────────────────
        tab_ids = tk.Frame(nb, bg=CARD)
        nb.add(tab_ids, text="🔍 IDS/IPS")

        self.ids_box = scrolledtext.ScrolledText(
            tab_ids, bg="#001a22", fg=CYAN,
            font=("Consolas", 9), state="disabled", wrap="word")
        self.ids_box.pack(fill="both", expand=True, padx=4, pady=4)

        # IDS stats frame
        ids_stats = tk.Frame(tab_ids, bg=CARD)
        ids_stats.pack(fill="x", padx=4, pady=(0, 4))
        self.ids_stats_label = tk.Label(
            ids_stats,
            text="IDS/IPS Stats: waiting for traffic...",
            bg=CARD, fg=MUTED, font=("Segoe UI", 9))
        self.ids_stats_label.pack(side="left", padx=8)

        # ── Tab 3: Malware/C2 Alerts (NEW) ────────────────────────────────────
        tab_malware = tk.Frame(nb, bg=CARD)
        nb.add(tab_malware, text="☠ Malware/C2")

        self.malware_box = scrolledtext.ScrolledText(
            tab_malware, bg="#150a2a", fg=PURPLE,
            font=("Consolas", 9), state="disabled", wrap="word")
        self.malware_box.pack(fill="both", expand=True, padx=4, pady=4)

        # ── Tab 4: Phishing Alerts (NEW) ──────────────────────────────────────
        tab_phishing = tk.Frame(nb, bg=CARD)
        nb.add(tab_phishing, text="🎣 Phishing")

        self.phishing_box = scrolledtext.ScrolledText(
            tab_phishing, bg="#1a0f00", fg=ORANGE,
            font=("Consolas", 9), state="disabled", wrap="word")
        self.phishing_box.pack(fill="both", expand=True, padx=4, pady=4)

        # Phishing email analyzer (manual input)
        ph_input_frame = tk.Frame(tab_phishing, bg=CARD)
        ph_input_frame.pack(fill="x", padx=4, pady=4)
        tk.Label(ph_input_frame, text="Paste raw email to analyze:",
                 bg=CARD, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w")
        self.email_input = scrolledtext.ScrolledText(
            ph_input_frame, bg="#0f172a", fg=WHITE,
            font=("Consolas", 9), height=6, wrap="word")
        self.email_input.pack(fill="x", pady=4)
        tk.Button(ph_input_frame, text="🎣 Analyze Email",
                  command=self._analyze_email_manual,
                  bg=ORANGE, fg="white", font=("Segoe UI", 9, "bold"),
                  relief="flat", cursor="hand2", padx=12).pack(anchor="e")

        # ── Tab 5: Existing IF Anomalies ──────────────────────────────────────
        tab_log = tk.Frame(nb, bg=CARD)
        nb.add(tab_log, text="⚠ IF Anomalies")
        self.log_box = scrolledtext.ScrolledText(
            tab_log, bg="#0f2218", fg=GREEN,
            font=("Consolas", 9), state="disabled", wrap="word")
        self.log_box.pack(fill="both", expand=True, padx=4, pady=4)

        # ── Tab 6: AI Threats ─────────────────────────────────────────────────
        tab_threat = tk.Frame(nb, bg=CARD)
        nb.add(tab_threat, text="🔴 AI Threats")
        self.threat_box = scrolledtext.ScrolledText(
            tab_threat, bg="#200a0a", fg=RED,
            font=("Consolas", 9), state="disabled", wrap="word")
        self.threat_box.pack(fill="both", expand=True, padx=4, pady=4)

        # ── Tab 7: Threat Intel ───────────────────────────────────────────────
        tab_intel = tk.Frame(nb, bg=CARD)
        nb.add(tab_intel, text="🌐 Intel")
        self.intel_box = scrolledtext.ScrolledText(
            tab_intel, bg="#1a1400", fg=AMBER,
            font=("Consolas", 9), state="disabled", wrap="word")
        self.intel_box.pack(fill="both", expand=True, padx=4, pady=4)

        # ── Tab 8: Blocked IPs ────────────────────────────────────────────────
        tab_blocked = tk.Frame(nb, bg=CARD)
        nb.add(tab_blocked, text="🚫 Blocked")
        self.blocked_list = tk.Listbox(
            tab_blocked, bg=CARD, fg="#ff6b6b",
            font=("Consolas", 10), selectbackground="#334155")
        self.blocked_list.pack(fill="both", expand=True, padx=4, pady=4)
        btn_unblock = tk.Button(
            tab_blocked, text="Unblock Selected",
            command=self._unblock_selected,
            bg="#334155", fg=WHITE, relief="flat",
            font=("Segoe UI", 9), cursor="hand2")
        btn_unblock.pack(pady=4)

        # ── Right panel: Chart ────────────────────────────────────────────────
        right = tk.Frame(main, bg=CARD, width=320)
        right.pack(side="right", fill="y", padx=(8, 0))
        right.pack_propagate(False)

        tk.Label(right, text="Live Traffic",
                 bg=CARD, fg=MUTED,
                 font=("Segoe UI", 10, "bold")).pack(pady=(8, 0))

        fig = Figure(figsize=(3.0, 3.5), dpi=90, facecolor=CARD)
        self.ax = fig.add_subplot(111, facecolor=BG)
        self.ax.tick_params(colors=MUTED, labelsize=7)
        for spine in self.ax.spines.values():
            spine.set_edgecolor(MUTED)
        self.canvas_chart = FigureCanvasTkAgg(fig, master=right)
        self.canvas_chart.get_tk_widget().pack(fill="both", expand=True, padx=8)

        # IDS Stats mini panel (NEW)
        ids_mini = tk.Frame(right, bg=CARD)
        ids_mini.pack(fill="x", padx=8, pady=4)
        tk.Label(ids_mini, text="IDS/IPS Summary",
                 bg=CARD, fg=CYAN,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.ids_mini_label = tk.Label(
            ids_mini, text="No alerts yet",
            bg=CARD, fg=MUTED, font=("Consolas", 8),
            justify="left", wraplength=280)
        self.ids_mini_label.pack(anchor="w")

        # Status bar
        self.status_bar = tk.Label(
            self, text="Ready — press Start to begin capture",
            bg="#0a0f1e", fg=MUTED,
            font=("Segoe UI", 9), anchor="w")
        self.status_bar.pack(fill="x", side="bottom")

    # ─────────────────────────────────────────────────────────────────────────
    #  HELPER: stat card
    # ─────────────────────────────────────────────────────────────────────────
    def _card(self, parent, label, color, start="0"):
        f = tk.Frame(parent, bg=CARD, padx=12, pady=6,
                     relief="flat", bd=0)
        f.pack(side="left", padx=6)
        tk.Label(f, text=label, bg=CARD, fg=MUTED,
                 font=("Segoe UI", 8)).pack()
        v = tk.StringVar(value=start)
        tk.Label(f, textvariable=v, bg=CARD, fg=color,
                 font=("Segoe UI", 16, "bold")).pack()
        return v

    # ─────────────────────────────────────────────────────────────────────────
    #  CONTROLS
    # ─────────────────────────────────────────────────────────────────────────
    def _start(self):
        self.capture.start()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.v_status.set("Running")

    def _stop(self):
        self.capture.stop()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.v_status.set("Stopped")

    def _clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for box in (self.log_box, self.threat_box, self.intel_box,
                    self.ids_box, self.malware_box, self.phishing_box):
            box.config(state="normal")
            box.delete("1.0", "end")
            box.config(state="disabled")

    def _apply_filter(self):
        pass  # Filter applied in _add_row

    def _clear_filter(self):
        self.filter_ip.set("")
        self.filter_proto.set("All")

    def _unblock_selected(self):
        sel = self.blocked_list.curselection()
        if not sel:
            return
        ip = self.blocked_list.get(sel[0]).split()[0]
        ok, msg = unblock_ip(ip)
        if ok:
            self.blocked_list.delete(sel[0])
            self.blocked_count = max(0, self.blocked_count - 1)

    def _refresh_blocked(self):
        self.blocked_list.delete(0, "end")
        for ip in get_all_blocked():
            self.blocked_list.insert("end", ip)

    # ─────────────────────────────────────────────────────────────────────────
    #  LIVE CHART
    # ─────────────────────────────────────────────────────────────────────────
    def _start_chart_loop(self):
        def tick():
            while True:
                time.sleep(1)
                self.chart_normal.append(self._sec_n)
                self.chart_anomaly.append(self._sec_a)
                self._sec_n = self._sec_a = 0
                self.after(0, self._redraw_chart)
        threading.Thread(target=tick, daemon=True).start()

    def _redraw_chart(self):
        self.ax.clear()
        self.ax.set_facecolor(BG)
        xs = list(range(len(self.chart_normal)))
        if xs:
            self.ax.fill_between(xs, list(self.chart_normal),
                                  color=GREEN, alpha=0.4, label="Normal")
            self.ax.fill_between(xs, list(self.chart_anomaly),
                                  color=RED, alpha=0.6, label="Anomaly")
            self.ax.legend(fontsize=7, facecolor=CARD,
                           labelcolor=WHITE, loc="upper left")
        self.ax.tick_params(colors=MUTED, labelsize=7)
        for spine in self.ax.spines.values():
            spine.set_edgecolor(MUTED)
        self.canvas_chart.draw()

    # ─────────────────────────────────────────────────────────────────────────
    #  IDS / IPS CALLBACKS (called from IDSEngine)
    # ─────────────────────────────────────────────────────────────────────────
    def _ids_block_cb(self, ip: str, reason: str):
        """Called by IPS when it decides to block."""
        if not is_blocked(ip):
            ok, msg = block_ip(ip, reason)
            if ok:
                self.blocked_count += 1
                self.after(0, self._log_ids_block, ip, reason)
                self.after(0, self._refresh_blocked)

    def _ids_alert_cb(self, result: InspectionResult):
        """Called by IDS for every rule hit."""
        self.ids_alert_count += 1
        self.after(0, self._log_ids_alert, result)
        self.after(0, self._update_ids_stats)

    def _log_ids_block(self, ip, reason):
        now = datetime.now().strftime("%H:%M:%S")
        msg = (f"[{now}] 🔒 IPS BLOCKED {ip}\n"
               f"  Reason: {reason}\n"
               f"{'═'*35}\n")
        self.ids_box.config(state="normal")
        self.ids_box.insert("1.0", msg)
        self.ids_box.config(state="disabled")

    def _log_ids_alert(self, result: InspectionResult):
        now = datetime.now().strftime("%H:%M:%S")
        sev_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
        icon = sev_icons.get(result.severity, "⚪")
        action_str = "🚫 BLOCKED" if result.blocked else "👁 ALERT"
        msg = (f"[{now}] {icon} SID:{result.sid} [{result.severity}] "
               f"{action_str}\n"
               f"  Rule:   {result.rule_name}\n"
               f"  Method: {result.method}\n"
               f"  Src:    {result.src_ip} → {result.dst_ip}:{result.dst_port}\n"
               f"  Detail: {result.msg}\n"
               f"{'─'*35}\n")
        self.ids_box.config(state="normal")
        self.ids_box.insert("1.0", msg)
        self.ids_box.config(state="disabled")
        self.v_ids.set(str(self.ids_alert_count))

    def _update_ids_stats(self):
        s = self.ids_engine.get_stats()
        text = (f"Inspected: {s['total_inspected']}  "
                f"Alerts: {s['alerts']}  Blocks: {s['blocks']}\n"
                f"CRITICAL:{s['by_severity']['CRITICAL']}  "
                f"HIGH:{s['by_severity']['HIGH']}  "
                f"MEDIUM:{s['by_severity']['MEDIUM']}  "
                f"LOW:{s['by_severity']['LOW']}")
        self.ids_mini_label.config(text=text)
        self.ids_stats_label.config(text=f"IDS/IPS: {text.replace(chr(10), '  ')}")

    # ─────────────────────────────────────────────────────────────────────────
    #  MANUAL EMAIL ANALYZER
    # ─────────────────────────────────────────────────────────────────────────
    def _analyze_email_manual(self):
        raw = self.email_input.get("1.0", "end").strip()
        if not raw:
            messagebox.showwarning("Empty", "Paste an email first.")
            return
        is_ph, attack, conf, findings = \
            self.phishing_detector.analyze_email(raw)
        now = datetime.now().strftime("%H:%M:%S")
        verdict = f"🎣 {attack}" if is_ph else "✅ Clean"
        msg = (f"[{now}] MANUAL EMAIL SCAN\n"
               f"  Verdict:    {verdict}\n"
               f"  Confidence: {conf:.0%}\n"
               f"  Findings ({len(findings)}):\n")
        for f in findings:
            msg += f"    • {f}\n"
        msg += f"{'═'*35}\n"
        self.phishing_box.config(state="normal")
        self.phishing_box.insert("1.0", msg)
        self.phishing_box.config(state="disabled")

    # ─────────────────────────────────────────────────────────────────────────
    #  PACKET PROCESSING PIPELINE
    # ─────────────────────────────────────────────────────────────────────────
    def _on_packet(self, features, vector):
        """Called for every captured packet (from PacketCapture thread)."""
        self.total += 1
        src  = features.get("src_ip", "?")
        port = features.get("dst_port", 0)

        # 1. IsolationForest
        is_if, if_score = self.if_model.update(vector)

        # 2. Rule-based AI threat engine
        is_ai, ai_type, severity = self.ai_engine.analyze(features)

        # 3. IDS/IPS engine (NEW)
        ids_result = self.ids_engine.inspect(features)

        # 4. Malware/C2 detector (NEW)
        is_mw, mw_name, mw_conf, mw_detail = \
            self.malware_detector.analyze(features)

        # 5. Phishing detector on SMTP packets (NEW)
        is_ph, ph_type, ph_conf, ph_detail = \
            self.phishing_detector.analyze_packet(features)

        is_anomaly = is_if or is_ai or ids_result.triggered or is_mw or is_ph

        if is_if:
            self.anomaly_count += 1
            log_anomaly(features, "IsolationForest", if_score)

        if is_ai:
            self.threat_count += 1
            log_anomaly(features, f"AI:{severity}", 1.0)
            threading.Thread(target=play_alert, daemon=True).start()

        if is_mw:
            self.malware_count += 1
            log_anomaly(features, f"MALWARE:{mw_name}", mw_conf)
            self.after(0, self._log_malware, features, mw_name, mw_conf, mw_detail)

        if is_ph:
            self.phishing_count += 1
            log_anomaly(features, f"PHISHING:{ph_type}", ph_conf)
            self.after(0, self._log_phishing, features, ph_type, ph_conf, str(ph_detail))

        if is_anomaly:
            self._sec_a += 1
        else:
            self._sec_n += 1

        if not is_private_ip(src):
            threading.Thread(
                target=self._check_and_block,
                args=(features, src, port,
                      is_if, if_score,
                      is_ai, ai_type, severity,
                      ids_result, is_mw, mw_name,
                      is_ph, ph_type),
                daemon=True
            ).start()
        else:
            self.after(0, self._add_row,
                       features, "🏠 Local", "Local",
                       is_if, if_score,
                       is_ai, ai_type, severity,
                       ids_result,
                       is_mw, mw_name,
                       is_ph, ph_type,
                       False, "", 0, False)

    def _check_and_block(self, features, src, port,
                          is_if, if_score,
                          is_ai, ai_type, severity,
                          ids_result, is_mw, mw_name,
                          is_ph, ph_type):
        rep      = check_ip_reputation(src)
        port_bad, port_name = check_port_threat(port)

        is_real = rep["is_malicious"] or port_bad
        risk    = rep["risk_score"]
        reason  = rep["reason"]

        if port_bad and not reason:
            reason = port_name
            risk   = max(risk, 75)

        if is_real:
            self.real_threat += 1
            log_anomaly(features, f"REAL_THREAT:{reason}", risk)
            threading.Thread(target=play_alert, daemon=True).start()

        # Auto-block: triggered by IPS rule, malware, phishing, or reputation
        was_blocked = False
        should_block = (
            self.auto_block.get() and not is_blocked(src) and (
                (ids_result.triggered and ids_result.action == "block") or
                (is_mw and mw_name and "C2" in mw_name) or
                (is_real and risk >= AUTO_BLOCK_THRESHOLD)
            )
        )
        if should_block:
            block_reason = (ids_result.msg if ids_result.triggered
                            else reason or mw_name)
            ok, msg = block_ip(src, block_reason)
            if ok:
                was_blocked = True
                self.blocked_count += 1
                self.after(0, self._log_block, msg)

        self.after(0, self._add_row,
                   features,
                   rep["country"], rep["isp"],
                   is_if, if_score,
                   is_ai, ai_type, severity,
                   ids_result,
                   is_mw, mw_name,
                   is_ph, ph_type,
                   is_real, reason, risk, was_blocked)

    # ─────────────────────────────────────────────────────────────────────────
    #  LOG HELPERS
    # ─────────────────────────────────────────────────────────────────────────
    def _log_block(self, msg):
        now   = datetime.now().strftime("%H:%M:%S")
        entry = f"[{now}] 🚫 AUTO-BLOCKED\n  {msg}\n{'═'*30}\n"
        self.intel_box.config(state="normal")
        self.intel_box.insert("1.0", entry)
        self.intel_box.config(state="disabled")
        self.v_blocked.set(str(self.blocked_count))
        self._refresh_blocked()

    def _log_malware(self, features, name, conf, detail):
        now = datetime.now().strftime("%H:%M:%S")
        msg = (f"[{now}] ☠ MALWARE DETECTED\n"
               f"  Type:       {name}\n"
               f"  Confidence: {conf:.0%}\n"
               f"  Src IP:     {features.get('src_ip','?')}\n"
               f"  Dst IP:     {features.get('dst_ip','?')}:"
               f"{features.get('dst_port',0)}\n"
               f"  Detail:     {detail}\n"
               f"{'═'*35}\n")
        self.malware_box.config(state="normal")
        self.malware_box.insert("1.0", msg)
        self.malware_box.config(state="disabled")
        self.v_malware.set(str(self.malware_count))

    def _log_phishing(self, features, ph_type, conf, detail):
        now = datetime.now().strftime("%H:%M:%S")
        msg = (f"[{now}] 🎣 PHISHING TRAFFIC\n"
               f"  Type:       {ph_type}\n"
               f"  Confidence: {conf:.0%}\n"
               f"  Src IP:     {features.get('src_ip','?')}\n"
               f"  Detail:     {detail}\n"
               f"{'═'*35}\n")
        self.phishing_box.config(state="normal")
        self.phishing_box.insert("1.0", msg)
        self.phishing_box.config(state="disabled")
        self.v_phishing.set(str(self.phishing_count))

    # ─────────────────────────────────────────────────────────────────────────
    #  TABLE ROW
    # ─────────────────────────────────────────────────────────────────────────
    def _add_row(self, features, country, isp,
                  is_if, if_score,
                  is_ai, ai_type, severity,
                  ids_result,
                  is_mw, mw_name,
                  is_ph, ph_type,
                  is_real, reason, risk, was_blocked):

        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto = proto_map.get(features.get("protocol", 0),
                               str(features.get("protocol", 0)))
        risk_label = get_risk_level(risk) if risk > 0 else "✅ Safe"

        # Determine row colour priority
        if self.total < 30:
            tag = "warmup"
        elif was_blocked:
            tag = "blocked"
        elif is_mw:
            tag = "malware"
        elif is_ph:
            tag = "phishing"
        elif ids_result.triggered and ids_result.severity == "CRITICAL":
            tag = "blocked"
        elif ids_result.triggered:
            tag = "ids"
        elif is_real:
            tag = "threat"
        elif is_ai:
            tag = "threat"
        elif is_if:
            tag = "anomaly"
        else:
            tag = "normal"

        ids_col   = (f"[{ids_result.severity}] {ids_result.rule_name[:18]}"
                     if ids_result.triggered else "—")
        mw_col    = f"☠ {mw_name[:14]}" if is_mw else "—"
        ph_col    = f"🎣 {ph_type[:12]}" if is_ph else "—"
        action_col = ("🚫 BLOCKED"  if was_blocked
                      else "🚨 REAL"   if is_real
                      else "🔴 THREAT" if is_ai
                      else "⚠ ANOMALY" if is_if
                      else "✓ Normal")

        row = (
            datetime.now().strftime("%H:%M:%S"),
            features.get("src_ip", "?"),
            country,
            features.get("dst_ip", "?"),
            proto,
            features.get("dst_port", 0),
            features.get("pkt_size", 0),
            risk_label,
            f"{if_score:.3f}" if is_if else "—",
            ids_col,
            mw_col,
            ph_col,
            action_col,
        )

        self.tree.insert("", 0, values=row, tags=(tag,))
        rows = self.tree.get_children()
        if len(rows) > 400:
            self.tree.delete(rows[-1])

        # Update all stat counters
        self.v_total.set(str(self.total))
        self.v_anomaly.set(str(self.anomaly_count))
        self.v_threat.set(str(self.threat_count))
        self.v_real.set(str(self.real_threat))
        self.v_blocked.set(str(self.blocked_count))
        self.v_malware.set(str(self.malware_count))
        self.v_phishing.set(str(self.phishing_count))

        self.status_bar.config(
            text=(f"Packets: {self.total}  |  "
                  f"IDS/IPS: {self.ids_alert_count}  |  "
                  f"Malware: {self.malware_count}  |  "
                  f"Phishing: {self.phishing_count}  |  "
                  f"Blocked: {self.blocked_count} 🚫"))


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Optional: start web dashboard in background
    try:
        from dashboard import run_dashboard
        threading.Thread(target=run_dashboard, daemon=True).start()
    except Exception:
        pass

    app = App()
    app.mainloop()
