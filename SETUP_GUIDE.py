# ═══════════════════════════════════════════════════════════════════
#  ADVANCED NETWORK SECURITY PLATFORM — SETUP GUIDE
# ═══════════════════════════════════════════════════════════════════
#
#  NEW FILES ADDED TO YOUR PROJECT:
#  ┌──────────────────────┬─────────────────────────────────────────┐
#  │ malware_detector.py  │ C2 beacon, DNS tunnel, payload entropy  │
#  │ phishing_detector.py │ SMTP traffic + email content analysis   │
#  │ ids_ips.py           │ Snort-style rules + rate limiting       │
#  │ main.py (updated)    │ Integrates all 3 new engines            │
#  └──────────────────────┴─────────────────────────────────────────┘
#
# ── STEP 1: Copy new files into your project folder ─────────────────
#
#   malware_detector.py  →  your_project/
#   phishing_detector.py →  your_project/
#   ids_ips.py           →  your_project/
#   main.py (replace)    →  your_project/
#
# ── STEP 2: Install new dependencies ────────────────────────────────
#
#   pip install scapy tensorflow scikit-learn flask flask-socketio
#   pip install requests difflib  # (usually built-in)
#
# ── STEP 3: Run ─────────────────────────────────────────────────────
#
#   python main.py        (Run as Administrator on Windows for packet capture)
#   sudo python main.py   (Linux/Mac)
#
# ═══════════════════════════════════════════════════════════════════
#  WHAT EACH NEW MODULE DETECTS
# ═══════════════════════════════════════════════════════════════════

MALWARE_DETECTOR = """
malware_detector.py
────────────────────
✓ C2 Beacon Detection    Finds malware phoning home at regular intervals
                         (CobaltStrike every ~60s, Emotet every ~300s, etc.)
✓ DNS Tunneling          Oversized/high-entropy DNS packets = data exfiltration
✓ Known C2 IOC Check     Matches src/dst IPs against threat intelligence IOC list
✓ Port Signatures        Metasploit (4444), AsyncRAT, Mirai, Ransomware C2 ports
✓ Payload Entropy        High Shannon entropy on non-HTTPS ports = custom C2 encryption

HOW BEACON DETECTION WORKS:
  Tracks timestamps of (src_ip, dst_ip, port) triplets.
  If jitter < 15% and interval is 30-600s → it's beaconing.
  Matches intervals against known malware families:
    CobaltStrike = 55-65s, Emotet = 295-305s, Ransomware = 115-125s
"""

PHISHING_DETECTOR = """
phishing_detector.py
─────────────────────
✓ SMTP Flood Detection    >20 emails/min from same IP = phishing campaign
✓ SPF / DKIM Failure      Email fails authentication = spoofed sender
✓ Reply-To Mismatch       From: ceo@company.com but Reply-To: hacker@gmail.com
✓ Free Email Spoofing     Gmail pretending to be PayPal/Amazon/IRS
✓ Urgency Language        "Your account will be suspended in 24 hours"
✓ Credential Harvesting   "Enter your password to verify"
✓ Dangerous Attachments   .exe .docm .xlsm .js .vbs .ps1 .lnk in email
✓ URL Analysis            IP-based URLs, punycode homographs, subdomain stuffing
✓ Typosquatting           paypa1.com vs paypal.com (75%+ similarity match)
✓ URL Shorteners          bit.ly, tinyurl hiding phishing destinations

MANUAL EMAIL SCANNER:
  In the app, open the "Phishing" tab.
  Paste any raw email (including headers) into the text box.
  Click "Analyze Email" to get a full phishing report.
"""

IDS_IPS_ENGINE = """
ids_ips.py — IDS/IPS Engine
────────────────────────────
IDS MODE: Detect and ALERT only (passive, never blocks)
IPS MODE: Detect and BLOCK via Windows Firewall (active)

Switch modes live in the UI using the Mode dropdown.

SNORT-STYLE SIGNATURE RULES (SID list):
  1001  NULL Scan            — No TCP flags set (stealth recon)
  1002  XMAS Scan            — FIN+PSH+URG flags (stealth recon)
  1003  FIN Scan             — FIN only (stealth recon)
  2001  EternalBlue SMB      — Port 445 (WannaCry / NotPetya) → BLOCK
  2002  RDP Connection       — Port 3389 monitoring
  2003  SSH Connection       — Port 22 monitoring
  2004  Telnet               — Port 23 → BLOCK (cleartext, insecure)
  2005  Metasploit Shell     — Port 4444/4445 → BLOCK
  2006  Docker API Exposed   — Port 2375/2376 → BLOCK (critical!)
  2007  Redis Exposed        — Port 6379
  2008  MongoDB Exposed      — Port 27017
  2009  Elasticsearch        — Port 9200/9300
  3001  IRC Botnet C2        — Port 6667-6669 → BLOCK
  3002  Tor SOCKS Proxy      — Port 9050
  4001  DNS Amplification    — UDP port 53 both directions
  5001  Ping of Death        — Oversized ICMP → BLOCK

RATE-LIMIT DETECTION (SID 9xxx):
  9001  SYN Flood            — >100 SYN/s from one IP → BLOCK
  9002  ICMP Flood           — >50 ICMP/s from one IP → BLOCK
  9003  UDP Flood            — >200 UDP/s from one IP → BLOCK
  9004  SSH Brute Force      — >5 SSH attempts/30s → BLOCK
  9005  RDP Brute Force      — >3 RDP attempts/30s → BLOCK

PROTOCOL VIOLATION DETECTION (SID 8xxx):
  8001  RST+SYN flags        — Invalid TCP combination (OS fingerprinting)
  8002  All flags set        — Possible XMAS/evasion
  8003  Undersized packet    — <28 bytes on TCP/UDP (malformed fragment)

ADDING CUSTOM RULES (in ids_ips.py or at runtime):
  ids_engine.add_rule({
      "sid": 9999, "name": "Custom Block Port 31337",
      "proto": 6, "dst_ports": {31337}, "tcp_flags": None,
      "severity": "HIGH", "action": "block",
      "msg": "Backdoor port 31337 detected"
  })
"""

INTEGRATION = """
INTEGRATION SUMMARY
───────────────────
Every packet now goes through 5 detection layers:

  Packet → [1] IsolationForest  (ML statistical anomaly)
          → [2] AIThreatEngine   (rule-based behavioral)
          → [3] IDSEngine        (Snort signature + rate limits)
          → [4] MalwareDetector  (C2 beacon + DNS tunnel + IOC)
          → [5] PhishingDetector (SMTP flood detection)
          → [6] AbuseIPDB        (reputation lookup, async)
          → Auto-block decision  (firewall.block_ip)

The packet table now has columns for all 5 engines.
Each engine has its own colour-coded tab in the UI.

COLOUR CODING:
  Purple  = Malware/C2 detected
  Orange  = Phishing detected
  Cyan    = IDS/IPS rule triggered
  Red     = AI threat / real threat
  Green   = IsolationForest anomaly
  Pink    = Auto-blocked
"""
