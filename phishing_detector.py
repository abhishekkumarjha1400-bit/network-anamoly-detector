# phishing_detector.py
# Detects phishing attacks in email traffic captured on the network.
#
# DETECTION LAYERS:
#  1. SMTP Traffic Analysis   – inspect emails passing over port 25/587/465
#  2. URL Analysis            – detect homograph, typosquat, URL shortener abuse
#  3. Header Forensics        – SPF/DKIM fail, Reply-To mismatch, spoofed From
#  4. Content Heuristics      – urgency words, credential harvesting phrases
#  5. Attachment Risk         – dangerous extension detection in MIME headers
#  6. Domain Reputation       – newly registered domains, free-email spoofing
#
# Usage:
#   detector = PhishingDetector()
#   # From network packet features:
#   result = detector.analyze_packet(features)
#   # From raw email string (if you captured SMTP payload):
#   result = detector.analyze_email(raw_email_string)

import re
import math
import time
import urllib.parse
from difflib import SequenceMatcher
from collections import defaultdict

# ── Urgency / Social Engineering Keywords ────────────────────────────────────
URGENCY_PHRASES = [
    r"verify your account",      r"confirm your identity",
    r"update your (payment|billing|credit card)",
    r"your account (will be|has been) (suspended|locked|disabled|terminated)",
    r"click here (immediately|now|urgently)",
    r"limited time",             r"act (now|immediately|fast)",
    r"unauthorized (access|login|activity)",
    r"security (alert|warning|breach|notification)",
    r"you (have won|are selected|are a winner)",
    r"congratulations.*prize",   r"claim your reward",
    r"reset your password.*immediately",
    r"your (paypal|amazon|netflix|apple|microsoft|google|bank).*account",
    r"invoice.*attached",        r"payment.*required",
    r"irs.*refund",              r"tax.*return.*pending",
]

# ── Credential Harvesting Phrases ────────────────────────────────────────────
CREDENTIAL_PHRASES = [
    r"enter your (password|username|email|ssn|social security)",
    r"provide your (card number|account number|pin)",
    r"login to (verify|confirm|update)",
    r"sign in to (your account|continue)",
    r"click.*link.*below.*to (reset|verify|confirm)",
]

# ── Dangerous Attachment Extensions ──────────────────────────────────────────
DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".scr", ".vbs", ".js", ".jse",
    ".wsf", ".hta", ".ps1", ".psm1", ".psd1",              # Scripts
    ".docm", ".xlsm", ".pptm", ".dotm",                    # Macro-enabled Office
    ".iso", ".img", ".lnk",                                 # Container / shortcut
    ".jar", ".class",                                       # Java
    ".apk",                                                  # Android
}

# ── Legitimate domains to check typosquatting against ────────────────────────
POPULAR_DOMAINS = [
    "paypal.com", "amazon.com", "microsoft.com", "google.com",
    "apple.com", "netflix.com", "facebook.com", "instagram.com",
    "linkedin.com", "twitter.com", "bankofamerica.com", "chase.com",
    "wellsfargo.com", "citibank.com", "irs.gov", "dropbox.com",
    "outlook.com", "office.com", "adobe.com", "zoom.us",
]

# ── Free email providers (often spoofed as corporate) ────────────────────────
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "yandex.com", "mail.com",
}

# ── URL shorteners (used to hide phishing URLs) ───────────────────────────────
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "short.link", "tiny.cc", "rebrand.ly", "cutt.ly", "tr.im",
}

# ── SMTP ports ────────────────────────────────────────────────────────────────
SMTP_PORTS = {25, 587, 465, 2525}


class PhishingDetector:
    """
    Dual-mode phishing detector:
      - analyze_packet(features)  : from network packet metadata
      - analyze_email(raw_email)  : from captured SMTP payload string
    """

    def __init__(self):
        self._email_counts: dict[str, list] = defaultdict(list)
        self._compiled_urgency     = [re.compile(p, re.I) for p in URGENCY_PHRASES]
        self._compiled_credential  = [re.compile(p, re.I) for p in CREDENTIAL_PHRASES]

    # ── Mode 1: Packet-level analysis ─────────────────────────────────────────
    def analyze_packet(self, features: dict) -> tuple[bool, str, float, str]:
        """
        Light-weight analysis on packet metadata alone (no payload).
        Returns (is_phishing, attack_type, confidence, detail)
        """
        dport = features.get("dst_port", 0)
        sport = features.get("src_port", 0)
        src   = features.get("src_ip",   "?")
        size  = features.get("pkt_size", 0)

        # Only care about SMTP traffic
        if dport not in SMTP_PORTS and sport not in SMTP_PORTS:
            return False, "", 0.0, ""

        now = time.time()
        self._email_counts[src].append(now)

        # Prune old entries
        self._email_counts[src] = [
            t for t in self._email_counts[src]
            if now - t < 60
        ]

        # Email flood = spam/phishing campaign
        count_1min = len(self._email_counts[src])
        if count_1min > 20:
            return (True,
                    "Email Spam/Phishing Campaign",
                    0.88,
                    f"{src} sent {count_1min} emails in 60s — "
                    f"mass phishing campaign detected")

        # Unusually large SMTP packet (could be malicious attachment)
        if size > 50000:
            return (True,
                    "Suspicious Email Attachment",
                    0.65,
                    f"Large SMTP packet ({size}B) from {src} — "
                    f"possible dangerous attachment")

        return False, "", 0.0, ""

    # ── Mode 2: Full email content analysis ───────────────────────────────────
    def analyze_email(self, raw_email: str,
                      sender_ip: str = "") -> tuple[bool, str, float, list]:
        """
        Deep analysis on captured/provided raw email text.
        Returns (is_phishing, attack_type, confidence 0-1, findings list)
        """
        findings = []
        score    = 0.0

        # --- Header analysis
        from_addr  = self._extract_field(raw_email, "From")
        reply_to   = self._extract_field(raw_email, "Reply-To")
        subject    = self._extract_field(raw_email, "Subject")
        spf        = self._extract_field(raw_email, "Received-SPF")
        dkim       = self._extract_field(raw_email, "DKIM-Signature")
        auth_res   = self._extract_field(raw_email, "Authentication-Results")

        # SPF / DKIM failure
        if spf and "fail" in spf.lower():
            findings.append("SPF FAIL — sender IP not authorized for domain")
            score += 0.30
        if auth_res and "dkim=fail" in auth_res.lower():
            findings.append("DKIM FAIL — email signature invalid (possible spoofing)")
            score += 0.25
        if not dkim:
            findings.append("No DKIM signature — unauthenticated email")
            score += 0.10

        # Reply-To mismatch
        if from_addr and reply_to:
            from_domain  = self._extract_domain(from_addr)
            reply_domain = self._extract_domain(reply_to)
            if from_domain and reply_domain and from_domain != reply_domain:
                findings.append(
                    f"Reply-To domain mismatch: From={from_domain} "
                    f"but Reply-To={reply_domain}")
                score += 0.35

        # Free email provider pretending to be corporate
        if from_addr:
            from_domain = self._extract_domain(from_addr)
            if from_domain in FREE_EMAIL_PROVIDERS:
                # Check if subject/body pretends to be a company
                body_lower = raw_email.lower()
                for domain in POPULAR_DOMAINS:
                    brand = domain.split(".")[0]
                    if brand in body_lower and brand not in from_domain:
                        findings.append(
                            f"Free email ({from_domain}) impersonating '{brand}'")
                        score += 0.40
                        break

        # --- Subject analysis
        if subject:
            for phrase in ["urgent", "action required", "verify", "suspended",
                           "winner", "prize", "refund", "invoice"]:
                if phrase in subject.lower():
                    findings.append(
                        f"Suspicious subject keyword: '{phrase}'")
                    score += 0.10
                    break

        # --- Body analysis
        body = self._extract_body(raw_email)

        # Urgency phrases
        urgency_hits = []
        for pattern in self._compiled_urgency:
            m = pattern.search(body)
            if m:
                urgency_hits.append(m.group(0)[:60])
        if urgency_hits:
            findings.append(
                f"Urgency/manipulation language detected: "
                f"{urgency_hits[0]!r}")
            score += min(0.30, len(urgency_hits) * 0.08)

        # Credential harvesting
        for pattern in self._compiled_credential:
            m = pattern.search(body)
            if m:
                findings.append(
                    f"Credential harvesting phrase: {m.group(0)!r}")
                score += 0.35
                break

        # --- URL analysis
        urls = self._extract_urls(body)
        for url in urls:
            url_result = self._analyze_url(url)
            if url_result:
                findings.append(url_result)
                score += 0.25

        # --- Attachment analysis
        attachment_result = self._check_attachments(raw_email)
        if attachment_result:
            findings.append(attachment_result)
            score += 0.40

        # --- Typosquatting check (From domain vs popular domains)
        if from_addr:
            from_domain = self._extract_domain(from_addr)
            typo_result = self._check_typosquat(from_domain)
            if typo_result:
                findings.append(typo_result)
                score += 0.45

        confidence = min(score, 1.0)
        is_phishing = confidence >= 0.40

        attack_type = ""
        if is_phishing:
            if score >= 0.70:
                attack_type = "High-Confidence Phishing"
            elif score >= 0.40:
                attack_type = "Suspected Phishing"

        return is_phishing, attack_type, round(confidence, 2), findings

    # ── URL Analysis ──────────────────────────────────────────────────────────
    def _analyze_url(self, url: str) -> str:
        try:
            parsed = urllib.parse.urlparse(url)
            host   = parsed.netloc.lower()

            # URL shortener
            if any(s in host for s in URL_SHORTENERS):
                return f"URL shortener detected ({host}) — destination hidden"

            # IP address as host (no domain name)
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                return f"IP-address URL ({host}) — avoiding domain detection"

            # Homograph / punycode (internationalized domain abuse)
            if "xn--" in host:
                return f"Punycode/homograph domain: {host}"

            # Subdomain stuffing (e.g. paypal.com.evil.ru)
            for trusted in POPULAR_DOMAINS:
                t_base = trusted.split(".")[0]
                if t_base in host and not host.endswith(trusted):
                    return (f"Subdomain-stuffed URL: {host} "
                            f"mimics {trusted}")

            # Typosquatting in URL domain
            typo = self._check_typosquat(host)
            if typo:
                return typo

            # Redirect parameters
            if "redirect" in url.lower() or "url=" in url.lower():
                return f"Open redirect parameter in URL: {url[:80]}"

        except Exception:
            pass
        return ""

    # ── Attachment Check ──────────────────────────────────────────────────────
    def _check_attachments(self, email_text: str) -> str:
        # Find Content-Disposition: attachment; filename=... headers
        matches = re.findall(
            r'filename=["\']?([^"\'\s;]+)',
            email_text, re.I)
        for fname in matches:
            ext = "." + fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
            if ext in DANGEROUS_EXTENSIONS:
                return (f"Dangerous attachment: {fname!r} "
                        f"(extension {ext} can execute malware)")
        return ""

    # ── Typosquatting ─────────────────────────────────────────────────────────
    def _check_typosquat(self, domain: str) -> str:
        if not domain:
            return ""
        # Strip subdomains
        parts = domain.split(".")
        if len(parts) >= 2:
            domain = ".".join(parts[-2:])
        for legit in POPULAR_DOMAINS:
            if domain == legit:
                return ""
            similarity = SequenceMatcher(None, domain, legit).ratio()
            if 0.75 <= similarity < 1.0:
                return (f"Typosquatting: {domain!r} looks like {legit!r} "
                        f"(similarity {similarity:.0%})")
        return ""

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _extract_field(text: str, field: str) -> str:
        m = re.search(
            rf"^{re.escape(field)}:\s*(.+)$",
            text, re.I | re.M)
        return m.group(1).strip() if m else ""

    @staticmethod
    def _extract_domain(address: str) -> str:
        m = re.search(r"@([\w.\-]+)", address)
        return m.group(1).lower() if m else ""

    @staticmethod
    def _extract_body(raw_email: str) -> str:
        # Simple split on blank line between headers and body
        parts = re.split(r"\n\n", raw_email, maxsplit=1)
        return parts[1] if len(parts) > 1 else raw_email

    @staticmethod
    def _extract_urls(text: str) -> list:
        return re.findall(
            r"https?://[^\s\"'<>]+",
            text, re.I)

    def get_summary(self, findings: list, confidence: float) -> str:
        if not findings:
            return "No phishing indicators found."
        lines = [f"Confidence: {confidence:.0%}", "Findings:"]
        for f in findings:
            lines.append(f"  • {f}")
        return "\n".join(lines)
