# firewall.py
# Automatically blocks malicious IPs using Windows Firewall
# Think of it like a security guard who permanently bans bad visitors

import subprocess
import threading
import os

# Keep track of already blocked IPs so we don't block twice
_blocked_ips = set()
_lock        = threading.Lock()

# File to save all blocked IPs permanently
BLOCKED_FILE = "blocked_ips.txt"


def _load_blocked():
    """Load previously blocked IPs from file on startup."""
    if os.path.exists(BLOCKED_FILE):
        with open(BLOCKED_FILE, "r") as f:
            for line in f:
                ip = line.strip()
                if ip:
                    _blocked_ips.add(ip)


def _save_blocked(ip):
    """Save newly blocked IP to file."""
    with open(BLOCKED_FILE, "a") as f:
        f.write(ip + "\n")


def is_blocked(ip: str) -> bool:
    """Check if an IP is already blocked."""
    return ip in _blocked_ips


def block_ip(ip: str, reason: str = "") -> tuple:
    """
    Block an IP address using Windows Firewall.
    Returns (success: bool, message: str)

    This runs the Windows netsh command which adds a
    firewall rule to DROP all traffic from that IP.
    """
    # Skip private/local IPs — never block your own network!
    if _is_private(ip):
        return False, f"Skipped {ip} — private/local IP"

    with _lock:
        # Already blocked — skip
        if ip in _blocked_ips:
            return False, f"{ip} already blocked"

        try:
            rule_name = f"BLOCKED_ATTACKER_{ip}"

            # Windows Firewall command to block inbound traffic from IP
            cmd_in = [
                "netsh", "advfirewall", "firewall",
                "add", "rule",
                f"name={rule_name}_IN",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
                "description=Auto-blocked by Network Anomaly Detector"
            ]

            # Windows Firewall command to block outbound traffic to IP
            cmd_out = [
                "netsh", "advfirewall", "firewall",
                "add", "rule",
                f"name={rule_name}_OUT",
                "dir=out",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
                "description=Auto-blocked by Network Anomaly Detector"
            ]

            # Run both commands
            r1 = subprocess.run(cmd_in,  capture_output=True,
                                text=True, timeout=10)
            r2 = subprocess.run(cmd_out, capture_output=True,
                                text=True, timeout=10)

            if r1.returncode == 0 and r2.returncode == 0:
                _blocked_ips.add(ip)
                _save_blocked(ip)
                msg = (f"BLOCKED: {ip}"
                       f"{' — ' + reason if reason else ''}")
                return True, msg
            else:
                err = r1.stderr or r2.stderr
                return False, f"Failed to block {ip}: {err}"

        except subprocess.TimeoutExpired:
            return False, f"Timeout blocking {ip}"
        except Exception as e:
            return False, f"Error blocking {ip}: {e}"


def unblock_ip(ip: str) -> tuple:
    """
    Remove firewall block for an IP address.
    Returns (success: bool, message: str)
    """
    try:
        rule_name = f"BLOCKED_ATTACKER_{ip}"

        cmd_in = [
            "netsh", "advfirewall", "firewall",
            "delete", "rule",
            f"name={rule_name}_IN"
        ]
        cmd_out = [
            "netsh", "advfirewall", "firewall",
            "delete", "rule",
            f"name={rule_name}_OUT"
        ]

        subprocess.run(cmd_in,  capture_output=True,
                       text=True, timeout=10)
        subprocess.run(cmd_out, capture_output=True,
                       text=True, timeout=10)

        with _lock:
            _blocked_ips.discard(ip)

        # Remove from file
        if os.path.exists(BLOCKED_FILE):
            with open(BLOCKED_FILE, "r") as f:
                lines = f.readlines()
            with open(BLOCKED_FILE, "w") as f:
                for line in lines:
                    if line.strip() != ip:
                        f.write(line)

        return True, f"UNBLOCKED: {ip}"

    except Exception as e:
        return False, f"Error unblocking {ip}: {e}"


def get_all_blocked() -> list:
    """Return list of all currently blocked IPs."""
    return list(_blocked_ips)


def _is_private(ip: str) -> bool:
    """Never block private/local network IPs."""
    return ip.startswith((
        "192.168.", "10.", "172.16.", "172.17.",
        "172.18.", "172.19.", "172.20.", "172.21.",
        "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "127.", "0.",
        "224.", "239.", "169.254."
    ))


# Load previously blocked IPs when module loads
_load_blocked()