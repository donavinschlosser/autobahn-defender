"""
Autobahn Defender — Persistence scanner and hosts-file integrity checker.

Standalone versions of the scan_persistence and check_hosts checks
from ai/tools.py, adapted to be callable directly (not just as checks).
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Suspicious patterns for crontab entries
_CRON_SUSPICIOUS = [
    re.compile(r'(curl|wget)\s+.*\|\s*(bash|sh|python)', re.IGNORECASE),
    re.compile(r'/tmp/', re.IGNORECASE),
    re.compile(r'base64\s+-d.*\|', re.IGNORECASE),
    re.compile(r'python.*-c.*import', re.IGNORECASE),
]

# Suspicious patterns for systemd ExecStart
_SYSTEMD_SUSPICIOUS = [
    re.compile(r'/tmp/', re.IGNORECASE),
    re.compile(r'(curl|wget).*\|.*(bash|sh)', re.IGNORECASE),
    re.compile(r'Restart\s*=\s*always', re.IGNORECASE),
    re.compile(r'/\.', re.IGNORECASE),  # hidden dirs
]

# Major domains to check in hosts file (adapted from Kudu, MIT)
_SAFE_IPS = {
    "127.0.0.1", "::1", "0.0.0.0",
}
_CHECK_DOMAINS = {
    "google.com", "www.google.com", "microsoft.com", "www.microsoft.com",
    "github.com", "paypal.com", "www.paypal.com", "apple.com",
    "amazon.com", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "linkedin.com", "netflix.com", "youtube.com",
    "gmail.com", "outlook.com", "yahoo.com", "live.com",
    "dropbox.com", "steam.com", "steampowered.com",
}


def scan_crontab() -> list[dict[str, Any]]:
    """Scan user crontab for suspicious entries."""
    findings = []
    try:
        r = subprocess.run(
            ["crontab", "-l"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return []
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for pattern in _CRON_SUSPICIOUS:
                if pattern.search(line):
                    findings.append({
                        "type": "crontab",
                        "detail": f"Suspicious crontab entry: {line[:200]}",
                        "path": "crontab",
                        "pattern": pattern.pattern,
                    })
                    break
    except Exception as e:
        log.debug("crontab scan failed: %s", e)
    return findings


def scan_systemd_user_services() -> list[dict[str, Any]]:
    """Scan systemd user services for suspicious ExecStart entries."""
    findings = []
    user_services_dir = Path.home() / ".config" / "systemd" / "user"
    if not user_services_dir.exists():
        return findings

    for service_file in user_services_dir.glob("*.service"):
        try:
            content = service_file.read_text(errors="replace")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("ExecStart="):
                    exec_cmd = line[len("ExecStart="):]
                    for pattern in _SYSTEMD_SUSPICIOUS:
                        if pattern.search(exec_cmd):
                            findings.append({
                                "type": "systemd_user",
                                "detail": f"Suspicious ExecStart in {service_file.name}: {exec_cmd[:200]}",
                                "path": str(service_file),
                                "pattern": pattern.pattern,
                            })
                            break
        except Exception:
            continue
    return findings


def scan_persistence() -> dict[str, Any]:
    """Full persistence scan: crontab + systemd user services + autostart."""
    findings = []
    findings.extend(scan_crontab())
    findings.extend(scan_systemd_user_services())

    # Check XDG autostart for suspicious entries
    autostart_dir = Path.home() / ".config" / "autostart"
    if autostart_dir.exists():
        for desktop_file in autostart_dir.glob("*.desktop"):
            try:
                content = desktop_file.read_text(errors="replace")
                for line in content.splitlines():
                    if line.startswith("Exec="):
                        exec_cmd = line[5:]
                        if "/tmp/" in exec_cmd or "curl" in exec_cmd.lower():
                            findings.append({
                                "type": "autostart",
                                "detail": f"Suspicious autostart entry: {desktop_file.name}: {exec_cmd[:200]}",
                                "path": str(desktop_file),
                            })
                            break
            except Exception:
                continue

    return {
        "suspicious_entries": findings,
        "total_found": len(findings),
    }


def check_hosts_file() -> dict[str, Any]:
    """Check /etc/hosts for tampering (redirects of major domains)."""
    hosts_path = Path("/etc/hosts")
    if not hosts_path.exists():
        return {"tampered": False, "redirects": [], "error": "No /etc/hosts found"}

    redirects = []
    try:
        content = hosts_path.read_text(errors="replace")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ip = parts[0]
            domains = parts[1:]
            for domain in domains:
                if domain.lower() in _CHECK_DOMAINS and ip not in _SAFE_IPS:
                    redirects.append({
                        "domain": domain,
                        "ip": ip,
                        "line": line,
                    })
    except Exception as e:
        return {"tampered": False, "redirects": [], "error": str(e)}

    return {
        "tampered": len(redirects) > 0,
        "redirects": redirects,
    }