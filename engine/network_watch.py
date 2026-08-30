"""
Autobahn Defender — Network threat watch (AI-free).

Monitors established network connections against an IP/domain/CIDR
blacklist. Runs on a QTimer (no RAM gate, no AI required).

Connection parsing via `ss -tunap state established`.
CIDR matching with proper IPv4/IPv6 support.
Blacklist download with size caps + atomic replace.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from . import BLACKLIST_DIR, BLACKLIST_FILE

log = logging.getLogger(__name__)

_BLACKLIST_PATH = BLACKLIST_DIR / BLACKLIST_FILE
_MAX_ENTRIES = 500_000
_MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
_DOWNLOAD_TIMEOUT = 60
_DEDUP_TTL = 60  # seconds — don't re-flag the same connection within 60s

# Default blacklist sources (disabled by default — privacy: no cloud sends)
BLACKLIST_SOURCES = {
    "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
}


def parse_ss_output(output: str) -> list[dict[str, Any]]:
    """Parse `ss -tunap state established` output into connection dicts."""
    connections = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("Netid") or line.startswith("State"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            # ss output: Netid Recv-Q Send-Q LocalAddr:Port PeerAddr:Port Process
            # Index:     0     1      2      3            4           5+
            local_addr = parts[3]
            peer_addr = parts[4]
            process = " ".join(parts[5:]) if len(parts) > 5 else ""

            # Parse peer address — extract IP and port
            peer_ip = ""
            peer_port = ""
            if "]:" in peer_addr:  # IPv6
                idx = peer_addr.rfind("]:")
                peer_ip = peer_addr[1:idx]  # strip brackets
                peer_port = peer_addr[idx + 2:]
            elif ":" in peer_addr:  # IPv4
                idx = peer_addr.rfind(":")
                peer_ip = peer_addr[:idx]
                peer_port = peer_addr[idx + 1:]

            # Extract PID/proc from process field
            # Format: users:(("procname",pid=1234,fd=5))
            pid = 0
            proc_name = ""
            if "pid=" in process:
                import re as _re
                pid_match = _re.search(r'pid=(\d+)', process)
                if pid_match:
                    pid = int(pid_match.group(1))
                name_match = _re.search(r'\("([^"]+)"', process)
                if name_match:
                    proc_name = name_match.group(1)

            if peer_ip and peer_ip != "*":
                connections.append({
                    "local_addr": local_addr,
                    "peer_ip": peer_ip,
                    "peer_port": peer_port,
                    "pid": pid,
                    "process": proc_name,
                })
        except Exception:
            continue
    return connections


def get_connections() -> list[dict[str, Any]]:
    """Get established network connections."""
    try:
        r = subprocess.run(
            ["ss", "-tunap", "state", "established"],
            capture_output=True, text=True, timeout=10,
        )
        return parse_ss_output(r.stdout or "")
    except Exception as e:
        log.error("ss command failed: %s", e)
        return []


def load_blacklist() -> dict[str, Any] | None:
    """Load the cached blacklist from disk."""
    if not _BLACKLIST_PATH.exists():
        return None
    try:
        data = json.loads(_BLACKLIST_PATH.read_text())
        return validate_blacklist(data)
    except Exception as e:
        log.error("Failed to load blacklist: %s", e)
        return None


def validate_blacklist(raw: Any) -> dict[str, Any] | None:
    """Validate a blacklist JSON structure.
    Adapted from Kudu threat-blacklist-store.ts (MIT).
    """
    if raw is None or not isinstance(raw, dict):
        return None
    version = raw.get("version")
    updated_at = raw.get("updatedAt")
    if not isinstance(version, str) or not version:
        return None
    if not isinstance(updated_at, str) or not updated_at:
        return None
    for key in ("domains", "ips", "cidrs"):
        arr = raw.get(key)
        if not isinstance(arr, list) or len(arr) > _MAX_ENTRIES:
            return None
        for item in arr:
            if not isinstance(item, str) or len(item) > 500 or not item:
                return None
    return raw


def save_blacklist(bl: dict[str, Any]) -> None:
    """Atomically save blacklist to disk."""
    BLACKLIST_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(BLACKLIST_DIR), 0o700)
    except OSError:
        pass
    fd, tmp_path = tempfile.mkstemp(dir=str(BLACKLIST_DIR), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(bl, f)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, str(_BLACKLIST_PATH))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def download_blacklist(source_url: str) -> dict[str, Any] | None:
    """Download and parse a blacklist from a URL.
    Returns a validated blacklist dict or None on failure.
    """
    try:
        r = requests.get(source_url, timeout=_DOWNLOAD_TIMEOUT,
                         stream=True)
        r.raise_for_status()

        content = b""
        for chunk in r.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > _MAX_DOWNLOAD_BYTES:
                log.warning("Blacklist download exceeded %d bytes, truncating",
                            _MAX_DOWNLOAD_BYTES)
                break

        text = content.decode("utf-8", errors="replace")
        ips = set()
        cidrs = set()

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            # Remove inline comments
            if ";" in line:
                line = line.split(";")[0].strip()
            # Try to parse as IP or CIDR
            try:
                if "/" in line:
                    net = ipaddress.ip_network(line, strict=False)
                    cidrs.add(str(net))
                else:
                    addr = ipaddress.ip_address(line)
                    ips.add(str(addr))
            except ValueError:
                continue

        return {
            "version": str(int(time.time())),
            "updatedAt": datetime.now(timezone.utc).isoformat(),
            "domains": [],
            "ips": sorted(ips)[:_MAX_ENTRIES],
            "cidrs": sorted(cidrs)[:_MAX_ENTRIES],
        }
    except Exception as e:
        log.error("Blacklist download failed: %s", e)
        return None


def match_connection(peer_ip: str, blacklist: dict[str, Any]) -> bool:
    """Check if a peer IP matches any entry in the blacklist."""
    try:
        addr = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False

    # Check exact IP matches
    if peer_ip in blacklist.get("ips", []):
        return True

    # Check CIDR ranges
    for cidr in blacklist.get("cidrs", []):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if addr in net:
                return True
        except ValueError:
            continue

    return False


class NetworkWatch:
    """Network threat monitor — runs on a QTimer, no AI required."""

    _last_alerts: dict[str, float]  # peer_ip -> timestamp (dedup)

    def __init__(self) -> None:
        self._last_alerts = {}
        self._blacklist: dict[str, Any] | None = load_blacklist()

    def refresh_blacklist(self, source_url: str | None = None) -> bool:
        """Download and cache a fresh blacklist."""
        url = source_url or BLACKLIST_SOURCES.get("firehol_level1")
        if not url:
            return False
        bl = download_blacklist(url)
        if bl:
            save_blacklist(bl)
            self._blacklist = bl
            return True
        return False

    def scan(self) -> list[dict[str, Any]]:
        """Scan current connections against the blacklist.
        Returns list of threats found.
        """
        if not self._blacklist:
            return []

        connections = get_connections()
        now = time.time()
        threats = []

        for conn in connections:
            peer_ip = conn.get("peer_ip", "")
            if not peer_ip:
                continue

            # Dedup — don't re-flag within TTL
            last = self._last_alerts.get(peer_ip, 0)
            if now - last < _DEDUP_TTL:
                continue

            if match_connection(peer_ip, self._blacklist):
                self._last_alerts[peer_ip] = now
                severity = "HIGH" if conn.get("pid", 0) == 0 else "MEDIUM"
                threats.append({
                    "ip": peer_ip,
                    "port": conn.get("peer_port", ""),
                    "pid": conn.get("pid", 0),
                    "process": conn.get("process", ""),
                    "severity": severity,
                    "reason": "IP on threat blacklist",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        return threats

    def has_blacklist(self) -> bool:
        return self._blacklist is not None