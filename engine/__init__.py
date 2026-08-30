"""
Autobahn Defender v2.0 — Security Engine (No-AI Rework)

Replaces the v2.0 AI module (Ollama/LFM2.5 sidecar) with a deterministic,
local security engine that runs without any AI model. All checks run as
plain Python functions; the advisor produces the same [SEVERITY]-tagged
reports the AI used to generate, but with zero inference latency and zero
RAM overhead.

Submodules:
  versions       — Debian/Ubuntu version parsing and comparison
  cve_filter     — CVE false-positive filter (adapted from Kudu, MIT)
  cve            — OSV.dev batch CVE query + filter integration
  patches        — Patch-availability tracker + "did the update fix it" verification
  checks         — Deterministic local security checks (ported from ai/tools.py)
  advisor        — Runbook engine: ordered checks, scoring, report rendering
  alerts         — Security alert model and JSONL storage
  state          — System state digest + intelligence database (JSONL)
  apply          — pkexec-gated hardening/firewall/AppArmor/service actions
  network_watch  — Live connection monitoring + IP/CIDR blacklist matching
  privacy        — Privacy shield: gsettings + sysctl hardening checks/apply
  startup        — Startup manager: systemd user services + XDG autostart + cron
  persistence    — Persistence scan (crontab + systemd) + hosts-file integrity
  knowledge_map  — Static remediation reference (from ai/knowledge_base.py)

Contact: XMPP digitalautobahn@xmpp.brax.me
"""

from __future__ import annotations

import os
from pathlib import Path

APP_VERSION = "2.0.0"

# Data directory for engine state (intel DBs, alerts, patches, blacklist)
DATA_DIR = Path(os.environ.get(
    "XDG_DATA_HOME",
    os.path.expanduser("~/.local/share/autobahn-defender"),
))
INTEL_DIR = DATA_DIR / "intel"
REPORTS_DIR = DATA_DIR / "reports"
BLACKLIST_DIR = DATA_DIR / "blacklist"

# Subdirectory names
PATCHES_FILE = "patches.jsonl"
ACTIONS_LOG = "actions.log"
BLACKLIST_FILE = "threat-blacklist.json"

# Contact
CONTACT_XMPP = "digitalautobahn@xmpp.brax.me"


def ensure_dirs() -> None:
    """Create data directories with secure permissions (0o700)."""
    for d in (INTEL_DIR, REPORTS_DIR, BLACKLIST_DIR):
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(d), 0o700)
        except OSError:
            pass