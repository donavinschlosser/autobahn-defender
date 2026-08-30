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
  findings       — Finding dataclass + CVSS parsing (P0 unified schema)
  paths          — neutral path constants (headless-importable; no Qt)
  apply          — pkexec-gated hardening/firewall/AppArmor/service actions
  network_watch  — Live connection monitoring + IP/CIDR blacklist matching
  privacy        — Privacy shield: gsettings + sysctl hardening checks/apply
  startup        — Startup manager: systemd user services + XDG autostart + cron
  persistence    — Persistence scan (crontab + systemd) + hosts-file integrity
  intel/         — Threat-intel collectors (KEV, Ubuntu OSV, EPSS, PoC) + matching
  watch/         — Active monitoring (inotify watcher, watch daemon)
  remediate      — Alert→contain→update→verify→restore lifecycle

Contact: XMPP digitalautobahn@xmpp.brax.me
"""
from __future__ import annotations

import os
from pathlib import Path

from .paths import (  # noqa: F401  (re-exported for compatibility)
    APP_DIR,
    BLACKLIST_DIR,
    DATA_DIR,
    DEFS_DIR,
    INTEL_DIR,
    QUARANTINE_DIR,
    REPORTS_DIR,
    RULES_DIR,
)

APP_VERSION = "2.0.0"

# Legacy alias: some checks historically imported AI_DATA_DIR from here.
AI_DATA_DIR = DATA_DIR

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