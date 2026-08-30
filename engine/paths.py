"""Neutral path constants — importable headless (no Qt, no scanner import).

audit 2026-08-31 F-6: engine/checks.py used to `from scanner import RULES_DIR`,
dragging PyQt6 + quarantine into every headless import. All shared app paths
live here now; scanner.py keeps its own aliases for backward compatibility.
"""
from __future__ import annotations

import os
from pathlib import Path

# App data (~/.autobahn — scanner definitions, rules, quarantine, history DB)
APP_DIR = Path.home() / ".autobahn"
RULES_DIR = APP_DIR / "rules"
DEFS_DIR = APP_DIR / "definitions"
QUARANTINE_DIR = APP_DIR / "quarantine"
HISTORY_DB = APP_DIR / "history.db"

# Machine-readable intel data root. Fixed per audit A-8: the previous code
# used $XDG_DATA_HOME *verbatim* (dropping the app subdir) when the env var
# was set, dumping state into the shared XDG root.
_XDG_DATA_ROOT = os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))
DATA_DIR = Path(_XDG_DATA_ROOT) / "autobahn-defender"
INTEL_DIR = DATA_DIR / "intel"
REPORTS_DIR = DATA_DIR / "reports"
BLACKLIST_DIR = DATA_DIR / "blacklist"