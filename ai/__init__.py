"""
Autobahn Defender — RSS feed support module.

This package is kept for the Security News tab and RSS feed polling.
The old AI module (ollama_manager, worker, tools) has been removed.
Only rss_feeds.py and intel_db.py remain here.

Data directory for intelligence JSONL files.
"""
from __future__ import annotations

import os
from pathlib import Path

# Data directory for intelligence JSONL files.
# A-8 fix: join the app dir onto XDG_DATA_HOME rather than using it verbatim.
_DATA_ROOT = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
AI_DATA_DIR = Path(_DATA_ROOT) / "autobahn-defender"
INTEL_DIR = AI_DATA_DIR / "intel"

APP_VERSION = "2.0.2"
