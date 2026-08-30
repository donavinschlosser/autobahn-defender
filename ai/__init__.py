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

AI_DATA_DIR = Path(os.environ.get(
    "XDG_DATA_HOME",
    os.path.expanduser("~/.local/share/autobahn-defender"),
))
INTEL_DIR = AI_DATA_DIR / "intel"

APP_VERSION = "2.0.0"