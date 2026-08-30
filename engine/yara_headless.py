"""Headless YARA rules updater — mirror of yara_updater.py minus Qt.

Same Codeberg source and local state file as the GUI updater, so both
front-ends stay in sync. Downloads atomically (tmp + rename).
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

APP_DIR = Path.home() / ".autobahn"
RULES_DIR = APP_DIR / "rules"
STATE_FILE = APP_DIR / "yara_update_state.json"
VERSION_FILE_STATE = STATE_FILE
RAW_BASE = ("https://codeberg.org/donavinschlosser/autobahn-defender"
            "/raw/branch/main/yara")
VERSION_URL = f"{RAW_BASE}/VERSION"

RULE_FILES_MAP = {
    "linux-rules.yar": "upstream_linux.yar",
    "windows-rules.yar": "upstream_windows.yar",
    "macos-rules.yar": "upstream_macos.yar",
}

# alias used by update_rules
RULE_FILES = RULE_FILES_MAP


def _load_local_version() -> str:
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text())
            if isinstance(data, dict):
                return str(data.get("version", "0"))
        except Exception:
            pass
    return "0"


def get_yara_current_version() -> str:
    return _load_local_version()


def _fetch_bytes(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(
        url, headers={"User-Agent": "AutobahnDefender/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def check_version() -> dict:
    """Read-only: local vs remote YARA VERSION."""
    try:
        remote = _fetch_bytes(VERSION_URL, timeout=30).decode().strip()
        return {"remote": remote or "0", "local": _load_local_version()}
    except Exception as e:
        return {"error": str(e)[:200]}


def update_rules() -> dict:
    """Download every rule file from Codeberg; atomic replace per file."""
    results = []
    ok_count = 0
    for repo_name, local_name in RULE_FILES_MAP.items():
        try:
            data = _fetch_bytes(f"{RAW_BASE}/{repo_name}")
            RULES_DIR.mkdir(parents=True, exist_ok=True)
            dest = RULES_DIR / local_name
            tmp = dest.with_suffix(dest.suffix + ".part")
            tmp.write_bytes(data)
            tmp.replace(dest)
            results.append({"file": repo_name, "installed_as": local_name,
                            "success": True, "bytes": len(data)})
            ok_count += 1
        except Exception as e:
            results.append({"file": repo_name, "success": False,
                            "error": str(e)[:200]})
    return {"success": ok_count > 0, "updated": ok_count,
            "results": results, "version": _load_local_version()}