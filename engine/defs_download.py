"""Self-contained definitions downloader (v2.0.2).

The self-contained AppImage bundles the clamscan ENGINE but not the virus
DEFINITIONS (300MB+ and updated weekly — data, not a dependency). Instead of
depending on a freshclam binary/service, the app fetches the official ClamAV
signature databases directly over HTTPS into the user's data dir
(~/.autobahn/definitions) — no root, no system service.

Files (official database.clamav.net, TLS only):
  main.cvd, daily.cvd, bytecode.cvd

Design:
  - stdlib urllib only (matches the rest of the engine)
  - verify: CVD files start with "ClamAV-VDB:" header — check the magic
    before accepting a download
  - atomic: download to <name>.cvd.part then os.replace
  - UA header identifies the app (same convention as updater.py)
"""
from __future__ import annotations

import os
import urllib.request
from pathlib import Path
from typing import Any

from .paths import DEFS_DIR
from .version import APP_VERSION

_CVD_URLS = {
    "main.cvd": "https://database.clamav.net/main.cvd",
    "daily.cvd": "https://database.clamav.net/daily.cvd",
    "bytecode.cvd": "https://database.clamav.net/bytecode.cvd",
}
_TIMEOUT_S = 120


def _user_agent() -> str:
    return f"AutobahnDefender/{APP_VERSION} (self-contained)"


def defs_status() -> dict[str, Any]:
    """Report which definition files exist locally."""
    out: dict[str, Any] = {"defs_dir": str(DEFS_DIR), "files": {},
                           "complete": True}
    for name in _CVD_URLS:
        p = DEFS_DIR / name
        if p.exists() and p.stat().st_size > 1024:
            out["files"][name] = {"present": True, "size": p.stat().st_size}
        else:
            out["files"][name] = {"present": False}
            out["complete"] = False
    return out


def _download(url: str, dest: Path) -> tuple[bool, str]:
    """Download one CVD atomically with basic integrity checks."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": _user_agent()})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp, \
                open(part, "wb") as f:
            while True:
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                f.write(chunk)
    except Exception as e:  # network errors are operational, not fatal
        try:
            part.unlink()
        except OSError:
            pass
        return False, str(e)
    # Sanity: CVD magic + non-trivial size
    try:
        with open(part, "rb") as f:
            head = f.read(64)
        if not head.startswith(b"ClamAV-VDB:") or part.stat().st_size < 1024:
            part.unlink()
            return False, "downloaded file is not a valid CVD database"
    except OSError as e:
        return False, str(e)
    part.replace(dest)
    return True, ""


def download_all(force: bool = False, progress=None) -> dict[str, Any]:
    """Fetch any missing CVD databases. progress: cb(name, state) or None.

    Idempotent: existing valid files are skipped unless force=True.
    """
    results: dict[str, Any] = {"ok": True, "downloaded": [], "failed": [],
                               "skipped": [], "errors": {}}
    DEFS_DIR.mkdir(parents=True, exist_ok=True)
    for name, url in _CVD_URLS.items():
        dest = DEFS_DIR / name
        if not force and dest.exists() and dest.stat().st_size > 1024:
            results["skipped"].append(name)
            continue
        if progress:
            progress(name, "downloading")
        ok, err = _download(url, dest)
        if ok:
            results["downloaded"].append(name)
            if progress:
                progress(name, "done")
        else:
            results["failed"].append(name)
            results["errors"][name] = err
    if results["failed"]:
        results["ok"] = False
    return results