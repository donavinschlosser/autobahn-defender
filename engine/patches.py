"""
Autobahn Defender — Patch availability tracker.

Tracks open CVEs against installed packages and detects when a fix
is available in the distro repositories. After the user applies an
update, verifies that the installed version actually resolves the CVE.

This is the "did the update fix it" verification loop — fully
deterministic, no AI required.

State file: ~/.local/share/autobahn-defender/intel/patches.jsonl
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import INTEL_DIR
from .versions import is_version_at_least
from .cve import detect_ecosystem, get_installed_packages, query_osv

log = logging.getLogger(__name__)

PATCHES_FILE = INTEL_DIR / "patches.jsonl"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_patches() -> list[dict[str, Any]]:
    """Load all patch tracking entries from JSONL."""
    if not PATCHES_FILE.exists():
        return []
    entries = []
    try:
        for line in PATCHES_FILE.read_text().splitlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    except Exception as e:
        log.error("Failed to load patches: %s", e)
    return entries


def _save_patches(entries: list[dict[str, Any]]) -> None:
    """Atomically save patches to JSONL (tmp + rename)."""
    INTEL_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(INTEL_DIR), 0o700)
    except OSError:
        pass
    fd, tmp_path = tempfile.mkstemp(dir=str(INTEL_DIR), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, str(PATCHES_FILE))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def check_for_fixes() -> dict[str, Any]:
    """Check if fixes are available in the distro repositories for tracked CVEs.

    Runs `apt-get -s upgrade` (simulation, no root needed) to find
    available updates, then cross-references with tracked open CVEs.

    Returns summary of fix availability.
    """
    tracked = _load_patches()
    open_entries = [e for e in tracked if e.get("status") == "open"]

    if not open_entries:
        return {
            "tracked": len(tracked),
            "open": 0,
            "fixes_available": 0,
            "fixes_applied": 0,
            "details": [],
        }

    # Get simulated upgrade list
    available = _simulate_upgrade()
    avail_map: dict[str, str] = {}  # pkg -> new_version
    for pkg_name, new_ver in available:
        avail_map[pkg_name] = new_ver

    updated = []
    fixes_available = 0
    fixes_applied = 0
    details = []

    for entry in open_entries:
        pkg = entry.get("package", "")
        fixed_in = entry.get("fixed_in", "")
        installed = entry.get("installed_version", "")
        cve_id = entry.get("cve_id", "")

        # Check if an update is available
        new_ver = avail_map.get(pkg)
        if new_ver:
            # Is the new version >= fixed_in?
            resolves = False
            if fixed_in:
                try:
                    resolves = is_version_at_least(new_ver, fixed_in)
                except Exception:
                    resolves = False

            if resolves:
                entry["status"] = "fix_available"
                entry["available_version"] = new_ver
                entry["last_checked"] = _now_iso()
                fixes_available += 1
                details.append({
                    "package": pkg,
                    "cve_id": cve_id,
                    "installed": installed,
                    "available": new_ver,
                    "fixed_in": fixed_in,
                    "status": "fix_available",
                    "fix_command": f"sudo apt update && sudo apt upgrade {pkg}",
                })
            else:
                entry["last_checked"] = _now_iso()
        else:
            # Check if the currently installed version already resolves it
            # (user may have updated outside the app)
            if fixed_in and installed:
                try:
                    if is_version_at_least(installed, fixed_in):
                        entry["status"] = "applied"
                        entry["resolved_at"] = _now_iso()
                        entry["verified_version"] = installed
                        fixes_applied += 1
                        details.append({
                            "package": pkg,
                            "cve_id": cve_id,
                            "installed": installed,
                            "fixed_in": fixed_in,
                            "status": "verified_fixed",
                        })
                        continue
                except Exception:
                    pass
            entry["last_checked"] = _now_iso()
        updated.append(entry)

    # Save updated entries
    _save_patches(tracked)
    return {
        "tracked": len(tracked),
        "open": len(open_entries),
        "fixes_available": fixes_available,
        "fixes_applied": fixes_applied,
        "details": details,
    }


def verify_patch_applied(package: str, cve_id: str = "") -> dict[str, Any]:
    """After the user runs an update, verify the installed version fixes the CVE.

    Re-queries OSV for the package and checks if the new installed version
    is >= the fix version. This closes the "did the update fix it" loop.
    """
    ecosystem = detect_ecosystem()
    packages = get_installed_packages()
    pkg_info = next((p for p in packages if p["name"] == package), None)
    if not pkg_info:
        return {"error": f"Package {package} not found in installed packages."}

    installed_ver = pkg_info["version"]

    # Re-query OSV for just this package
    vulns = query_osv([pkg_info], ecosystem)
    target_vulns = [v for v in vulns if not cve_id or v.get("cve_id") == cve_id]

    results = []
    for v in target_vulns:
        fixed_in = v.get("fixed_in", "")
        resolved = False
        if fixed_in:
            try:
                resolved = is_version_at_least(installed_ver, fixed_in)
            except Exception:
                resolved = False

        results.append({
            "cve_id": v.get("cve_id", ""),
            "package": package,
            "installed_version": installed_ver,
            "fixed_in": fixed_in,
            "resolved": resolved,
            "status": "verified_fixed" if resolved else "still_vulnerable",
        })

    # Update tracked entries
    tracked = _load_patches()
    for entry in tracked:
        if entry.get("package") == package and (not cve_id or entry.get("cve_id") == cve_id):
            matching = [r for r in results if r["cve_id"] == entry.get("cve_id")]
            if matching and matching[0]["resolved"]:
                entry["status"] = "applied"
                entry["resolved_at"] = _now_iso()
                entry["verified_version"] = installed_ver
    _save_patches(tracked)

    # Audit 2026-08-31 A-7 fix: empty results used to report all_resolved=True
    # ("verified fixed") even when OSV was unreachable or returned nothing.
    # No data != verified. Only claim 'verified' when we actually got results
    # for the tracked CVEs and they all resolved.
    if not results:
        return {
            "package": package,
            "installed_version": installed_ver,
            "results": [],
            "all_resolved": None,       # None = inconclusive (was: True)
            "status": "inconclusive",
            "note": ("OSV returned no vulnerability data for this package — "
                     "verification is inconclusive (network issue or no data "
                     "published yet). The alert stays OPEN."),
        }

    return {
        "package": package,
        "installed_version": installed_ver,
        "results": results,
        "all_resolved": all(r["resolved"] for r in results),
        "status": "resolved" if all(r["resolved"] for r in results) else "still_vulnerable",
    }


def track_cve(cve_id: str, package: str, installed_version: str,
              fixed_in: str, summary: str = "") -> dict[str, Any]:
    """Add a CVE to the patch tracking list."""
    entry = {
        "cve_id": cve_id,
        "package": package,
        "installed_version": installed_version,
        "fixed_in": fixed_in,
        "summary": summary[:300],
        "status": "open",
        "first_seen": _now_iso(),
        "last_checked": "",
        "resolved_at": "",
        "available_version": "",
        "verified_version": "",
    }
    tracked = _load_patches()
    # Don't duplicate
    existing = any(
        e.get("cve_id") == cve_id and e.get("package") == package
        for e in tracked
    )
    if not existing:
        tracked.append(entry)
        _save_patches(tracked)
    return entry


def get_tracked() -> list[dict[str, Any]]:
    """Get all tracked patch entries."""
    return _load_patches()


def _simulate_upgrade() -> list[tuple[str, str]]:
    """Run apt-get -s upgrade to get available updates (no root needed).

    Returns list of (package_name, new_version) tuples.
    """
    try:
        r = subprocess.run(
            ["apt-get", "-s", "upgrade"],
            capture_output=True, text=True, timeout=30,
        )
        updates = []
        for line in (r.stdout or "").splitlines():
            # Conf python3 (3.12.3-0ubuntu2 [Ubuntu:24.04/...]) ...
            # Inst libssl3t64 [3.0.13-0ubuntu13.1] (3.0.13-0ubuntu13.5 Ubuntu:24.04/...)
            if line.startswith("Inst "):
                # Parse: Inst <pkg> [[old_ver]] (new_ver ...)
                parts = line[5:].split()
                if not parts:
                    continue
                pkg = parts[0]
                # Find the new version in parentheses
                for part in parts:
                    if part.startswith("("):
                        new_ver = part[1:].split()[0]
                        updates.append((pkg, new_ver))
                        break
        return updates
    except Exception as e:
        log.error("apt-get -s upgrade failed: %s", e)
        return []