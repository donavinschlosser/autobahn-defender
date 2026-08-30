"""
Autobahn Defender — Startup manager.

Adapted from Kudu startup.ts + startup-manager.ipc.ts (MIT license).
Lists and manages systemd user services, XDG autostart entries, and
@reboot cron entries. Provides enable/disable/toggle with path validation.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

AUTOSTART_DIR = Path.home() / ".config" / "autostart"


def list_autostart() -> list[dict[str, Any]]:
    """List XDG autostart entries."""
    entries = []
    if not AUTOSTART_DIR.exists():
        return entries
    for f in sorted(AUTOSTART_DIR.glob("*.desktop*")):
        try:
            content = f.read_text(errors="replace")
            name = f.stem
            exec_cmd = ""
            hidden = False
            for line in content.splitlines():
                if line.startswith("Name="):
                    name = line[5:]
                elif line.startswith("Exec="):
                    exec_cmd = line[5:]
                elif line.startswith("Hidden="):
                    hidden = line[7:].lower() == "true"
            is_disabled = f.suffix == ".disabled" or hidden
            entries.append({
                "name": name,
                "exec": exec_cmd,
                "source": "autostart-desktop",
                "location": str(f),
                "enabled": not is_disabled,
                "filename": f.name,
            })
        except Exception:
            continue
    return entries


def list_systemd_user_services() -> list[dict[str, Any]]:
    """List systemd user services and their enable state."""
    entries = []
    try:
        r = subprocess.run(
            ["systemctl", "--user", "list-unit-files", "--type=service",
             "--no-pager", "--plain"],
            capture_output=True, text=True, timeout=10,
        )
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if not line or line.startswith("UNIT FILE") or "unit files listed" in line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0].endswith(".service"):
                unit = parts[0]
                state = parts[1]
                entries.append({
                    "name": unit,
                    "displayName": unit.replace(".service", ""),
                    "source": "systemd-user",
                    "enabled": state == "enabled",
                    "state": state,
                })
    except Exception as e:
        log.debug("systemd user services list failed: %s", e)
    return entries


def list_cron_reboot() -> list[dict[str, Any]]:
    """List @reboot cron entries."""
    entries = []
    try:
        r = subprocess.run(
            ["crontab", "-l"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if line.startswith("@reboot"):
                    cmd = line[len("@reboot"):].strip()
                    entries.append({
                        "name": cmd[:60],
                        "exec": cmd,
                        "source": "cron-reboot",
                        "enabled": True,
                    })
    except Exception:
        pass
    return entries


def list_all() -> dict[str, Any]:
    """List all startup items from all sources."""
    return {
        "autostart": list_autostart(),
        "systemd_user": list_systemd_user_services(),
        "cron_reboot": list_cron_reboot(),
    }


def toggle_autostart(filename: str, enable: bool) -> dict[str, Any]:
    """Enable or disable an XDG autostart entry by renaming .desktop/.disabled."""
    # Validate the path is within the autostart directory
    target = AUTOSTART_DIR / filename
    try:
        resolved = target.resolve()
        if not str(resolved).startswith(str(AUTOSTART_DIR.resolve())):
            return {"success": False, "error": "Path traversal blocked"}
    except Exception:
        return {"success": False, "error": "Invalid path"}

    if enable:
        # Remove .disabled suffix
        if filename.endswith(".disabled"):
            new_name = filename[:-len(".disabled")]
            new_target = AUTOSTART_DIR / new_name
            try:
                target.rename(new_target)
                return {"success": True, "action": "enabled", "filename": new_name}
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {"success": True, "action": "already_enabled"}
    else:
        # Add .disabled suffix
        if not filename.endswith(".disabled"):
            new_name = filename + ".disabled"
            new_target = AUTOSTART_DIR / new_name
            try:
                target.rename(new_target)
                return {"success": True, "action": "disabled", "filename": new_name}
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {"success": True, "action": "already_disabled"}


def toggle_systemd_user_service(service: str, enable: bool) -> dict[str, Any]:
    """Enable or disable a systemd user service."""
    # Validate service name
    if not re.match(r'^[a-zA-Z0-9@\-.]+\.service$', service):
        return {"success": False, "error": "Invalid service name"}

    action = "enable" if enable else "disable"
    try:
        r = subprocess.run(
            ["systemctl", "--user", action, service],
            capture_output=True, text=True, timeout=10,
        )
        return {
            "success": r.returncode == 0,
            "exit_code": r.returncode,
            "stdout": r.stdout,
            "stderr": r.stderr,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}