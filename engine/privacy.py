"""
Autobahn Defender — Privacy shield checks and apply actions.

Adapted from Kudu privacy.ts (MIT license).
GNOME/KDE gsettings + sysctl kernel/network hardening checks.
"""

from __future__ import annotations

import logging
import subprocess
from typing import Any

from .apply import SYSCTL_HARDENING, run_privileged

log = logging.getLogger(__name__)


def _gsettings_get(schema: str, key: str) -> str | None:
    try:
        r = subprocess.run(
            ["gsettings", "get", schema, key],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return None


def _gsettings_set(schema: str, key: str, value: str) -> bool:
    try:
        r = subprocess.run(
            ["gsettings", "set", schema, key, value],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def _sysctl_get(param: str) -> str | None:
    try:
        r = subprocess.run(
            ["sysctl", "-n", param],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return None


# GNOME privacy settings (no root required)
GNOME_PRIVACY_SETTINGS = [
    {
        "id": "gnome-usage-stats",
        "label": "Usage Statistics",
        "description": "Disable GNOME usage statistics collection",
        "schema": "org.gnome.desktop.privacy",
        "key": "send-software-usage-stats",
        "hardened_value": "false",
        "requires_admin": False,
    },
    {
        "id": "gnome-recent-files",
        "label": "Recent Files Tracking",
        "description": "Disable tracking of recently used files",
        "schema": "org.gnome.desktop.privacy",
        "key": "remember-recent-files",
        "hardened_value": "false",
        "requires_admin": False,
    },
    {
        "id": "gnome-location",
        "label": "Location Services",
        "description": "Disable GNOME location services",
        "schema": "org.gnome.system.location",
        "key": "enabled",
        "hardened_value": "false",
        "requires_admin": False,
    },
    {
        "id": "gnome-crash-reporting",
        "label": "Crash Reporting (Apport)",
        "description": "Disable automatic crash report submission",
        "schema": "com.ubuntu.update-notifier",
        "key": "show-apport-crashes",
        "hardened_value": "false",
        "requires_admin": False,
    },
    {
        "id": "gnome-connectivity-check",
        "label": "Connectivity Checking",
        "description": "Disable GNOME connectivity check (stops network probing)",
        "schema": "org.gnome.desktop.privacy",
        "key": "check-network-availability",
        "hardened_value": "false",
        "requires_admin": False,
    },
]


def check_privacy_settings() -> list[dict[str, Any]]:
    """Check all privacy settings and return their current status."""
    results = []
    desktop = subprocess.run(
        ["echo", "$XDG_CURRENT_DESKTOP"],
        capture_output=True, text=True, timeout=2,
    ).stdout.strip().lower()

    # GNOME/Unity settings
    if "gnome" in desktop or "unity" in desktop or "cinnamon" in desktop:
        for setting in GNOME_PRIVACY_SETTINGS:
            current = _gsettings_get(setting["schema"], setting["key"])
            is_hardened = current == setting["hardened_value"]
            results.append({
                **setting,
                "current_value": current,
                "is_hardened": is_hardened,
                "status": "ok" if is_hardened else "needs_attention",
            })

    # Sysctl settings
    for param, hardened_value in SYSCTL_HARDENING.items():
        current = _sysctl_get(param)
        is_hardened = current == hardened_value
        results.append({
            "id": f"sysctl-{param}",
            "label": f"Kernel: {param}",
            "description": f"Set {param} to {hardened_value}",
            "current_value": current,
            "hardened_value": hardened_value,
            "is_hardened": is_hardened,
            "requires_admin": True,
            "status": "ok" if is_hardened else "needs_attention",
        })

    return results


def apply_privacy_setting(setting_id: str) -> dict[str, Any]:
    """Apply a single privacy setting."""
    # Check GNOME settings
    for setting in GNOME_PRIVACY_SETTINGS:
        if setting["id"] == setting_id:
            success = _gsettings_set(
                setting["schema"], setting["key"], setting["hardened_value"]
            )
            return {"success": success, "setting": setting_id}

    # Check sysctl settings
    for param, value in SYSCTL_HARDENING.items():
        if f"sysctl-{param}" == setting_id:
            result = run_privileged(["sysctl", "-w", f"{param}={value}"], timeout=5)
            return {"success": result.get("success", False), "setting": setting_id}

    return {"success": False, "error": f"Unknown setting: {setting_id}"}


def apply_all_privacy() -> dict[str, Any]:
    """Apply all privacy settings (gsettings + sysctl)."""
    results = []

    # GNOME settings (no root needed)
    for setting in GNOME_PRIVACY_SETTINGS:
        success = _gsettings_set(
            setting["schema"], setting["key"], setting["hardened_value"]
        )
        results.append({"setting": setting["id"], "success": success})

    # Sysctl settings (root needed)
    sysctl_result = run_privileged(
        ["sysctl", "-w"] + [f"{k}={v}" for k, v in SYSCTL_HARDENING.items()],
        timeout=30,
    )
    results.append({"setting": "sysctl_batch", "success": sysctl_result.get("success", False)})

    success_count = sum(1 for r in results if r.get("success"))
    return {
        "success": success_count == len(results),
        "applied": success_count,
        "total": len(results),
        "details": results,
    }