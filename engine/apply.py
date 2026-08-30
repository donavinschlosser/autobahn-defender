"""
Autobahn Defender — Privileged action executor (pkexec wrapper).

All hardening/firewall/AppArmor/service actions go through here.
Safety rules:
  - NO shell interpolation — every command is a list (argv-based)
  - Every action requires explicit user confirmation (review-first dialog)
  - Every action is logged to actions.log (append-only, 0600)
  - Rollback information is recorded for every action
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import DATA_DIR

log = logging.getLogger(__name__)

ACTIONS_LOG = DATA_DIR / "actions.log"

# SSH hardening drop-in (audit B-2 fix). Ubuntu/Mint sshd_config Includes
# sshd_config.d/*.conf at the TOP, so drop-in settings are global scope (no
# Match-block trap), survive openssh-server upgrades, and revert = delete file.
SSH_DROPIN_DIR = Path("/etc/ssh/sshd_config.d")
SSH_DROPIN_PATH = SSH_DROPIN_DIR / "60-autobahn-hardening.conf"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log_action(action: str, command, result: dict[str, Any],
                rollback: str = "") -> None:
    """Append to the actions audit log."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        if isinstance(command, (list, tuple)):
            command_str = " ".join(str(c) for c in command)
        else:
            command_str = str(command)
        entry = (
            f"[{_now_iso()}] ACTION: {action}\n"
            f"  CMD: {command_str}\n"
            f"  RESULT: {'success' if result.get('success') else 'failed'}\n"
            f"  ROLLBACK: {rollback}\n\n"
        )
        with open(ACTIONS_LOG, "a") as f:
            f.write(entry)
        os.chmod(str(ACTIONS_LOG), 0o600)
    except Exception as e:
        log.error("Failed to write action log: %s", e)


def run_privileged(argv: list[str], timeout: int = 60) -> dict[str, Any]:
    """Run a command with elevated privileges via pkexec (sudo fallback).

    Args:
        argv: command as a list (no shell interpolation, ever)
        timeout: max seconds to wait

    Returns:
        {"success": bool, "exit_code": int, "stdout": str, "stderr": str}
    """
    if not argv or not isinstance(argv[0], str):
        return {"success": False, "error": "Invalid command"}

    if Path("/usr/bin/pkexec").exists():
        full_cmd = ["pkexec"] + argv
    elif Path("/usr/bin/sudo").exists():
        full_cmd = ["sudo"] + argv
    else:
        return {"success": False,
                "error": "No privilege escalation tool found (pkexec/sudo)"}

    try:
        r = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "success": r.returncode == 0,
            "exit_code": r.returncode,
            "stdout": r.stdout or "",
            "stderr": r.stderr or "",
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Command timed out after {timeout}s"}
    except FileNotFoundError as e:
        return {"success": False, "error": f"Command not found: {e}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Action definitions — each returns a dict; every action is logged w/ rollback
# ---------------------------------------------------------------------------

def apparmor_enforce(profile_path: str = "/etc/apparmor.d/*") -> dict[str, Any]:
    """Set AppArmor profiles to enforce mode."""
    if not profile_path.startswith("/etc/apparmor.d/"):
        return {"success": False, "error": "Invalid profile path"}

    cmd = ["aa-enforce", profile_path]
    result = run_privileged(cmd)
    _log_action("apparmor_enforce", cmd, result,
                rollback=f"aa-complain {profile_path}")
    return result


def firewall_enable() -> dict[str, Any]:
    """Enable UFW."""
    cmd = ["ufw", "enable"]
    result = run_privileged(cmd)
    _log_action("firewall_enable", cmd, result, rollback="ufw disable")
    return result


def firewall_disable() -> dict[str, Any]:
    """Disable UFW."""
    cmd = ["ufw", "disable"]
    result = run_privileged(cmd)
    _log_action("firewall_disable", cmd, result, rollback="ufw enable")
    return result


def firewall_allow_port(port: str, proto: str = "tcp") -> dict[str, Any]:
    """Allow a port through UFW."""
    if not port.replace("/", "").isalnum():
        return {"success": False, "error": "Invalid port"}
    if proto not in ("tcp", "udp"):
        return {"success": False, "error": "Invalid protocol"}
    cmd = ["ufw", "allow", f"{port}/{proto}"]
    result = run_privileged(cmd)
    _log_action("firewall_allow_port", cmd, result,
                rollback=f"ufw delete allow {port}/{proto}")
    return result


def firewall_deny_port(port: str, proto: str = "tcp") -> dict[str, Any]:
    """Deny a port through UFW."""
    if not port.replace("/", "").isalnum():
        return {"success": False, "error": "Invalid port"}
    if proto not in ("tcp", "udp"):
        return {"success": False, "error": "Invalid protocol"}
    cmd = ["ufw", "deny", f"{port}/{proto}"]
    result = run_privileged(cmd)
    _log_action("firewall_deny_port", cmd, result,
                rollback=f"ufw delete deny {port}/{proto}")
    return result


# Sysctl hardening set (adapted from Kudu privacy.ts, MIT)
SYSCTL_HARDENING = {
    "kernel.randomize_va_space": "2",
    "kernel.kptr_restrict": "2",
    "kernel.dmesg_restrict": "1",
    "kernel.yama.ptrace_scope": "1",
    "kernel.unprivileged_bpf_disabled": "1",
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.all.log_martians": "1",
    "net.ipv6.conf.all.accept_redirects": "0",
    "fs.suid_dumpable": "0",
}


def sysctl_harden() -> dict[str, Any]:
    """Apply all 13 sysctl hardening settings and persist to /etc/sysctl.d/.

    Audit C-2 fix: 14 separate pkexec invocations (1 conf copy + 13 sysctl -w)
    collapsed to 2 (write conf, then one `sysctl --system`).
    """
    results = []
    conf_path = "/etc/sysctl.d/99-autobahn.conf"

    conf_content = (
        "# Autobahn Defender security hardening settings\n"
        "# Remove this file and run 'sysctl --system' to revert\n"
        "# Applied: " + _now_iso() + "\n\n"
    )
    for key, value in SYSCTL_HARDENING.items():
        conf_content += f"{key} = {value}\n"

    fd, tmp_path = tempfile.mkstemp(suffix=".conf")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(conf_content)
        os.chmod(tmp_path, 0o644)
        result = run_privileged(["cp", tmp_path, conf_path], timeout=10)
        results.append({"action": "write_config", "result": result})
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    if results and results[0].get("result", {}).get("success"):
        reload_result = run_privileged(["sysctl", "--system"], timeout=30)
        results.append({"action": "sysctl_reload", "result": reload_result})
        success = bool(reload_result.get("success"))
    else:
        results.append({"action": "sysctl --system", "result": {
            "success": False, "error": "config write failed — sysctl not applied"}})
        success = False

    _log_action("sysctl_harden", ["sysctl_harden (13 settings persisted)"],
                {"success": success},
                rollback=f"rm {conf_path} && sysctl --system")
    return {"success": success, "details": results}


def ssh_harden() -> dict[str, Any]:
    """Harden SSH via a drop-in in /etc/ssh/sshd_config.d/ (audit B-2 fix).

    Global scope (Include at the top of sshd_config), survives upgrades,
    untouched original config, trivial revert (rm the drop-in). Validates
    with sshd -t; removes the drop-in if validation fails.
    """
    sshd_config = Path("/etc/ssh/sshd_config")
    if not sshd_config.exists():
        return {"success": False, "error": "No sshd_config found (openssh-server not installed)"}

    content = (
        "# Autobahn Defender SSH hardening (safe to delete to revert)\n"
        f"# Applied: {_now_iso()}\n"
        "PermitRootLogin no\n"
        "PasswordAuthentication no\n"
        "MaxAuthTries 3\n"
        "ClientAliveInterval 300\n"
        "ClientAliveCountMax 2\n"
    )

    fd, tmp_path = tempfile.mkstemp(suffix=".conf")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.chmod(tmp_path, 0o644)

        # Ensure the drop-in dir exists (root-owned)
        run_privileged(["mkdir", "-p", str(SSH_DROPIN_DIR)], timeout=10)
        # Install the drop-in
        result = run_privileged(["cp", tmp_path, str(SSH_DROPIN_PATH)], timeout=10)
        if not result.get("success"):
            _log_action("ssh_harden", [f"write {SSH_DROPIN_PATH}"], result,
                        rollback="(nothing to roll back — write failed)")
            return result

        # Validate
        validate = run_privileged(["sshd", "-t"], timeout=15)
        if not validate.get("success"):
            # Rollback: remove our drop-in; original sshd_config never touched
            run_privileged(["rm", "-f", str(SSH_DROPIN_PATH)], timeout=5)
            _log_action("ssh_harden", ["sshd drop-in"],
                        {"success": False, "error": "sshd -t failed, drop-in removed"},
                        rollback="drop-in removed; sshd_config untouched")
            return {"success": False,
                    "error": f"SSH config validation failed: {validate.get('stderr', '')}"}

        # Reload (unit name differs across distros: ssh on Debian/Ubuntu, sshd elsewhere)
        reload_r = run_privileged(["systemctl", "reload", "ssh"], timeout=15)
        if not reload_r.get("success"):
            reload_r = run_privileged(["systemctl", "reload", "sshd"], timeout=15)

        _log_action("ssh_harden", [f"write {SSH_DROPIN_PATH}"], {"success": True},
                    rollback=f"rm {SSH_DROPIN_PATH} && systemctl reload ssh")
        return {
            "success": True,
            "changes": {
                "PermitRootLogin": "no", "PasswordAuthentication": "no",
                "MaxAuthTries": "3", "ClientAliveInterval": "300",
                "ClientAliveCountMax": "2",
            },
            "drop_in": str(SSH_DROPIN_PATH),
        }
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def service_action(service: str, action: str) -> dict[str, Any]:
    """Start/stop/enable/disable/mask/unmask a systemd service.

    Only whitelisted services are allowed for safety.
    """
    ALLOWED_SERVICES = {
        "fail2ban", "ufw", "clamav-daemon", "clamav-freshclam",
        "apparmor", "auditd",
    }
    ALLOWED_ACTIONS = {"start", "stop", "enable", "disable", "restart", "reload",
                       "mask", "unmask"}

    if service not in ALLOWED_SERVICES:
        return {"success": False, "error": f"Service '{service}' is not in the allowed list"}
    if action not in ALLOWED_ACTIONS:
        return {"success": False, "error": f"Action '{action}' is not allowed"}

    cmd = ["systemctl", action, service]
    result = run_privileged(cmd, timeout=15)
    rollback = f"systemctl {('unmask' if action == 'mask' else 'mask') if action in ('mask', 'unmask') else ('start' if action == 'stop' else 'stop')} {service}"
    _log_action(f"service_{action}", cmd, result, rollback=rollback)
    return result


def apt_upgrade_security() -> dict[str, Any]:
    """Run apt-get update + upgrade (privileged, review-first upstream)."""
    update_result = run_privileged(["apt-get", "update"], timeout=300)
    if not update_result.get("success"):
        return update_result
    result = run_privileged(["apt-get", "upgrade", "-y"], timeout=600)
    _log_action("apt_upgrade_security", ["apt-get upgrade -y"], result,
                rollback="Manual rollback required (apt-get install <pkg>=<old_ver>)")
    return result


def apt_upgrade_package(package: str) -> dict[str, Any]:
    """Upgrade a single package (to fix a tracked CVE)."""
    if not re.match(r'^[a-z0-9][a-z0-9+.\-]+$', package):
        return {"success": False, "error": "Invalid package name"}
    result = run_privileged(["apt-get", "install", "-y", package], timeout=300)
    _log_action("apt_upgrade_package", ["apt-get install -y", package], result,
                rollback=f"apt-get install {package}=<old_version>")
    return result


def apply_batch(packages: list[str]) -> dict[str, Any]:
    """Upgrade several packages, aggregating results (engine-level: both the
    GUI worker (B-7) and CLI 'patches --yes' call this single implementation).
    """
    results = []
    applied = 0
    for pkg in packages:
        r = apt_upgrade_package(pkg)
        ok = bool(r.get("success"))
        results.append({"package": pkg, "success": ok,
                        "error": r.get("error") or r.get("stderr", "")[:200]})
        if ok:
            applied += 1
    return {
        "requested": len(packages),
        "applied": applied,
        "failed": len(packages) - applied,
        "results": results,
        "success": applied == len(packages),
    }


def get_action_log(limit: int = 50) -> list[str]:
    """Read the action log (last N entries)."""
    if not ACTIONS_LOG.exists():
        return []
    try:
        lines = ACTIONS_LOG.read_text().splitlines()
        return lines[-limit:]
    except Exception:
        return []