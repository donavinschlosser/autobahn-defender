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
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import DATA_DIR

log = logging.getLogger(__name__)

ACTIONS_LOG = DATA_DIR / "actions.log"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log_action(action: str, command: list[str], result: dict[str, Any],
                rollback: str = "") -> None:
    """Append to the actions audit log."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        entry = (
            f"[{_now_iso()}] ACTION: {action}\n"
            f"  CMD: {' '.join(command)}\n"
            f"  RESULT: {'success' if result.get('success') else 'failed'}\n"
            f"  ROLLBACK: {rollback}\n\n"
        )
        with open(ACTIONS_LOG, "a") as f:
            f.write(entry)
        os.chmod(str(ACTIONS_LOG), 0o600)
    except Exception as e:
        log.error("Failed to write action log: %s", e)


def run_privileged(argv: list[str], timeout: int = 60) -> dict[str, Any]:
    """Run a command with elevated privileges via pkexec.

    Args:
        argv: command as a list (no shell interpolation, ever)
        timeout: max seconds to wait

    Returns:
        {"success": bool, "exit_code": int, "stdout": str, "stderr": str}
    """
    if not argv or not isinstance(argv[0], str):
        return {"success": False, "error": "Invalid command"}

    # Use pkexec for privilege escalation (GUI password prompt)
    # Fall back to sudo if pkexec is not available
    if Path("/usr/bin/pkexec").exists():
        full_cmd = ["pkexec"] + argv
    elif Path("/usr/bin/sudo").exists():
        full_cmd = ["sudo"] + argv
    else:
        return {"success": False, "error": "No privilege escalation tool found (pkexec/sudo)"}

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
# Action definitions — each returns a description + executes via run_privileged
# ---------------------------------------------------------------------------

def apparmor_enforce(profile_path: str = "/etc/apparmor.d/*") -> dict[str, Any]:
    """Set AppArmor profiles to enforce mode."""
    # Validate path is within /etc/apparmor.d/
    if not profile_path.startswith("/etc/apparmor.d/"):
        return {"success": False, "error": "Invalid profile path"}

    cmd = ["aa-enforce", profile_path]
    result = run_privileged(cmd)
    _log_action("apparmor_enforce", cmd, result,
                rollback=f"aa-complain {profile_path}")
    return result


def firewall_enable() -> dict[str, Any]:
    """Enable UFW with default deny incoming."""
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
    # Validate port is numeric or a known service name
    if not port.replace("/", "").isalnum():
        return {"success": False, "error": "Invalid port"}
    cmd = ["ufw", "allow", f"{port}/{proto}"]
    result = run_privileged(cmd)
    _log_action("firewall_allow_port", cmd, result,
                rollback=f"ufw delete allow {port}/{proto}")
    return result


def firewall_deny_port(port: str, proto: str = "tcp") -> dict[str, Any]:
    """Deny a port through UFW."""
    if not port.replace("/", "").isalnum():
        return {"success": False, "error": "Invalid port"}
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
    """Apply all 13 sysctl hardening settings and persist to /etc/sysctl.d/."""
    results = []
    conf_path = "/etc/sysctl.d/99-autobahn.conf"

    # Build the config file content
    conf_content = (
        "# Autobahn Defender security hardening settings\n"
        "# Remove this file and run 'sysctl --system' to revert\n"
        "# Applied: " + _now_iso() + "\n\n"
    )
    for key, value in SYSCTL_HARDENING.items():
        conf_content += f"{key} = {value}\n"

    # Write the config file via pkexec
    # Use a temp file + pkexec mv to avoid shell injection
    fd, tmp_path = tempfile.mkstemp(suffix=".conf")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(conf_content)
        result = run_privileged(["cp", tmp_path, conf_path], timeout=10)
        results.append({"action": "write_config", "result": result})
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    # Apply each sysctl setting
    for key, value in SYSCTL_HARDENING.items():
        result = run_privileged(["sysctl", "-w", f"{key}={value}"], timeout=5)
        results.append({"setting": key, "value": value, "result": result})

    success = all(r.get("result", {}).get("success") for r in results)
    _log_action("sysctl_harden", ["sysctl_harden (13 settings)"],
                {"success": success},
                rollback=f"rm {conf_path} && sysctl --system")
    return {"success": success, "details": results}


def ssh_harden() -> dict[str, Any]:
    """Harden SSH configuration: disable root login, disable password auth."""
    sshd_config = Path("/etc/ssh/sshd_config")
    if not sshd_config.exists():
        return {"success": False, "error": "No sshd_config found"}

    # Read current config
    try:
        content = sshd_config.read_text()
    except Exception as e:
        return {"success": False, "error": f"Cannot read sshd_config: {e}"}

    # Apply hardening changes
    changes = {
        "PermitRootLogin": "no",
        "PasswordAuthentication": "no",
        "MaxAuthTries": "3",
        "ClientAliveInterval": "300",
        "ClientAliveCountMax": "2",
    }

    new_lines = []
    for line in content.splitlines():
        stripped = line.strip()
        changed = False
        for key, value in changes.items():
            if stripped.startswith(f"{key} ") or stripped.startswith(f"#{key} "):
                new_lines.append(f"{key} {value}")
                changed = True
                break
        if not changed:
            new_lines.append(line)

    # Add any missing settings at the end
    for key, value in changes.items():
        if not any(l.strip().startswith(f"{key} ") for l in new_lines):
            new_lines.append(f"{key} {value}")

    new_content = "\n".join(new_lines) + "\n"

    # Write via temp file + pkexec
    fd, tmp_path = tempfile.mkstemp(suffix=".sshd_config")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(new_content)

        # Backup original
        run_privileged(["cp", str(sshd_config), f"{sshd_config}.autobahn-bak"], timeout=5)
        # Write new config
        result = run_privileged(["cp", tmp_path, str(sshd_config)], timeout=5)

        if result.get("success"):
            # Validate config with sshd -t before reloading
            validate = run_privileged(["sshd", "-t"], timeout=10)
            if not validate.get("success"):
                # Rollback on validation failure
                run_privileged(["cp", f"{sshd_config}.autobahn-bak", str(sshd_config)], timeout=5)
                _log_action("ssh_harden", ["sshd_config edit"],
                            {"success": False, "error": "sshd -t failed, rolled back"},
                            rollback="restored from .autobahn-bak")
                return {"success": False, "error": f"SSH config validation failed: {validate.get('stderr', '')}"}

            # Reload SSH
            reload = run_privileged(["systemctl", "reload", "sshd"], timeout=10)
            _log_action("ssh_harden", ["sshd_config edit"],
                        {"success": True},
                        rollback=f"cp {sshd_config}.autobahn-bak {sshd_config} && systemctl reload sshd")
            return {"success": True, "changes": changes}
        else:
            return result
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def service_action(service: str, action: str) -> dict[str, Any]:
    """Start/stop/enable/disable a systemd service.

    Only whitelisted services are allowed for safety.
    """
    ALLOWED_SERVICES = {
        "fail2ban", "ufw", "clamav-daemon", "clamav-freshclam",
        "apparmor", "auditd",
    }
    ALLOWED_ACTIONS = {"start", "stop", "enable", "disable", "restart", "reload"}

    if service not in ALLOWED_SERVICES:
        return {"success": False, "error": f"Service '{service}' is not in the allowed list"}
    if action not in ALLOWED_ACTIONS:
        return {"success": False, "error": f"Action '{action}' is not allowed"}

    cmd = ["systemctl", action, service]
    result = run_privileged(cmd, timeout=15)
    rollback = f"systemctl {('start' if action == 'stop' else 'stop')} {service}"
    _log_action(f"service_{action}", cmd, result, rollback=rollback)
    return result


def apt_upgrade_security() -> dict[str, Any]:
    """Run apt-get upgrade (security updates)."""
    # First update package lists
    update_result = run_privileged(["apt-get", "update"], timeout=120)
    if not update_result.get("success"):
        return update_result

    # Then upgrade
    result = run_privileged(["apt-get", "upgrade", "-y"], timeout=600)
    _log_action("apt_upgrade_security", ["apt-get upgrade -y"], result,
                rollback="Manual rollback required (apt-get install <pkg>=<old_ver>)")
    return result


def apt_upgrade_package(package: str) -> dict[str, Any]:
    """Upgrade a single package to fix a CVE."""
    # Validate package name (alphanumeric + dashes)
    import re
    if not re.match(r'^[a-z0-9][a-z0-9+\-.]+$', package):
        return {"success": False, "error": "Invalid package name"}

    result = run_privileged(["apt-get", "install", "-y", package], timeout=120)
    _log_action("apt_upgrade_package", ["apt-get install -y", package], result,
                rollback=f"apt-get install {package}=<old_version>")
    return result


def get_action_log(limit: int = 50) -> list[str]:
    """Read the action log (last N entries)."""
    if not ACTIONS_LOG.exists():
        return []
    try:
        lines = ACTIONS_LOG.read_text().splitlines()
        return lines[-limit:]
    except Exception:
        return []