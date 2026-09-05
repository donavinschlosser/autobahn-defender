"""
Autobahn Defender - System Hardening Advisor
Checks system configuration and provides tailored security recommendations.
"""

import os
import subprocess
import sys
import shutil
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal


class HardeningCheckWorker(QThread):
    """Background worker that audits system hardening status."""

    finished = pyqtSignal(dict)

    def run(self):
        # Thread guard: an exception escaping QThread.run hard-closes the
        # process in PyQt6 (see scanner.ScanWorker.run).
        try:
            self._run_inner()
        except Exception as e:  # noqa: BLE001
            try:
                self.finished.emit({"error": f"Hardening check crashed: {e}"})
            except Exception:
                pass

    def _run_inner(self):
        findings = {
            "distro": self._detect_distro(),
            "checks": [],
        }
        checks = [
            self._check_root_ssh,
            self._check_auto_updates,
            self._check_apparmor_selinux,
            self._check_firewall,
            self._check_password_shadow,
            self._check_suid_bins,
            self._check_world_writable,
            self._check_umask,
            self._check_shared_memory,
            self._check_ipv6,
        ]

        # Add distro-specific checks
        distro_id = findings["distro"].get("id", "").lower()
        if "arch" in distro_id or distro_id in ("cachyos", "garuda", "manjaro", "endeavouros"):
            checks.append(self._check_aur_warnings)
        elif "debian" in distro_id or distro_id in ("ubuntu", "linuxmint", "pop", "zorin"):
            checks.append(self._check_debian_security)

        for check_fn in checks:
            try:
                result = check_fn()
                if result:
                    findings["checks"].append(result)
            except Exception as e:
                findings["checks"].append({
                    "name": check_fn.__name__,
                    "status": "error",
                    "description": f"Check failed: {e}",
                    "recommendation": "Manual review recommended",
                    "severity": "info",
                })

        self.finished.emit(findings)

    def _detect_distro(self):
        """Detect Linux distribution."""
        distro = {"id": "unknown", "name": "Unknown", "family": "unknown"}
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("ID="):
                        distro["id"] = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("NAME="):
                        distro["name"] = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("ID_LIKE="):
                        distro["family"] = line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        return distro

    def _check_root_ssh(self):
        """Check if root SSH login is disabled."""
        sshd_config = Path("/etc/ssh/sshd_config")
        sshd_config_d = Path("/etc/ssh/sshd_config.d")
        root_login_disabled = False

        if sshd_config.exists():
            try:
                content = sshd_config.read_text().lower()
                if "permitrootlogin no" in content:
                    root_login_disabled = True
            except OSError:
                pass

        # Check drop-in configs
        if sshd_config_d.exists():
            for f in sshd_config_d.iterdir():
                if f.is_file() and f.suffix == ".conf":
                    try:
                        if "permitrootlogin no" in f.read_text().lower():
                            root_login_disabled = True
                    except OSError:
                        pass

        if root_login_disabled:
            return {
                "name": "Root SSH Login",
                "status": "pass",
                "description": "Root SSH login is disabled",
                "recommendation": "No action needed",
                "severity": "info",
            }

        # Also check for PermitRootLogin prohibit-password (default on many systems)
        try:
            with open("/etc/ssh/sshd_config") as f:
                for line in f:
                    stripped = line.strip().lower()
                    if stripped.startswith("permitrootlogin") and "prohibit-password" in stripped:
                        return {
                            "name": "Root SSH Login",
                            "status": "pass",
                            "description": "Root SSH login is restricted to key-based auth (prohibit-password)",
                            "recommendation": "No action needed",
                            "severity": "info",
                        }
        except OSError:
            pass
        return {
            "name": "Root SSH Login",
            "status": "warn",
            "description": "Root SSH login may be enabled",
            "recommendation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
            "severity": "high",
        }

    def _check_auto_updates(self):
        """Check if automatic updates are configured."""
        has_unattended = Path("/etc/apt/apt.conf.d/50unattended-upgrades").exists()
        has_pacman_hook = False
        try:
            hooks_dir = Path("/etc/pacman.d/hooks")
            has_pacman_hook = hooks_dir.exists() and any(hooks_dir.iterdir())
        except (PermissionError, OSError):
            pass
        has_dnf_automatic = Path("/etc/dnf/automatic.conf").exists()

        if has_unattended or has_pacman_hook or has_dnf_automatic:
            return {
                "name": "Automatic Updates",
                "status": "pass",
                "description": "Automatic updates appear to be configured",
                "recommendation": "No action needed",
                "severity": "info",
            }
        return {
            "name": "Automatic Updates",
            "status": "warn",
            "description": "No automatic update configuration found",
            "recommendation": "Install and configure unattended-upgrades (Debian) or set up a pacman hook (Arch)",
            "severity": "medium",
        }

    def _check_apparmor_selinux(self):
        """Check if AppArmor or SELinux is active."""
        apparmor_enabled = False
        selinux_enabled = False

        # Check AppArmor
        if Path("/sys/kernel/security/apparmor").exists():
            apparmor_enabled = True
        if shutil.which("aa-status"):
            try:
                proc = subprocess.run(["aa-status"], capture_output=True, text=True, timeout=5)
                if proc.returncode == 0 and "profiles" in proc.stdout:
                    apparmor_enabled = True
            except Exception:
                pass

        # Check SELinux
        selinux_path = Path("/etc/selinux/config")
        if selinux_path.exists():
            try:
                content = selinux_path.read_text()
                if "SELINUX=enforcing" in content or "SELINUX=permissive" in content:
                    selinux_enabled = True
            except OSError:
                pass

        if apparmor_enabled or selinux_enabled:
            which = "AppArmor" if apparmor_enabled else "SELinux"
            return {
                "name": "MAC Security (AppArmor/SELinux)",
                "status": "pass",
                "description": f"{which} is active",
                "recommendation": "No action needed",
                "severity": "info",
            }
        return {
            "name": "MAC Security (AppArmor/SELinux)",
            "status": "warn",
            "description": "Neither AppArmor nor SELinux appears to be active",
            "recommendation": "Enable AppArmor: sudo apt install apparmor (Debian) or sudo pacman -S apparmor (Arch)",
            "severity": "high",
        }

    def _check_firewall(self):
        """Check if a firewall is active."""
        # Check UFW
        if shutil.which("ufw"):
            try:
                proc = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=10)
                if "Status: active" in proc.stdout:
                    return {
                        "name": "Firewall",
                        "status": "pass",
                        "description": "UFW firewall is active",
                        "recommendation": "No action needed",
                        "severity": "info",
                    }
            except Exception:
                pass

        # Check firewalld
        if shutil.which("firewall-cmd"):
            try:
                proc = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True, timeout=10)
                if "running" in proc.stdout:
                    return {
                        "name": "Firewall",
                        "status": "pass",
                        "description": "firewalld is running",
                        "recommendation": "No action needed",
                        "severity": "info",
                    }
            except Exception:
                pass

        # Check iptables
        if shutil.which("iptables"):
            try:
                proc = subprocess.run(
                    ["iptables", "-L"],
                    capture_output=True, text=True, timeout=10,
                    env={"PATH": os.environ.get("PATH", "")},
                )
                if proc.returncode == 0 and ("DROP" in proc.stdout or "REJECT" in proc.stdout):
                    return {
                        "name": "Firewall",
                        "status": "pass",
                        "description": "iptables firewall rules detected",
                        "recommendation": "Consider switching to UFW or firewalld for easier management",
                        "severity": "info",
                    }
            except Exception:
                pass

        return {
            "name": "Firewall",
            "status": "warn",
            "description": "No active firewall detected",
            "recommendation": "Enable a firewall: sudo ufw enable (Debian) or sudo systemctl start firewalld (Arch)",
            "severity": "high",
        }

    def _check_password_shadow(self):
        """Check if /etc/passwd has shadow passwords (no plaintext passwords)."""
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 2 and parts[1] not in ("x", "*", "!"):
                        return {
                            "name": "Password Security",
                            "status": "warn",
                            "description": f"User '{parts[0]}' may have a plaintext password in /etc/passwd",
                            "recommendation": "Run 'sudo pwconv' to migrate passwords to /etc/shadow",
                            "severity": "high",
                        }
        except OSError:
            pass

        return {
            "name": "Password Security",
            "status": "pass",
            "description": "Passwords are stored in /etc/shadow",
            "recommendation": "No action needed",
            "severity": "info",
        }

    def _check_suid_bins(self):
        """Check for unusual SUID binaries."""
        unusual = []
        known_suid = {
            "sudo", "su", "passwd", "ping", "mount", "umount",
            "chsh", "chfn", "gpasswd", "newgrp", "pkexec",
            "Xorg", "strace", "ltrace", "fusermount", "fusermount3",
            "pam_extrausers_chkpwd", "unix_chkpwd", "chage",
        }
        try:
            # Increased timeout for large systems, with graceful failure
            proc = subprocess.run(
                ["find", "/usr/bin", "/usr/sbin", "/usr/local/bin", "-perm", "-4000", "-type", "f"],
                capture_output=True, text=True, timeout=60,  # Extended to 60s
            )
            if proc.returncode == 0:
                for line in proc.stdout.strip().split("\n"):
                    if line:
                        name = Path(line).name
                        if name not in known_suid:
                            unusual.append(line)
            else:
                # Handle errors gracefully - return safe warning
                return {
                    "name": "SUID Binaries",
                    "status": "warn",
                    "description": "Could not scan SUID binaries (insufficient permissions)",
                    "recommendation": "Run check manually with elevated privileges",
                    "severity": "info",
                }
        except subprocess.TimeoutExpired:
            return {
                "name": "SUID Binaries",
                "status": "warn",
                "description": "SUID scan timed out (system may have slow storage)",
                "recommendation": "Scan manually or increase timeout",
                "severity": "low",
            }

        if unusual:
            return {
                "name": "SUID Binaries",
                "status": "warn",
                "description": f"Found {len(unusual)} unusual SUID binary(ies): {', '.join(Path(p).name for p in unusual[:5])}",
                "recommendation": "Review unusual SUID binaries and remove unnecessary ones with 'sudo chmod -s <path>'",
                "severity": "medium",
            }
        return {
            "name": "SUID Binaries",
            "status": "pass",
            "description": "No unusual SUID binaries found",
            "recommendation": "No action needed",
            "severity": "info",
        }

    def _check_world_writable(self):
        """Check for world-writable files in system directories."""
        count = 0
        try:
            # Extended timeout for large systems
            proc = subprocess.run(
                ["find", "/etc", "-perm", "-o+w", "-type", "f"],
                capture_output=True, text=True, timeout=60,
            )
            if proc.returncode == 0:
                count = len([l for l in proc.stdout.strip().split("\n") if l.strip()])
            else:
                # Handle errors gracefully - return safe warning
                return {
                    "name": "World-Writable Config Files",
                    "status": "warn",
                    "description": "Could not check world-writable files (insufficient permissions)",
                    "recommendation": "Run check manually with elevated privileges",
                    "severity": "info",
                }
        except subprocess.TimeoutExpired:
            return {
                "name": "World-Writable Config Files",
                "status": "warn",
                "description": "World-writable scan timed out (system may have slow storage)",
                "recommendation": "Scan manually or increase timeout",
                "severity": "low",
            }
        except Exception:
            pass

        if count > 0:
            return {
                "name": "World-Writable Config Files",
                "status": "warn",
                "description": f"Found {count} world-writable file(s) in /etc",
                "recommendation": "Review and fix: sudo find /etc -perm -o+w -type f -exec chmod o-w {} \\;",
                "severity": "medium",
            }
        return {
            "name": "World-Writable Config Files",
            "status": "pass",
            "description": "No world-writable files found in /etc",
            "recommendation": "No action needed",
            "severity": "info",
        }

    def _check_umask(self):
        """Check if default umask is restrictive."""
        umask_val = "022"
        try:
            with open("/etc/profile") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith("umask"):
                        parts = stripped.split()
                        if len(parts) >= 2:
                            umask_val = parts[1]
        except OSError:
            pass

        # 027 or more restrictive is good; 022 is acceptable; 002 or less is bad
        if umask_val in ("077", "027", "026", "007"):
            return {
                "name": "Default Umask",
                "status": "pass",
                "description": f"Default umask is {umask_val} (restrictive)",
                "recommendation": "No action needed",
                "severity": "info",
            }
        if umask_val == "022":
            return {
                "name": "Default Umask",
                "status": "warn",
                "description": f"Default umask is {umask_val} (permissive)",
                "recommendation": "Consider setting umask to 027 in /etc/profile for better security",
                "severity": "low",
            }
        return {
            "name": "Default Umask",
            "status": "warn",
            "description": f"Default umask is {umask_val} (too permissive)",
            "recommendation": "Set umask to 027 or 077 in /etc/profile",
            "severity": "medium",
        }

    def _check_shared_memory(self):
        """Check if /dev/shm is mounted with nodev, nosuid, noexec."""
        secure = False
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    if "/dev/shm" in line and "nodev" in line and "nosuid" in line and "noexec" in line:
                        secure = True
                        break
        except OSError:
            pass

        if secure:
            return {
                "name": "Shared Memory Security",
                "status": "pass",
                "description": "/dev/shm is mounted with nodev, nosuid, noexec",
                "recommendation": "No action needed",
                "severity": "info",
            }
        return {
            "name": "Shared Memory Security",
            "status": "warn",
            "description": "/dev/shm may not have all security mount options",
            "recommendation": "Add to /etc/fstab: tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0",
            "severity": "medium",
        }

    def _check_ipv6(self):
        """Check if IPv6 is disabled when not needed."""
        ipv6_disabled = False
        try:
            proc = subprocess.run(
                ["sysctl", "net.ipv6.conf.all.disable_ipv6"],
                capture_output=True, text=True, timeout=5,
            )
            if "1" in proc.stdout:
                ipv6_disabled = True
        except Exception:
            pass

        if ipv6_disabled:
            return {
                "name": "IPv6",
                "status": "pass",
                "description": "IPv6 is disabled",
                "recommendation": "No action needed",
                "severity": "info",
            }
        return {
            "name": "IPv6",
            "status": "warn",
            "description": "IPv6 is enabled",
            "recommendation": "If not needed, disable IPv6: net.ipv6.conf.all.disable_ipv6 = 1 in /etc/sysctl.d/99-sysctl.conf",
            "severity": "low",
        }

    def _check_aur_warnings(self):
        """Arch-specific: warn about AUR packages."""
        aur_count = 0
        pacman_foreign = 0
        try:
            # Count foreign (manually installed/AUR) packages
            proc = subprocess.run(
                ["pacman", "-Qm"], capture_output=True, text=True, timeout=10,
            )
            if proc.returncode == 0:
                aur_count = len(proc.stdout.strip().split("\n")) if proc.stdout.strip() else 0
                pacman_foreign = aur_count
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        if pacman_foreign > 0:
            return {
                "name": "AUR / Foreign Packages",
                "status": "warn",
                "description": f"{pacman_foreign} foreign/AUR package(s) installed — review regularly for updates",
                "recommendation": "Review AUR packages regularly: pacman -Qm. Consider using an AUR helper with review capabilities.",
                "severity": "low",
            }
        return {
            "name": "AUR / Foreign Packages",
            "status": "pass",
            "description": "No AUR/foreign packages detected",
            "recommendation": "No action needed",
            "severity": "info",
        }

    def _check_debian_security(self):
        """Debian-specific: check if security repo is enabled."""
        security_enabled = False
        sources = [Path("/etc/apt/sources.list")]
        sources.extend(Path("/etc/apt/sources.list.d").glob("*.list"))

        for src in sources:
            try:
                if src.exists():
                    content = src.read_text().lower()
                    if "security" in content and "debian" in content:
                        security_enabled = True
                        break
            except OSError:
                continue

        if security_enabled:
            return {
                "name": "Debian Security Repo",
                "status": "pass",
                "description": "Debian security repository is enabled",
                "recommendation": "No action needed",
                "severity": "info",
            }
        return {
            "name": "Debian Security Repo",
            "status": "warn",
            "description": "Debian security repository may not be enabled",
            "recommendation": "Enable the security repo in /etc/apt/sources.list: deb http://security.debian.org/debian-security bookworm-security main",
            "severity": "medium",
        }