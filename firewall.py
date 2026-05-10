"""
Autobahn Defender - Firewall Integration
Manages UFW (Debian-based) and firewalld (Arch/Fedora) firewalls.
"""

import subprocess
import shutil
from PyQt6.QtCore import QThread, pyqtSignal


def detect_firewall():
    """Detect which firewall system is available. Returns 'ufw', 'firewalld', or None."""
    if shutil.which("ufw"):
        return "ufw"
    if shutil.which("firewall-cmd"):
        return "firewalld"
    return None


def get_firewall_status():
    """Return dict with firewall type and status info."""
    fw_type = detect_firewall()
    if not fw_type:
        return {"type": None, "active": False, "error": "No firewall tool found"}

    if fw_type == "ufw":
        return _get_ufw_status()
    elif fw_type == "firewalld":
        return _get_firewalld_status()
    return {"type": fw_type, "active": False, "error": "Unknown firewall type"}


def _get_ufw_status():
    """Get UFW status."""
    try:
        proc = subprocess.run(
            ["ufw", "status"], capture_output=True, text=True, timeout=10,
        )
        output = proc.stdout + proc.stderr
        active = "Status: active" in output
        rules = []
        for line in output.split("\n"):
            line = line.strip()
            if line and not line.startswith("Status:") and not line.startswith("To") and not line.startswith("---"):
                rules.append(line)
        return {"type": "ufw", "active": active, "rules": rules, "raw": output.strip()}
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"type": "ufw", "active": False, "error": str(e)}


def _get_firewalld_status():
    """Get firewalld status."""
    try:
        proc = subprocess.run(
            ["firewall-cmd", "--state"], capture_output=True, text=True, timeout=10,
        )
        active = "running" in proc.stdout.lower()
        # Get default zone rules
        rules = []
        proc2 = subprocess.run(
            ["firewall-cmd", "--list-all"], capture_output=True, text=True, timeout=10,
        )
        return {
            "type": "firewalld",
            "active": active,
            "rules": [proc2.stdout.strip()],
            "raw": proc2.stdout.strip(),
        }
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"type": "firewalld", "active": False, "error": str(e)}


class FirewallApplyWorker(QThread):
    """Apply recommended firewall rules in a background thread."""

    finished = pyqtSignal(bool, str)

    def __init__(self, fw_type=None):
        super().__init__()
        self.fw_type = fw_type or detect_firewall()

    def run(self):
        if not self.fw_type:
            self.finished.emit(False, "No firewall tool found")
            return

        if self.fw_type == "ufw":
            self._apply_ufw()
        elif self.fw_type == "firewalld":
            self._apply_firewalld()
        else:
            self.finished.emit(False, f"Unsupported firewall: {self.fw_type}")

    def _apply_ufw(self):
        """Apply recommended UFW rules: deny inbound, allow SSH + loopback."""
        cmds = [
            ["ufw", "default", "deny", "incoming"],
            ["ufw", "default", "allow", "outgoing"],
            ["ufw", "allow", "ssh"],
            ["ufw", "allow", "in", "on", "lo"],
            ["ufw", "--force", "enable"],
        ]
        results = []
        for cmd in cmds:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                output = proc.stdout.strip() or proc.stderr.strip()
                if proc.returncode != 0 and cmd[1] != "--force":
                    results.append(f"$ {' '.join(cmd)}\nFAILED: {output}")
                    self.finished.emit(False, "\n".join(results))
                    return
                results.append(f"$ {' '.join(cmd)}\n{output}")
            except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                results.append(f"$ {' '.join(cmd)}\nError: {e}")
                self.finished.emit(False, "\n".join(results))
                return
        self.finished.emit(True, "\n".join(results))

    def _apply_firewalld(self):
        """Apply recommended firewalld rules."""
        # Ensure SSH is allowed before setting zone to drop
        cmds = [
            ["firewall-cmd", "--permanent", "--add-service=ssh"],
            ["firewall-cmd", "--permanent", "--add-interface=lo"],
            ["firewall-cmd", "--set-default-zone=drop"],
            ["firewall-cmd", "--reload"],
        ]
        results = []
        for cmd in cmds:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                output = proc.stdout.strip() or proc.stderr.strip()
                if proc.returncode != 0:
                    results.append(f"$ {' '.join(cmd)}\nFAILED: {output}")
                    self.finished.emit(False, "\n".join(results))
                    return
                results.append(f"$ {' '.join(cmd)}\n{output}")
            except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                results.append(f"$ {' '.join(cmd)}\nError: {e}")
                self.finished.emit(False, "\n".join(results))
                return
        self.finished.emit(True, "\n".join(results))