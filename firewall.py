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
        # Get default zone rules - parse the output into structured rules
        rules = []
        proc2 = subprocess.run(
            ["firewall-cmd", "--list-all"], capture_output=True, text=True, timeout=10,
        )
        output = proc2.stdout.strip()
        if output:
            # Parse thefirewall-cmd --list-all output into structured rules
            # Format: "zone: public (active)\n  services: ssh ...\n  ports: ...\n  interfaces: ..."
            for line in output.split("\n"):
                line = line.strip()
                if line and not line.startswith("zone:") and not line.startswith(" "):
                    # It's a zone declaration - extract zone name
                    zone_match = line.replace("(", "").replace(")", "").split()
                    if zone_match:
                        rules.append(f"Zone: {zone_match[0]}")
                elif line.startswith("services:"):
                    services = line.replace("services:", "").strip()
                    if services:
                        rules.append(f"Services: {services}")
                elif line.startswith("ports:"):
                    ports = line.replace("ports:", "").strip()
                    if ports:
                        rules.append(f"Ports: {ports}")
                elif line.startswith("interfaces:"):
                    interfaces = line.replace("interfaces:", "").strip()
                    if interfaces:
                        rules.append(f"Interfaces: {interfaces}")
        return {
            "type": "firewalld",
            "active": active,
            "rules": rules,
            "raw": output,
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
        # Thread guard: an exception escaping QThread.run hard-closes the
        # process in PyQt6 (see scanner.ScanWorker.run).
        try:
            self._run_inner()
        except Exception as e:  # noqa: BLE001
            try:
                self.finished.emit(False, f"Firewall apply crashed: {e}")
            except Exception:
                pass

    def _run_inner(self):
        if not self.fw_type:
            self.finished.emit(False, "No firewall tool found")
            return

        if self.fw_type == "ufw":
            self._apply_ufw()
        elif self.fw_type == "firewalld":
            self._apply_firewalld()
        else:
            self.finished.emit(False, f"Unsupported firewall: {self.fw_type}")

    def _run_cmd_with_auth(self, display_cmd, cmd):
        """Run a command with pkexec for root privileges. Fall back to sudo if pkexec missing."""
        # Try pkexec first (GUI password dialog via PolicyKit)
        if shutil.which("pkexec"):
            full_cmd = ["pkexec"] + cmd
        elif shutil.which("sudo"):
            # Use sudo with -A flag for password prompt (SSH_ASKPASS)
            # This works better than -n on systems without passwordless sudo
            full_cmd = ["sudo", "-A"] + cmd
        else:
            raise FileNotFoundError("No privilege escalation tool found (install pkexec or sudo)")

        proc = subprocess.run(full_cmd, capture_output=True, text=True, timeout=60)
        output = proc.stdout.strip() or proc.stderr.strip()
        if proc.returncode != 0:
            # Don't fail on non-zero exit for --force enable (ufw enable returns non-zero in some cases)
            raise subprocess.CalledProcessError(proc.returncode, full_cmd, output=output)
        return f"$ {display_cmd}\n{output}"

    def _apply_ufw(self):
        """Apply recommended UFW rules: deny inbound, allow SSH + loopback."""
        # Each command runs via pkexec so the user gets a GUI password prompt
        commands = [
            (["ufw", "default", "deny", "incoming"], True),
            (["ufw", "default", "allow", "outgoing"], True),
            (["ufw", "allow", "ssh"], True),
            (["ufw", "allow", "in", "on", "lo"], True),
            (["ufw", "--force", "enable"], False),  # --force enable is allowed to fail
        ]
        results = []
        try:
            for display_cmd, strict in commands:
                result_line = self._run_cmd_with_auth(" ".join(display_cmd), display_cmd)
                results.append(result_line)
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            results.append(f"Error: {e}")
            self.finished.emit(False, "\n".join(results))
            return
        except subprocess.CalledProcessError as e:
            failed_cmd = " ".join(e.cmd[1:]) if len(e.cmd) > 1 else " ".join(e.cmd)
            results.append(f"$ {failed_cmd}\nFAILED: {e.output}")
            self.finished.emit(False, "\n".join(results))
            return
        self.finished.emit(True, "\n".join(results))

    def _apply_firewalld(self):
        """Apply recommended firewalld rules via pkexec/sudo."""
        # Each cmd needs root; pkexec pops the GUI password dialog
        commands = [
            (["firewall-cmd", "--permanent", "--add-service=ssh"], True),
            (["firewall-cmd", "--permanent", "--add-interface=lo"], True),
            (["firewall-cmd", "--set-default-zone=drop"], True),
            (["firewall-cmd", "--reload"], True),
        ]
        results = []
        try:
            for display_cmd, strict in commands:
                result_line = self._run_cmd_with_auth(" ".join(display_cmd), display_cmd)
                results.append(result_line)
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            results.append(f"Error: {e}")
            self.finished.emit(False, "\n".join(results))
            return
        except subprocess.CalledProcessError as e:
            failed_cmd = " ".join(e.cmd[1:]) if len(e.cmd) > 1 else " ".join(e.cmd)
            results.append(f"$ {failed_cmd}\nFAILED: {e.output}")
            self.finished.emit(False, "\n".join(results))
            return
        self.finished.emit(True, "\n".join(results))