"""
Autobahn Defender - Kernel Module Checker
Analyzes loaded kernel modules for suspicious/unsigned modules.
"""

import subprocess
import re
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal


class KernelCheckWorker(QThread):
    """Background worker that analyzes kernel modules."""

    finished = pyqtSignal(dict)

    def run(self):
        results = {
            "total": 0,
            "suspicious": [],
            "unsigned": [],
            "unknown_source": [],
            "all_modules": [],
        }

        try:
            lsmod = self._run_lsmod()
            if not lsmod:
                results["error"] = "Could not read kernel modules (lsmod failed or no modules found)"
                self.finished.emit(results)
                return

            results["total"] = len(lsmod)

            # Limit modinfo calls to avoid hanging on systems with hundreds of modules
            # Process up to 80 modules, prioritizing those that look unusual
            checked = 0
            max_checks = 80
            for mod_name in lsmod:
                if not re.match(r'^[a-zA-Z0-9_.-]+$', mod_name):
                    continue
                if self._is_suspicious_name(mod_name):
                    # Always check suspicious-named modules
                    info = self._run_modinfo(mod_name)
                    self._classify_module(mod_name, info, results)
                    checked += 1
                elif checked < max_checks:
                    info = self._run_modinfo(mod_name)
                    self._classify_module(mod_name, info, results)
                    checked += 1

                if self.isInterruptionRequested():
                    results["error"] = "Check cancelled"
                    break

            # Add remaining modules as basic entries
            processed_names = {m["name"] for m in results["all_modules"]}
            for mod_name in lsmod:
                if mod_name not in processed_names and re.match(r'^[a-zA-Z0-9_.-]+$', mod_name):
                    results["all_modules"].append({"name": mod_name, "filename": "not checked"})

        except Exception as e:
            results["error"] = f"Kernel check failed: {e}"

        self.finished.emit(results)

    def _classify_module(self, mod_name, info, results):
        """Classify a module based on its modinfo output."""
        entry = {"name": mod_name, "filename": info.get("filename", "unknown")}

        filename = info.get("filename", "")
        if filename and "(builtin)" not in filename:
            entry["filename"] = filename
            entry["description"] = info.get("description", "")
            entry["license"] = info.get("license", "")

            # Flag unsigned modules (no signature key)
            sig_key = info.get("signature", "") or info.get("sig_key", "")
            if not sig_key:
                results["unsigned"].append(entry)

            # Flag modules from unknown sources
            if self._is_suspicious_source(info):
                results["unknown_source"].append(entry)

        # Flag known suspicious module names
        if self._is_suspicious_name(mod_name):
            if entry not in results["suspicious"]:
                results["suspicious"].append(entry)

        results["all_modules"].append(entry)

    def _run_lsmod(self):
        """Parse lsmod output to get module names."""
        try:
            proc = subprocess.run(
                ["lsmod"], capture_output=True, text=True, timeout=10,
            )
            if proc.returncode != 0:
                return []
            modules = []
            for line in proc.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if parts:
                    modules.append(parts[0])
            return modules
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return []

    def _run_modinfo(self, mod_name):
        """Run modinfo for a single module and return key-value pairs."""
        try:
            proc = subprocess.run(
                ["modinfo", mod_name], capture_output=True, text=True, timeout=3,
            )
            if proc.returncode != 0:
                return {}
            info = {}
            for line in proc.stdout.strip().split("\n"):
                if ":" in line:
                    key, _, value = line.partition(":")
                    info[key.strip().lower().replace(" ", "_")] = value.strip()
            return info
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return {}

    def _is_suspicious_source(self, info):
        """Check if a module comes from an unusual source."""
        filename = info.get("filename", "")
        standard_paths = ["/lib/modules/", "/usr/lib/modules/", "kernel/"]
        if filename and not any(p in filename for p in standard_paths):
            if "(builtin)" not in filename and "virtual" not in filename:
                return True
        return False

    def _is_suspicious_name(self, mod_name):
        """Flag known suspicious module name patterns."""
        suspicious_patterns = [
            "rootkit", "keylog", "sniff", "hack", "exploit",
            "backdoor", "trojan", "malware", "ransom",
        ]
        lower = mod_name.lower()
        return any(p in lower for p in suspicious_patterns)