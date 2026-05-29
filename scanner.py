"""
Autobahn Defender - Scanner Module
Core scanning engine using ClamAV (clamscan) and YARA.
"""

import os
import re
import shutil
import subprocess
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal, QObject


# Paths
APP_DIR = Path.home() / ".autobahn"
DEFS_DIR = APP_DIR / "definitions"
QUARANTINE_DIR = APP_DIR / "quarantine"
RULES_DIR = APP_DIR / "rules"
MANIFEST_FILE = QUARANTINE_DIR / "manifest.json"
DEFS_TIMESTAMP_FILE = APP_DIR / "defs_last_updated.txt"
WHITELIST_FILE = APP_DIR / "whitelist.json"


def _save_defs_timestamp():
    """Save the current timestamp as the last definition update time."""
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        DEFS_TIMESTAMP_FILE.write_text(datetime.now().isoformat())
    except OSError:
        pass


def get_defs_last_updated():
    """Return the last definition update time as a string, or 'Never'."""
    try:
        if DEFS_TIMESTAMP_FILE.exists():
            ts = DEFS_TIMESTAMP_FILE.read_text().strip()
            dt = datetime.fromisoformat(ts)
            return dt.strftime("%Y-%m-%d %H:%M")
    except (ValueError, OSError):
        pass
    return "Never"


def ensure_dirs():
    """Create application directories if they don't exist."""
    for d in [APP_DIR, DEFS_DIR, QUARANTINE_DIR, RULES_DIR]:
        d.mkdir(parents=True, exist_ok=True)

    # Copy bundled YARA rules to user rules dir on first run
    if not list(RULES_DIR.glob("*.yar")):
        # Determine bundled rules path (works for PyInstaller and source runs)
        import sys as _sys
        if getattr(_sys, "frozen", False):
            bundled_rules = Path(_sys._MEIPASS) / "rules"
        else:
            bundled_rules = Path(__file__).parent / "rules"
        if bundled_rules.exists():
            for rule_file in bundled_rules.glob("*.yar"):
                try:
                    shutil.copy2(str(rule_file), str(RULES_DIR / rule_file.name))
                except (OSError, PermissionError):
                    pass


def get_whitelist():
    """Load the whitelist of paths, YARA rules, and process names excluded from scanning.

    Each entry is a dict with __type__:
      - {"__type__": "path", "path": "/real/path"}
      - {"__type__": "yara_rule", "pattern": "RuleName"}
      - {"__type__": "process_name", "name": "processname"}
    Normalizes old-format string entries automatically.
    Only accepts strings that look like absolute paths (start with /).
    """
    if WHITELIST_FILE.exists():
        try:
            data = json.loads(WHITELIST_FILE.read_text())
            if isinstance(data, list):
                upgraded = []
                for entry in data:
                    if isinstance(entry, dict) and "__type__" in entry:
                        upgraded.append(entry)
                    elif isinstance(entry, str) and entry and entry.startswith("/"):
                        # Legacy plain-string path — normalize and upgrade
                        rp = _realpath(entry)
                        if rp:
                            upgraded.append({"__type__": "path", "path": rp})
                return upgraded
            return []
        except (json.JSONDecodeError, OSError):
            pass
    return []


def save_whitelist(entries):
    """Save the whitelist. Accepts list of dict entries or plain strings (auto-upgraded)."""
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        cleaned = []
        for entry in entries:
            if isinstance(entry, dict) and "__type__" in entry:
                cleaned.append(entry)
            elif isinstance(entry, str) and entry:
                rp = _realpath(entry)
                if rp:
                    cleaned.append({"__type__": "path", "path": rp})
        WHITELIST_FILE.write_text(json.dumps(cleaned, indent=2))
    except OSError:
        pass


def _realpath(p):
    """Resolve a path to its real canonical form, or return None on error."""
    try:
        return os.path.realpath(p)
    except (OSError, AttributeError):
        return None


def is_whitelisted(filepath):
    """Check if a file path or rule match should be skipped.

    Matches both path-based exemptions (filepath in directory or exact match),
    rule-name-based exemptions (used during YARA scanning),
    and process-name-based exemptions (used during process scanning).
    """
    whitelist = get_whitelist()
    if not whitelist:
        return False, None

    rp = _realpath(filepath) if filepath else None

    for entry in whitelist:
        if not isinstance(entry, dict):
            continue
        t = entry.get("__type__")

        if t == "path":
            wl_path = entry.get("path", "")
            if not wl_path:
                continue
            if rp and (rp == wl_path or rp.startswith(wl_path + "/")):
                return True, "path"
            # Also check the original (non-resolved) path
            if filepath and (filepath == wl_path or filepath.startswith(wl_path + "/")):
                return True, "path"

        elif t == "yara_rule":
            # Rule-name match is checked by the caller with a separate function
            pattern = entry.get("pattern", "")
            if pattern and filepath and pattern in filepath:
                return True, "yara_rule"

        elif t == "process_name":
            # Process name exemption: filepath will be "PID 1234: processname"
            # Match on the process name portion only
            exempt_name = entry.get("name", "").lower()
            if exempt_name and filepath:
                # Check if the process identifier contains this name
                filepath_lower = filepath.lower()
                if exempt_name in filepath_lower:
                    return True, "process_name"

    return False, None


def is_rule_exempted(rule_name):
    """Check if a YARA rule name is in the whitelist. Returns True if exempted."""
    whitelist = get_whitelist()
    if not whitelist:
        return False
    for entry in whitelist:
        if isinstance(entry, dict) and entry.get("__type__") == "yara_rule":
            if entry.get("pattern") == rule_name:
                return True
    return False


def find_clamscan():
    """Find clamscan binary, checking bundled location first."""
    candidates = [
        Path(__file__).parent / "bin" / "clamscan",
        Path("/usr/bin/clamscan"),
        Path("/usr/local/bin/clamscan"),
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    result = shutil.which("clamscan")
    return result if result else None


def find_yara():
    """Find yara binary."""
    candidates = [
        Path(__file__).parent / "bin" / "yara",
        Path("/usr/bin/yara"),
        Path("/usr/local/bin/yara"),
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return shutil.which("yara")


def find_freshclam():
    """Find freshclam binary."""
    candidates = [
        Path("/usr/bin/freshclam"),
        Path("/usr/local/bin/freshclam"),
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return shutil.which("freshclam")


def _clean_env():
    """Return a clean environment for system tool subprocesses.

    PyInstaller sets LD_LIBRARY_PATH to its bundled libraries, which can
    conflict with system libraries when running tools like freshclam,
    clamscan, or yara via subprocess.
    """
    env = os.environ.copy()
    env.pop("LD_LIBRARY_PATH", None)
    # Also remove potentially problematic environment variables
    for var in ["PYTHONPATH", "LD_PRELOAD", "GIO_MODULE_PATH"]:
        env.pop(var, None)
    return env


def _merge_yara_rules(rule_files):
    """Merge multiple YARA rule files into a single temporary file.
    Skips empty/comment-only files and deduplicates rule names.
    Returns the path to the merged rule file, or None on failure.
    """
    if not rule_files:
        return None

    # Read and filter out empty/comment-only files
    contents = []
    for rf in rule_files:
        text = rf.read_text()
        # Check if file has any non-comment, non-blank lines
        has_rules = any(
            line.strip()
            and not line.strip().startswith("//")
            and not line.strip().startswith("#")
            and not line.strip().startswith("/*")
            and not line.strip().startswith("* ")
            and not line.strip().startswith("*/")
            for line in text.splitlines()
        )
        if has_rules:
            contents.append(text)

    if not contents:
        return None
    if len(contents) == 1:
        # Still write to a temp file for safety
        try:
            merged_path = tempfile.NamedTemporaryFile(
                mode="w", suffix=".yar", delete=False, prefix="autobahn_"
            )
            merged_path.write(contents[0])
            merged_path.write("\n")
            merged_path.close()
            os.chmod(merged_path.name, 0o600)
            return merged_path.name
        except OSError:
            return str(rule_files[0]) if rule_files else None

    # Deduplicate rule names across files to avoid YARA "duplicated identifier" errors
    seen_names = set()
    deduped = []
    import re
    rule_name_re = re.compile(r'^\s*rule\s+(\w+)\s*\{', re.MULTILINE)
    for text in contents:
        names = rule_name_re.findall(text)
        has_dup = any(n in seen_names for n in names)
        if not has_dup:
            seen_names.update(names)
            deduped.append(text)
        else:
            # Rename duplicates by prefixing with file index
            idx = len(deduped)
            for n in names:
                if n in seen_names:
                    text = text.replace(f"rule {n} {{", f"rule {n}_{idx} {{")
                    text = text.replace(f"rule {n}\n{{", f"rule {n}_{idx}\n{{")
            seen_names.update(rule_name_re.findall(text))
            deduped.append(text)

    merged_path = None
    try:
        merged = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yar", delete=False, prefix="autobahn_"
        )
        for text in deduped:
            merged.write(text)
            merged.write("\n")
        merged.close()
        os.chmod(merged.name, 0o600)
        merged_path = merged.name
        return merged_path
    except OSError:
        return str(rule_files[0]) if rule_files else None


# Known suspicious process names and crypto-miner indicators
SUSPICIOUS_PROCESS_NAMES = {
    "xmrig", "cpuminer", "minerd", "cgminer", "bfgminer",
    "cryptonight", "nanopool", "ethminer", "claymore", "nicehash",
    "coinhive", "jsecoin", "minergate", "ccminer", "nheqminer",
    "equihash", "stratum", "kthreaddi", "kswapd0",
}

SUSPICIOUS_COMMAND_PATTERNS = [
    r"--pool\s", r"--user\s", r"--pass\s", r"stratum\+tcp://",
    r"stratum\+ssl://", r"--algo\s", r"--donate-level",
]


class ScanWorker(QThread):
    """Worker thread that runs a scan and emits progress signals."""

    progress = pyqtSignal(int)
    current_file = pyqtSignal(str)
    finished = pyqtSignal(dict)

    def __init__(self, scan_type, custom_paths=None, settings_mgr=None):
        super().__init__()
        self.scan_type = scan_type
        self.custom_paths = custom_paths or []
        self.settings_mgr = settings_mgr
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        ensure_dirs()
        results = {
            "files_scanned": 0,
            "threats_found": 0,
            "details": [],
        }

        if self.scan_type == "processes":
            results = self._scan_processes()
            self.finished.emit(results)
            return

        scan_paths = self._get_scan_paths()

        if not scan_paths:
            results["details"].append({
                "file": "N/A",
                "threat": "No valid paths to scan",
                "action": "error",
            })
            self.finished.emit(results)
            return

        # Run ClamAV if available
        clamscan = find_clamscan()
        if clamscan:
            results = self._run_clamscan(clamscan, scan_paths)

        # Also run YARA if available (runs alongside ClamAV, not just as fallback)
        yara = find_yara()
        if yara:
            yara_results = self._run_yara(yara, scan_paths)
            # Merge YARA results into the main results
            results["files_scanned"] += yara_results["files_scanned"]
            results["threats_found"] += yara_results["threats_found"]
            results["details"].extend(yara_results["details"])

        if not clamscan and not yara:
            results["details"].append({
                "file": "N/A",
                "threat": "No scanner engine found (install clamav or yara)",
                "action": "error",
            })

        # Final filter: remove any whitelisted files from results
        # This catches individual files whitelisted in ClamAV (which can't use
        # --exclude-dir for single files) and YARA (where whitelist is checked
        # at collection time but files in subdirs of scan targets may still sneak in
        # if they were collected before the whitelist was loaded)
        results["details"] = [
            d for d in results["details"]
            if not (d.get("file") and is_whitelisted(d["file"])[0])
        ]
        results["threats_found"] = len([d for d in results["details"]
                                         if d.get("action") != "error" and d.get("action") != "info"])

        self.finished.emit(results)

    def _get_scan_paths(self):
        """Return list of paths to scan based on scan type."""
        home = Path.home()
        mapping = {
            "quick_home": [
                str(home / "Downloads"),
                str(home / "Documents"),
                str(home / "Desktop"),
            ],
            "full_system": ["/"],
            "external": ["/media", "/mnt", "/run/media"],
            "custom": self.custom_paths,
            "rootkit": ["/usr/bin", "/usr/sbin", "/usr/lib"],
        }
        paths = mapping.get(self.scan_type, [])
        # Filter out whitelisted paths — only skip a path if it's inside a whitelisted dir
        whitelist = get_whitelist()
        if whitelist:
            wl_paths = [e.get("path", "") for e in whitelist
                        if isinstance(e, dict) and e.get("__type__") == "path"]
            filtered = [p for p in paths if not any(p.startswith(w + "/") or p == w for w in wl_paths)]
            paths = filtered
        return [p for p in paths if os.path.exists(p)]

    def _estimate_file_count(self, scan_paths):
        """Quickly estimate the number of files to scan for progress reporting."""
        total = 0
        try:
            for path in scan_paths:
                p = Path(path)
                if p.is_file():
                    total += 1
                elif p.is_dir():
                    try:
                        for _ in p.rglob("*"):
                            total += 1
                            if total > 500000:
                                return total
                    except (PermissionError, OSError):
                        pass
        except (PermissionError, OSError):
            pass
        return max(total, 1)

    def _run_clamscan(self, clamscan, scan_paths):
        """Run clamscan on the given paths and parse output."""
        if (DEFS_DIR / "main.cvd").exists() or (DEFS_DIR / "main.cld").exists():
            defs_path = str(DEFS_DIR)
        else:
            system_def = Path("/var/lib/clamav")
            if system_def.exists():
                defs_path = str(system_def)
            else:
                defs_path = str(DEFS_DIR)

        results = {"files_scanned": 0, "threats_found": 0, "details": []}

        exclude_dirs = ["/proc", "/sys", "/dev", "/run", str(QUARANTINE_DIR)]
        # Also exclude whitelisted paths
        whitelist = get_whitelist()
        for entry in whitelist:
            if isinstance(entry, dict) and entry.get("__type__") == "path":
                wl_path = entry.get("path", "")
                if wl_path and os.path.isdir(wl_path):
                    exclude_dirs.append(wl_path)

        # Read scan options from settings
        scan_archives = True
        scan_hidden = True
        if self.settings_mgr:
            scan_archives = self.settings_mgr.is_scan_archives()
            scan_hidden = self.settings_mgr.is_scan_hidden()

        # Estimate total files for progress reporting
        total_estimate = self._estimate_file_count(scan_paths)

        for path in scan_paths:
            if self._cancelled:
                break

            cmd = [
                clamscan,
                "--database", defs_path,
                "-r",
                "--no-summary",
            ]
            if scan_archives:
                cmd.append("--scan-archive=yes")
            else:
                cmd.append("--scan-archive=no")
            if not scan_hidden:
                cmd.append(r"--exclude-dir=^\.")
            for exc in exclude_dirs:
                cmd.extend(["--exclude-dir", f"^{re.escape(exc)}/"])
            # Add -- to prevent path names from being interpreted as options
            cmd.append("--")
            cmd.append(path)

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=_clean_env(),
                )
                self._parse_clamscan_output(proc, results, total_estimate)
            except Exception as e:
                results["details"].append({
                    "file": path,
                    "threat": f"Scan error: {e}",
                    "action": "error",
                })

        return results

    def _parse_clamscan_output(self, proc, results, total_estimate=0):
        """Parse clamscan stdout line by line for progress and threats."""
        for line in proc.stdout:
            if self._cancelled:
                proc.kill()
                break

            line = line.strip()
            if not line:
                continue

            if ": OK" in line:
                self.current_file.emit(line.split(": OK")[0])
                results["files_scanned"] += 1
            elif " FOUND" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    filepath = parts[0].strip()
                    threat = parts[-1].replace(" FOUND", "").strip()
                    results["threats_found"] += 1
                    results["details"].append({
                        "file": filepath,
                        "threat": threat,
                        "action": "quarantine",
                    })
                    self.current_file.emit(filepath)
                results["files_scanned"] += 1
            elif not line.startswith("---") and not line.startswith(" "):
                self.current_file.emit(line)

            if total_estimate > 0:
                progress = min(99, max(1, int(results["files_scanned"] / total_estimate * 95)))
            else:
                progress = min(99, max(1, results["files_scanned"] // 10))
            self.progress.emit(progress)

        proc.wait()
        # Check stderr for errors
        stderr_output = proc.stderr.read().strip()
        if proc.returncode not in (0, 1) and stderr_output:
            results["details"].append({
                "file": "N/A",
                "threat": f"ClamAV error: {stderr_output[:200]}",
                "action": "error",
            })
        self.progress.emit(100)

    def _is_scannable_file(self, filepath):
        """Check if a file should be scanned with YARA.

        Scans all regular files, including text files, documents, archives,
        compressed files, scripts, and binaries. Only skips the most extreme cases
        that would cause fatal errors (devices, pipes, sockets) or produce
        meaningless results (zero-byte files).
        """
        try:
            stat_info = os.stat(filepath)
            # Skip empty files (nothing to scan)
            if stat_info.st_size == 0:
                return False
            # Skip special files (devices, pipes, sockets)
            import stat as _stat_mod
            mode = stat_info.st_mode
            if (_stat_mod.S_ISCHR(mode) or _stat_mod.S_ISBLK(mode)
                    or _stat_mod.S_ISFIFO(mode) or _stat_mod.S_ISSOCK(mode)):
                return False
        except (OSError, PermissionError):
            return False

        return True

    def _collect_scannable_files(self, scan_paths):
        """Walk paths and collect scannable files for YARA scanning.

        Returns a flat list of file paths to scan.
        """
        scannable = []
        for path in scan_paths:
            try:
                p = Path(path)
                if p.is_file():
                    if self._is_scannable_file(str(p)) and not is_whitelisted(str(p))[0]:
                        scannable.append(str(p))
                elif p.is_dir():
                    for f in p.rglob("*"):
                        if self._cancelled:
                            return scannable
                        if f.is_file() and f.is_symlink() is False:
                            fp = str(f)
                            if self._is_scannable_file(fp) and not is_whitelisted(fp)[0]:
                                scannable.append(fp)
            except (PermissionError, OSError):
                continue
        return scannable

    def _run_yara(self, yara_bin, scan_paths):
        """Run YARA rules on the given paths.

        Scans all file types discovered during the file walk, filtering
        only by the _is_scannable_file check.
        """
        results = {"files_scanned": 0, "threats_found": 0, "details": []}
        rule_files = list(RULES_DIR.glob("*.yar"))

        if not rule_files:
            default_rule = RULES_DIR / "default.yar"
            if not default_rule.exists():
                default_rule.write_text(
                    'rule no_match { condition: false }\n'
                )
            rule_files = [default_rule]

        merged_path = _merge_yara_rules(rule_files)
        if not merged_path:
            results["details"].append({
                "file": "N/A",
                "threat": "Failed to prepare YARA rules",
                "action": "error",
            })
            self.progress.emit(100)
            return results

        # Validate rules compile before scanning
        try:
            validate = subprocess.run(
                [yara_bin, merged_path, "/dev/null"],
                capture_output=True, text=True, timeout=30,
                env=_clean_env(),
            )
            if validate.returncode != 0 and validate.stderr:
                error_msg = validate.stderr.strip().split("\n")[0]
                results["details"].append({
                    "file": "N/A",
                    "threat": f"YARA rule error: {error_msg}",
                    "action": "error",
                })
                self.progress.emit(100)
                try:
                    os.unlink(merged_path)
                except OSError:
                    pass
                return results
        except Exception:
            pass  # Continue even if validation fails

        # Collect only scannable files (ELF + scripts) — skip PDFs/images/docs
        scannable_files = self._collect_scannable_files(scan_paths)
        total = len(scannable_files)

        if total == 0:
            results["details"].append({
                "file": "N/A",
                "threat": "No scannable files found (only ELF binaries and scripts are scanned)",
                "action": "info",
            })
            try:
                os.unlink(merged_path)
            except OSError:
                pass
            self.progress.emit(100)
            return results

        scan_threads = min(total, 4)
        if self.settings_mgr:
            scan_threads = min(total, self.settings_mgr.get_scan_threads())

        def _scan_single_file(filepath):
            """Scan a single file with YARA. Returns a result dict."""
            path_results = {"threats_found": 0, "details": []}
            cmd = [yara_bin, merged_path, filepath]
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=_clean_env(),
                )
                for line in proc.stdout:
                    if self._cancelled:
                        proc.kill()
                        break
                    line = line.strip()
                    if line:
                        parts = line.split(maxsplit=1)
                        if len(parts) == 2:
                            rule_name, _ = parts
                            # Skip exempted YARA rules
                            if is_rule_exempted(rule_name):
                                continue
                            path_results["threats_found"] += 1
                            path_results["details"].append({
                                "file": filepath,
                                "threat": f"YARA: {rule_name}",
                                "action": "quarantine",
                            })
                proc.wait()
            except Exception:
                pass
            return path_results

        processed = 0
        if scan_threads > 1:
            with ThreadPoolExecutor(max_workers=scan_threads) as pool:
                futures = {pool.submit(_scan_single_file, f): f for f in scannable_files}
                for future in as_completed(futures):
                    if self._cancelled:
                        break
                    result = future.result()
                    results["threats_found"] += result["threats_found"]
                    results["details"].extend(result["details"])
                    results["files_scanned"] += 1
                    processed += 1
                    self.current_file.emit(futures[future])
                    if total > 0:
                        self.progress.emit(min(99, int(processed / total * 95)))
        else:
            for filepath in scannable_files:
                if self._cancelled:
                    break
                result = _scan_single_file(filepath)
                results["threats_found"] += result["threats_found"]
                results["details"].extend(result["details"])
                results["files_scanned"] += 1
                processed += 1
                self.current_file.emit(filepath)
                if total > 0:
                    self.progress.emit(min(99, int(processed / total * 95)))

        if merged_path:
            try:
                os.unlink(merged_path)
            except OSError:
                pass

        self.progress.emit(100)
        return results

    def _scan_processes(self):
        """Scan running processes for suspicious activity using psutil."""
        results = {"files_scanned": 0, "threats_found": 0, "details": []}

        try:
            import psutil
        except ImportError:
            results["details"].append({
                "file": "N/A",
                "threat": "psutil not installed — run: pip install psutil",
                "action": "error",
            })
            self.progress.emit(100)
            return results

        processes = list(psutil.process_iter(["pid", "name", "cmdline", "cpu_percent", "memory_percent", "ppid"]))
        results["files_scanned"] = len(processes)
        total = len(processes)

        suspicious_parents = set()

        for i, proc in enumerate(processes):
            if self._cancelled:
                break
            try:
                info = proc.info
                name = (info.get("name") or "").lower()
                cmdline = " ".join(info.get("cmdline") or [])
                cmdline_lower = cmdline.lower()
                pid = info.get("pid", "?")
                cpu = info.get("cpu_percent") or 0
                mem = info.get("memory_percent") or 0
                ppid = info.get("ppid")

                # Skip whitelisted process names
                proc_display = f"PID {pid}: {name}"
                if is_whitelisted(proc_display)[0]:
                    continue

                # Flag known suspicious names
                if name in SUSPICIOUS_PROCESS_NAMES:
                    results["threats_found"] += 1
                    results["details"].append({
                        "file": f"PID {pid}: {name}",
                        "threat": f"Suspicious process name: {name}",
                        "action": "flag",
                    })
                    suspicious_parents.add(pid)
                    continue

                # Flag suspicious command patterns (crypto miner args)
                for pattern in SUSPICIOUS_COMMAND_PATTERNS:
                    if re.search(pattern, cmdline_lower):
                        results["threats_found"] += 1
                        results["details"].append({
                            "file": f"PID {pid}: {name}",
                            "threat": f"Suspicious command pattern detected",
                            "action": "flag",
                        })
                        suspicious_parents.add(pid)
                        break

                # Flag high CPU processes that look like miners
                if isinstance(cpu, (int, float)) and cpu > 80 and name not in {
                    "firefox", "chrome", "chromium", "firefox-bin", "python3",
                    "python", "node", "java", "steam", "wine", "blender",
                }:
                    results["threats_found"] += 1
                    results["details"].append({
                        "file": f"PID {pid}: {name}",
                        "threat": f"High CPU usage ({cpu:.0f}%)",
                        "action": "info",
                    })

                self.current_file.emit(f"Checking: {name} (PID {pid})")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

            progress = min(95, max(1, int((i + 1) / total * 100)))
            self.progress.emit(progress)

        # Check suspicious parent-child relationships
        for proc in processes:
            try:
                info = proc.info
                ppid = info.get("ppid")
                if ppid in suspicious_parents:
                    name = info.get("name") or ""
                    pid = info.get("pid", "?")
                    results["threats_found"] += 1
                    results["details"].append({
                        "file": f"PID {pid}: {name}",
                        "threat": f"Child of suspicious process (PPID {ppid})",
                        "action": "flag",
                    })
            except Exception:
                continue

        self.progress.emit(100)
        return results


class Scanner(QObject):
    """High-level scanner interface for the UI."""

    scan_started = pyqtSignal()
    scan_progress = pyqtSignal(int)
    scan_file = pyqtSignal(str)
    scan_finished = pyqtSignal(dict)
    scan_error = pyqtSignal(str)
    defs_update_finished = pyqtSignal(bool, str)
    defs_update_progress = pyqtSignal(int)
    defs_update_status = pyqtSignal(str)
    defs_started = pyqtSignal()  # Emitted when definition update starts

    def __init__(self, parent=None, settings_mgr=None):
        super().__init__(parent)
        self.settings_mgr = settings_mgr
        self._worker = None
        self._defs_worker = None

    def start_scan(self, scan_type, custom_paths=None):
        """Start a scan. scan_type: quick_home, full_system, external, custom, rootkit, processes."""
        if self._worker and self._worker.isRunning():
            self.scan_error.emit("A scan is already running")
            return

        self._worker = ScanWorker(scan_type, custom_paths, settings_mgr=self.settings_mgr)
        self._worker.progress.connect(self.scan_progress.emit)
        self._worker.current_file.connect(self.scan_file.emit)
        self._worker.finished.connect(self._on_finished)
        self.scan_started.emit()
        self._worker.start()

    def cancel_scan(self):
        """Cancel the running scan."""
        if self._worker and self._worker.isRunning():
            self._worker.cancel()

    def _on_finished(self, results):
        self.scan_finished.emit(results)
        self._worker = None

    def update_definitions(self):
        """Start definition update in a background thread."""
        if self._defs_worker and self._defs_worker.isRunning():
            self.defs_update_finished.emit(False, "Update already in progress")
            return
        self._defs_worker = _DefsUpdateWorker()
        self._defs_worker.finished.connect(self._on_defs_update_finished)
        self._defs_worker.progress.connect(self.defs_update_progress.emit)
        self._defs_worker.status.connect(self.defs_update_status.emit)
        self.defs_started.emit()  # Emitted when update starts
        self._defs_worker.start()

    def _on_defs_update_finished(self, ok, msg):
        self.defs_update_finished.emit(ok, msg)
        self._defs_worker = None


class _DefsUpdateWorker(QThread):
    """Background thread for definition updates."""

    finished = pyqtSignal(bool, str)
    progress = pyqtSignal(int)
    status = pyqtSignal(str)

    def run(self):
        ensure_dirs()
        freshclam = find_freshclam()
        if not freshclam:
            system_defs = Path("/var/lib/clamav")
            if system_defs.exists():
                self.status.emit("Copying system definitions...")
                cvd_files = list(system_defs.glob("*.cvd")) + list(system_defs.glob("*.cld"))
                if cvd_files:
                    total = len(cvd_files)
                    for i, f in enumerate(cvd_files):
                        try:
                            shutil.copy2(str(f), str(DEFS_DIR / f.name))
                            self.progress.emit(int((i + 1) / total * 100))
                        except (PermissionError, OSError):
                            pass
                    count = len(list(DEFS_DIR.glob("*.cvd"))) + len(list(DEFS_DIR.glob("*.cld")))
                    if count > 0:
                        _save_defs_timestamp()
                        self.finished.emit(True, f"Copied {count} definition file(s) from system")
                        return
                    self.finished.emit(False, "Cannot copy system definitions (permission denied)")
                    return
            # On Debian, check if freshclam service exists but freshclam isn't in PATH
            if shutil.which("systemctl"):
                try:
                    proc = subprocess.run(
                        ["systemctl", "is-active", "clamav-freshclam"],
                        capture_output=True, text=True, timeout=5,
                    )
                    if proc.returncode == 0 and "active" in proc.stdout:
                        self.status.emit("System freshclam service is active — downloading definitions...")
                        self.progress.emit(10)
                        # Service runs as root and writes to /var/lib/clamav — copy from there
                        system_defs = Path("/var/lib/clamav")
                        if system_defs.exists():
                            cvd_files = list(system_defs.glob("*.cvd")) + list(system_defs.glob("*.cld"))
                            if cvd_files:
                                total = len(cvd_files)
                                for i, f in enumerate(cvd_files):
                                    try:
                                        shutil.copy2(str(f), str(DEFS_DIR / f.name))
                                        self.progress.emit(int((i + 1) / total * 100))
                                    except (PermissionError, OSError):
                                        pass
                                count = len(list(DEFS_DIR.glob("*.cvd"))) + len(list(DEFS_DIR.glob("*.cld")))
                                if count > 0:
                                    _save_defs_timestamp()
                                    self.finished.emit(True, f"Copied {count} definition file(s) from running system service")
                                    return
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass
            self.finished.emit(False, "freshclam not found — install clamav")
            return

        try:
            config_path = APP_DIR / "freshclam.conf"
            log_path = APP_DIR / "freshclam.log"
            pid_path = APP_DIR / "freshclam.pid"

            # Remove stale symlinks or files to prevent symlink attacks
            for p in (config_path, pid_path, log_path):
                if p.is_symlink():
                    p.unlink()
                elif p.exists():
                    try:
                        p.unlink()
                    except OSError:
                        pass

            import pwd
            current_user = pwd.getpwuid(os.getuid()).pw_name

            # ─── Version-agnostic freshclam config ─────────────────
            # ClamAV 0.103 (Zorin / Ubuntu 22.04) does NOT support
            # DatabaseOwner. ClamAV 1.0+ (Debian 12 / Ubuntu 24.04)
            # REQUIRES DatabaseOwner to prevent setuid to clamav user
            # (which then can't write to the user's ~/.autobahn/ dir).
            #
            # Strategy: ensure the defs dir is writable by the user, then
            # try WITHOUT DatabaseOwner first (works on all versions).
            # If that fails, retry WITH DatabaseOwner (needed for v1.0+).
            # If both fail, fall back to system defs / HTTP download.
            DEFS_DIR.mkdir(parents=True, exist_ok=True)
            # Set restrictive permissions - only user should have access
            os.chmod(str(DEFS_DIR), 0o700)

            # Base config — works on ALL ClamAV versions (no DatabaseOwner)
            config_base = (
                f"DatabaseDirectory {DEFS_DIR}\n"
                f"DatabaseMirror database.clamav.net\n"
                f"Foreground yes\n"
            )

            def _try_freshclam_run(freshclam_bin, config_text, pass_label):
                """Run freshclam with a config and return (success, output_lines)."""
                tmp = config_path.with_suffix(".tmp")
                tmp.write_text(config_text)
                os.chmod(str(tmp), 0o600)
                tmp.replace(config_path)

                db_files = ["main.cvd", "daily.cvd", "bytecode.cvd"]
                current_db = -1
                output_lines = []
                all_up_to_date = True

                proc = subprocess.Popen(
                    [freshclam_bin, "--config-file", str(config_path)],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                    env=_clean_env(),
                )
                for line in proc.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    output_lines.append(line)
                    lower = line.lower()
                    for i, db in enumerate(db_files):
                        if db in lower:
                            current_db = i
                            break
                    if "downloading" in lower:
                        all_up_to_date = False
                        db_name = db_files[current_db] if current_db >= 0 else "database"
                        self.status.emit(f"[{pass_label}] Downloading {db_name}...")
                        self.progress.emit(max(10, 10 + (current_db + 1) * 25 - 10))
                    elif "is up to date" in lower and current_db >= 0:
                        self.status.emit(f"{db_files[current_db]} is up to date")
                    elif "updated" in lower and current_db >= 0:
                        all_up_to_date = False
                        self.progress.emit(10 + (current_db + 1) * 25)
                        self.status.emit(f"{db_files[current_db]} updated")
                    elif "test" in lower:
                        self.status.emit("Testing database...")
                        self.progress.emit(90)

                proc.wait()
                return (proc.returncode == 0, all_up_to_date, output_lines)

            self.status.emit("Checking for definition updates...")
            self.progress.emit(5)

            # Pass 1: config WITHOUT DatabaseOwner (compatible with ClamAV 0.103+)
            ok, all_uptodate, lines1 = _try_freshclam_run(
                freshclam, config_base, "Pass 1"
            )
            if ok:
                self.progress.emit(100)
                _save_defs_timestamp()
                # freshclam can exit 0 with only daily.cvd downloaded
                # (main.cvd and bytecode.cvd may be skipped by the mirror).
                # Fill in any missing files via direct HTTP download.
                self.status.emit("Verifying all definitions present...")
                missing = [f for f in ["main.cvd", "bytecode.cvd"] if not (DEFS_DIR / f).exists()]
                if missing:
                    self.status.emit(f"Downloading missing: {', '.join(missing)}")
                    self._direct_http_download()
                if all_uptodate:
                    self.finished.emit(True, "Definitions are already up to date")
                else:
                    self.finished.emit(True, "Definitions updated successfully")
                log_path.unlink(missing_ok=True)
                return

            # Pass 1 failed. Check if the error looks like a DatabaseOwner problem
            # (permission-denied as clamav user — freshclam setuid'd to clamav).
            output_text = "\n".join(lines1).lower()
            needs_dbowner = (
                "permission denied" in output_text
                or "can't create" in output_text
                or "can not create" in output_text
                or "cannot create" in output_text
                or "clamav" in output_text
            )

            if needs_dbowner:
                # Pass 2: config WITH DatabaseOwner (needed for ClamAV 1.0+)
                self.status.emit("Retrying with DatabaseOwner...")
                config_v2 = config_base + f"DatabaseOwner {current_user}\n"
                ok2, all_uptodate2, lines2 = _try_freshclam_run(
                    freshclam, config_v2, "Pass 2"
                )
                if ok2:
                    self.progress.emit(100)
                    _save_defs_timestamp()
                    if all_uptodate2:
                        self.finished.emit(True, "Definitions are already up to date")
                    else:
                        self.finished.emit(True, "Definitions updated successfully")
                    log_path.unlink(missing_ok=True)
                    return
                output_text = "\n".join(lines2).lower()

            self.progress.emit(0)
            log_path.unlink(missing_ok=True)

            # If config contains "parse" errors (older ClamAV rejecting
            # DatabaseOwner), try pass 1 again — it succeeded once with
            # this user during testing.
            if "can't open/parse" in output_text or "cannot open/parse" in output_text:
                self.status.emit("Config error — retrying without DatabaseOwner...")
                ok3, all_uptodate3, _ = _try_freshclam_run(
                    freshclam, config_base, "Pass 3"
                )
                if ok3:
                    self.progress.emit(100)
                    _save_defs_timestamp()
                    self.finished.emit(True, "Definitions updated successfully")
                    return

            # Both freshclam passes failed — fall back to system definitions
            self.status.emit("Trying system definitions...")
            self._copy_system_defs_and_finish()
            return

        except FileNotFoundError:
            # freshclam binary not found — try system defs
            self.status.emit("freshclam not found, trying system definitions...")
            self._copy_system_defs_and_finish()
        except subprocess.TimeoutExpired:
            self.finished.emit(False, "Definition update timed out (can take several minutes)")
        except Exception as e:
            self.finished.emit(False, f"Error: {e}")

    def _copy_system_defs_and_finish(self):
        """Copy ClamAV definitions from /var/lib/clamav/ if available.

        Three-tier fallback:
        1. Copy existing CVD/CLD files from /var/lib/clamav/
        2. Run `sudo freshclam` (system config) to populate /var/lib/clamav/, then copy
        3. Direct HTTP download of CVD files from database.clamav.net
        """
        system_defs = Path("/var/lib/clamav")
        if system_defs.exists():
            cvd_files = list(system_defs.glob("*.cvd")) + list(system_defs.glob("*.cld"))
            if cvd_files:
                total = len(cvd_files)
                for i, f in enumerate(cvd_files):
                    try:
                        shutil.copy2(str(f), str(DEFS_DIR / f.name))
                        self.progress.emit(int((i + 1) / total * 100))
                        self.status.emit(f"Copied {f.name}")
                    except (PermissionError, OSError):
                        pass
                count = len(list(DEFS_DIR.glob("*.cvd"))) + len(list(DEFS_DIR.glob("*.cld")))
                if count > 0:
                    _save_defs_timestamp()
                    self.finished.emit(True, f"Copied {count} definition file(s) from system")
                    return
            # System directory exists but is empty — try pkexec freshclam to populate it
            self.status.emit("System directory empty — downloading with system freshclam...")
            freshclam = find_freshclam()
            if freshclam and self._try_sudo_freshclam(freshclam):
                # Retry copy after pkexec freshclam populated /var/lib/clamav
                cvd_files = list(system_defs.glob("*.cvd")) + list(system_defs.glob("*.cld"))
                if cvd_files:
                    for f in cvd_files:
                        try:
                            shutil.copy2(str(f), str(DEFS_DIR / f.name))
                        except (PermissionError, OSError):
                            pass
                    count = len(list(DEFS_DIR.glob("*.cvd"))) + len(list(DEFS_DIR.glob("*.cld")))
                    if count > 0:
                        _save_defs_timestamp()
                        self.finished.emit(True, f"Downloaded and copied {count} definition file(s)")
                        return

            # Tier 3: try starting systemd clamav-freshclam service briefly
            self.status.emit("Trying system freshclam service...")
            if self._try_systemctl_freshclam():
                cvd_files = list(system_defs.glob("*.cvd")) + list(system_defs.glob("*.cld"))
                if cvd_files:
                    for f in cvd_files:
                        try:
                            shutil.copy2(str(f), str(DEFS_DIR / f.name))
                        except (PermissionError, OSError):
                            pass
                    count = len(list(DEFS_DIR.glob("*.cvd"))) + len(list(DEFS_DIR.glob("*.cld")))
                    if count > 0:
                        _save_defs_timestamp()
                        self.finished.emit(True, f"Downloaded {count} definition file(s) via system service")
                        return

            # Last resort: direct HTTP download with mirror fallback
            self.status.emit("Downloading definitions directly...")
            if self._direct_http_download():
                count = len(list(DEFS_DIR.glob("*.cvd"))) + len(list(DEFS_DIR.glob("*.cld")))
                if count > 0:
                    _save_defs_timestamp()
                    self.finished.emit(True, f"Downloaded {count} definition file(s) directly")
                    return
            self.finished.emit(False, "System definitions directory exists but contains no files")
            return

        # No /var/lib/clamav at all — try direct HTTP download
        self.status.emit("Downloading definitions directly...")
        if self._direct_http_download():
            count = len(list(DEFS_DIR.glob("*.cvd"))) + len(list(DEFS_DIR.glob("*.cld")))
            if count > 0:
                _save_defs_timestamp()
                self.finished.emit(True, f"Downloaded {count} definition file(s) directly")
                return

        self.finished.emit(False, (
            "No virus definitions available.\n\n"
            "Please run this command once in a terminal:\n"
            "  sudo freshclam\n\n"
            "After that, Autobahn Defender will use those definitions automatically."
        ))

    def _try_sudo_freshclam(self, freshclam_bin):
        """Run pkexec freshclam using the system config to populate /var/lib/clamav/.

        Uses pkexec (PolicyKit GUI dialog) so the user gets a native
        password prompt — no terminal needed. Falls back to sudo -A
        (graphical askpass) if pkexec is unavailable.
        """
        try:
            # Try pkexec first (works without a terminal, native GUI prompt)
            proc = subprocess.run(
                ["pkexec", freshclam_bin, "--config-file=/etc/clamav/freshclam.conf"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                timeout=300, env=_clean_env(),
            )
            return proc.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # pkexec not available — try sudo -A (SUDO_ASKPASS for GUI)
            try:
                proc = subprocess.run(
                    ["sudo", "-A", freshclam_bin, "--config-file=/etc/clamav/freshclam.conf"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                    timeout=300, env=_clean_env(),
                )
                return proc.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return False

    def _try_systemctl_freshclam(self):
        """Start clamav-freshclam systemd service, wait for it to download
        definitions, stop it, then return True if any CVD files appeared.

        Uses pkexec so the user gets a GUI password prompt.
        This is a last-resort fallback for Debian systems where
        /var/lib/clamav/ exists but is empty.
        """
        try:
            # Start the service (requires root)
            subprocess.run(
                ["pkexec", "systemctl", "start", "clamav-freshclam"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=30, env=_clean_env(),
            )
            # Wait up to 120 seconds for CVD files to appear
            system_defs = Path("/var/lib/clamav")
            for _ in range(24):
                cvd_files = (
                    list(system_defs.glob("*.cvd"))
                    + list(system_defs.glob("*.cld"))
                )
                if cvd_files:
                    # Got them — stop the service
                    subprocess.run(
                        ["pkexec", "systemctl", "stop", "clamav-freshclam"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=15, env=_clean_env(),
                    )
                    return True
                import time
                time.sleep(5)
            # Timeout — stop the service regardless
            subprocess.run(
                ["pkexec", "systemctl", "stop", "clamav-freshclam"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=15, env=_clean_env(),
            )
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    def _direct_http_download(self):
        """Download ClamAV CVD files directly via HTTP as ultimate fallback.

        Tries multiple mirrors in sequence because database.clamav.net can
        be slow or unreachable on some networks.
        """
        import urllib.request
        import urllib.error

        mirrors = [
            "https://database.clamav.net",
            "https://packages.clamav.net",
            "https://pivotal-clamav-mirror.s3.amazonaws.com",
        ]
        files_to_get = ["daily.cvd", "main.cvd", "bytecode.cvd"]

        downloaded = 0
        for fname in files_to_get:
            if (DEFS_DIR / fname).exists():
                downloaded += 1
                continue
            for mirror in mirrors:
                url = f"{mirror}/{fname}"
                try:
                    self.status.emit(f"Downloading {fname}...")
                    req = urllib.request.Request(
                        url, headers={"User-Agent": "ClamAV"}
                    )
                    with urllib.request.urlopen(req, timeout=120) as resp:
                        data = resp.read()
                        if data and (data[:10] == b"ClamAV-VDB" or len(data) > 1024):
                            (DEFS_DIR / fname).write_bytes(data)
                            os.chmod(str(DEFS_DIR / fname), 0o644)
                            downloaded += 1
                            self.status.emit(f"Downloaded {fname}")
                            break  # got it from this mirror, next file
                except (urllib.error.URLError, urllib.error.HTTPError, OSError):
                    continue  # try next mirror

        return downloaded > 0