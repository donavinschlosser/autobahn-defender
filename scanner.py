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


def get_whitelist():
    """Load the whitelist of paths excluded from scanning."""
    if WHITELIST_FILE.exists():
        try:
            return json.loads(WHITELIST_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return []


def save_whitelist(paths):
    """Save the whitelist of paths excluded from scanning."""
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        WHITELIST_FILE.write_text(json.dumps(paths, indent=2))
    except OSError:
        pass


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
        # Still write to a temp file to avoid duplicate rule name issues
        # with the single file if it has issues
        try:
            merged = tempfile.NamedTemporaryFile(
                mode="w", suffix=".yar", delete=False, prefix="autobahn_"
            )
            merged.write(contents[0])
            merged.write("\n")
            merged.close()
            os.chmod(merged.name, 0o600)
            return merged.name
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

    try:
        merged = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yar", delete=False, prefix="autobahn_"
        )
        for text in deduped:
            merged.write(text)
            merged.write("\n")
        merged.close()
        os.chmod(merged.name, 0o600)
        return merged.name
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
            filtered = [p for p in paths if not any(p.startswith(w + "/") or p == w for w in whitelist)]
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
        exclude_dirs.extend(whitelist)

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
            cmd.append(path)

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
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

    def _run_yara(self, yara_bin, scan_paths):
        """Run YARA rules on the given paths."""
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
            )
            if validate.returncode != 0 and validate.stderr:
                error_msg = validate.stderr.strip().split("\n")[0]
                results["details"].append({
                    "file": "N/A",
                    "threat": f"YARA rule error: {error_msg}",
                    "action": "error",
                })
                self.progress.emit(100)
                # Clean up temp file
                try:
                    os.unlink(merged_path)
                except OSError:
                    pass
                return results
        except Exception:
            pass  # Continue even if validation fails

        scan_threads = 1
        if self.settings_mgr:
            scan_threads = self.settings_mgr.get_scan_threads()

        total_estimate = self._estimate_file_count(scan_paths)

        def _scan_single_path(path):
            """Scan a single path with YARA. Returns a result dict."""
            path_results = {"files_scanned": 0, "threats_found": 0, "details": []}
            cmd = [yara_bin, "-r", merged_path, path]
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for line in proc.stdout:
                    if self._cancelled:
                        proc.kill()
                        break
                    line = line.strip()
                    if line:
                        parts = line.split(maxsplit=1)
                        if len(parts) == 2:
                            rule_name, filepath = parts
                            path_results["threats_found"] += 1
                            path_results["details"].append({
                                "file": filepath,
                                "threat": f"YARA: {rule_name}",
                                "action": "quarantine",
                            })
                        path_results["files_scanned"] += 1
                        self.current_file.emit(line)
                proc.wait()
                # Check stderr for rule compilation errors
                stderr_output = proc.stderr.read().strip()
                if proc.returncode != 0 and stderr_output:
                    path_results["details"].append({
                        "file": path,
                        "threat": f"YARA error: {stderr_output[:200]}",
                        "action": "error",
                    })
            except Exception as e:
                path_results["details"].append({
                    "file": path,
                    "threat": f"YARA scan error: {e}",
                    "action": "error",
                })
            return path_results

        def _calc_progress(files_scanned):
            if total_estimate > 0:
                return min(99, max(1, int(files_scanned / total_estimate * 95)))
            return min(99, max(1, files_scanned // 10))

        if scan_threads > 1 and len(scan_paths) > 1:
            with ThreadPoolExecutor(max_workers=scan_threads) as pool:
                futures = {pool.submit(_scan_single_path, p): p for p in scan_paths}
                for future in as_completed(futures):
                    if self._cancelled:
                        break
                    path_result = future.result()
                    results["files_scanned"] += path_result["files_scanned"]
                    results["threats_found"] += path_result["threats_found"]
                    results["details"].extend(path_result["details"])
                    self.progress.emit(_calc_progress(results["files_scanned"]))
        else:
            for path in scan_paths:
                if self._cancelled:
                    break
                path_result = _scan_single_path(path)
                results["files_scanned"] += path_result["files_scanned"]
                results["threats_found"] += path_result["threats_found"]
                results["details"].extend(path_result["details"])
                self.progress.emit(_calc_progress(results["files_scanned"]))

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
            self.finished.emit(False, "freshclam not found — install clamav")
            return

        try:
            config_path = APP_DIR / "freshclam.conf"
            log_path = APP_DIR / "freshclam.log"
            pid_path = APP_DIR / "freshclam.pid"
            # Remove stale symlink to prevent symlink attacks
            if config_path.is_symlink():
                config_path.unlink()
            config_content = (
                f"DatabaseDirectory {DEFS_DIR}\n"
                f"UpdateLogFile {log_path}\n"
                f"LogFileMaxSize 1M\n"
                f"PidFile {pid_path}\n"
                f"DatabaseMirror database.clamav.net\n"
            )
            # Atomic write: write to temp file then rename
            tmp_config = config_path.with_suffix(".tmp")
            tmp_config.write_text(config_content)
            os.chmod(str(tmp_config), 0o600)
            tmp_config.replace(config_path)

            self.status.emit("Checking for definition updates...")
            self.progress.emit(5)

            try:
                pid_path.unlink()
            except OSError:
                pass

            proc = subprocess.Popen(
                [freshclam, "--config-file", str(config_path)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )

            db_files = ["main.cvd", "daily.cvd", "bytecode.cvd"]
            current_db = -1
            output_lines = []
            all_up_to_date = True
            any_downloaded = False

            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                output_lines.append(line)
                lower = line.lower()

                # Detect which database file is being processed
                for i, db in enumerate(db_files):
                    if db in lower:
                        current_db = i
                        break

                # Detect download start
                if "downloading" in lower:
                    all_up_to_date = False
                    any_downloaded = True
                    db_name = db_files[current_db] if current_db >= 0 else "database"
                    self.status.emit(f"Downloading {db_name}...")
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
            self.progress.emit(95)

            for p in [log_path, pid_path]:
                try:
                    p.unlink()
                except OSError:
                    pass

            if proc.returncode == 0:
                self.progress.emit(100)
                _save_defs_timestamp()
                if all_up_to_date:
                    self.status.emit("Definitions are already up to date")
                    self.finished.emit(True, "Definitions are already up to date")
                else:
                    self.status.emit("Definitions updated successfully")
                    self.finished.emit(True, "Definitions updated successfully")
                return

            error_msg = "\n".join(output_lines[-5:]) or "freshclam failed"
            self.progress.emit(0)
            if "libfreshclam init failed" in error_msg or "internal logger" in error_msg:
                self.finished.emit(False, (
                    "Cannot update definitions: freshclam requires elevated privileges.\n"
                    "Run in terminal: sudo freshclam"
                ))
                return
            self.finished.emit(False, f"Update failed: {error_msg}")

        except FileNotFoundError:
            self.finished.emit(False, "freshclam not found — install clamav")
        except subprocess.TimeoutExpired:
            self.finished.emit(False, "Definition update timed out (can take several minutes)")
        except Exception as e:
            self.finished.emit(False, f"Error: {e}")