"""Headless scan core (Phase 1.2b): QThread-free scan implementations.

scanner.py's ScanWorker is a QThread; the CLI and MCP server need the same
scanning logic without Qt. This module hosts the Qt-free primitives the GUI
ScanWorker and engine.runner.run_scan both call:

  - scan_files_yara(files, settings) -> dict
  - scan_files_clamav(files, progress_cb) -> dict
  - scan_custom_paths(paths, settings, progress_cb) -> dict
  - scan_processes() -> dict

scanner.py imports THIS for its worker bodies (adapter pattern from the plan),
so there is exactly one implementation of every scanning behavior.
"""
from __future__ import annotations

import logging
import re
import subprocess
import tempfile
import os
import threading
from pathlib import Path
from typing import Any, Callable

from .paths import DEFS_DIR, APP_DIR, QUARANTINE_DIR, RULES_DIR
from . import checks as _checks  # noqa: F401  (placeholder import for parity)

log = logging.getLogger(__name__)

ProgressCb = Callable[[int, str], None]


def _clean_env():
    """Subprocess env without PyInstaller's LD_LIBRARY_PATH (mirrors scanner)."""
    env = os.environ.copy()
    for var in ("LD_LIBRARY_PATH", "PYTHONPATH", "LD_PRELOAD", "GIO_MODULE_PATH"):
        env.pop(var, None)
    return env


def find_clamscan() -> str | None:
    for c in (Path("/usr/bin/clamscan"), Path("/usr/local/bin/clamscan")):
        if c.exists():
            return str(c)
    import shutil
    return shutil.which("clamscan")


def find_yara() -> str | None:
    import shutil
    return shutil.which("yara")


def find_freshclam() -> str | None:
    for c in (Path("/usr/bin/freshclam"), Path("/usr/local/bin/freshclam")):
        if c.exists():
            return str(c)
    import shutil
    return shutil.which("freshclam")


def _parse_clam_line(line: str):
    """Return ('ok'|'threat'|'info', filepath, threat) from a clamscan line."""
    line = line.strip()
    if not line:
        return None
    if ": OK" in line:
        return ("ok", line.split(": OK")[0], "")
    if " FOUND" in line:
        clean = line.rstrip()
        if clean.endswith(" FOUND"):
            without = clean[:-6].rstrip()
        else:
            without = clean
        if ": " in without:
            filepath, threat = without.rsplit(": ", 1)
        else:
            filepath, threat = without.rsplit(":", 1)
        return ("threat", filepath.strip(), threat.strip())
    return ("info", line, "")


def _classify_clam_stderr(stderr_text: str):
    """Split clamscan stderr into per-file access errors and real errors.

    Access errors (unreadable files — encrypted, permission, missing) are
    counted, not listed: a full-home eCryptfs scan can generate thousands of
    'Can't access file' lines. Returns (access_count, access_sample, others).
    """
    access, others = [], []
    for line in stderr_text.splitlines():
        line = line.strip()
        if not line or "Warning" in line or "LibClamAV" in line:
            continue
        if ("No such file or directory" in line
                or "Can't access file" in line
                or "Permission denied" in line
                or "ECRYPTFS" in line.upper()
                or "LSTAT" in line.upper()):
            access.append(line)
        else:
            others.append(line)
    return (len(access), access[0][:160] if access else "", others)


def run_clamscan_on_files(files: list[str], progress_cb: ProgressCb | None = None,
                          progress_start: int = 0, progress_end: int = 100,
                          defs_dir: Path | None = None) -> dict[str, Any]:
    """Scan a list of files with clamscan -f (batch file list).

    Returns results dict identical in shape to scanner.py's parallel runner
    (files_scanned, threats_found, details).
    """
    clamscan = find_clamscan()
    results: dict[str, Any] = {"files_scanned": 0, "threats_found": 0, "details": []}
    if not clamscan:
        results["details"].append({
            "file": "N/A",
            "threat": "ClamAV (clamscan) is not installed — install clamav",
            "action": "error",
        })
        return results

    if defs_dir is None:
        defs_dir = DEFS_DIR
    if (defs_dir / "main.cvd").exists() or (defs_dir / "main.cld").exists():
        defs_path = str(defs_dir)
    elif Path("/var/lib/clamav").exists():
        defs_path = "/var/lib/clamav"
    else:
        defs_path = str(defs_dir)

    if not files:
        return results

    file_list_path = None
    stderr_path = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="autobahn_clamlist_") as f:
            f.write("\n".join(files) + "\n")
            file_list_path = f.name
        # v2.0.2: stderr capture goes to a temp FILE (deadlock fix — a pipe
        # fills at ~64KB when clamscan errors on thousands of unreadable
        # files, e.g. eCryptfs raw stores, and the process wedges forever).
        stderr_fd, stderr_path = tempfile.mkstemp(suffix=".log",
                                                  prefix="clamav_err_")
        os.close(stderr_fd)
        cmd = [
            clamscan, "--database", defs_path, "--no-summary",
            "--exclude", r"^/tmp/autobahn_.*\.yar$",
            # v2.0.2: skip eCryptfs raw encrypted stores (unscannable ciphertext)
            "--exclude-dir", r"^/home/\.ecryptfs/",
            "--exclude-dir", r"^/\.ecryptfs/",
            "-f", file_list_path, "--",
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=open(stderr_path, "wb"),
                                text=True, env=_clean_env())
        total = len(files)
        for line in proc.stdout:
            parsed = _parse_clam_line(line)
            if not parsed:
                continue
            kind, fp, threat = parsed
            if kind == "ok":
                results["files_scanned"] += 1
                if progress_cb and results["files_scanned"] % 500 == 0:
                    frac = min(1.0, results["files_scanned"] / total)
                    pct = int(progress_start + frac * (progress_end - progress_start - 1))
                    progress_cb(max(progress_start + 1, pct), f"ClamAV: {fp}")
            elif kind == "threat":
                results["threats_found"] += 1
                results["files_scanned"] += 1
                results["details"].append({
                    "file": fp, "threat": threat, "action": "quarantine",
                })
        proc.wait()
        # v2.0.2: classify stderr; unreadable files become one aggregate row
        try:
            with open(stderr_path, "r", encoding="utf-8", errors="replace") as ef:
                stderr_text = ef.read()
        except OSError:
            stderr_text = ""
        access_count, access_sample, others = _classify_clam_stderr(stderr_text)
        if access_count:
            results["details"].append({
                "file": "N/A",
                "threat": (f"ClamAV could not read {access_count:,} file(s) — "
                           f"encrypted (eCryptfs), permission-denied, or missing. "
                           f"First: {access_sample}"),
                "action": "info",
            })
        stderr_real = "\n".join(others).strip()
        if proc.returncode not in (0, 1) and stderr_real:
            results["details"].append({
                "file": "N/A", "threat": f"ClamAV error: {stderr_real[:200]}",
                "action": "error",
            })
        if progress_cb:
            progress_cb(progress_end, "ClamAV scan complete")
    except Exception as e:
        results["details"].append({
            "file": "N/A", "threat": f"ClamAV scan error: {e}", "action": "error",
        })
    finally:
        if file_list_path:
            try:
                os.unlink(file_list_path)
            except OSError:
                pass
        if stderr_path:
            try:
                os.unlink(stderr_path)
            except OSError:
                pass
    return results


def scan_custom_paths(scan_paths: list[str], quick: bool = False,
                      progress_cb: ProgressCb | None = None) -> dict[str, Any]:
    """Collect files under scan_paths and scan them with YARA + ClamAV.

    Qt-free re-implementation of ScanWorker's phases for headless use:
    budgets/skip-dirs/whitelists mirror scanner.py's collection rules.
    """
    results: dict[str, Any] = {
        "files_scanned": 0, "threats_found": 0, "details": [],
        "engines": {"yara": False, "clamav": False},
    }

    if quick:
        ext_set = QUICK_SCAN_EXTENSIONS
    else:
        ext_set = None

    all_files: list[str] = []
    for path in scan_paths:
        p = Path(path)
        if p.is_file():
            if _is_scannable(p, ext_set):
                all_files.append(str(p))
        elif p.is_dir():
            for root, dirnames, filenames in os.walk(p):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                # v2.0.2: don't descend into eCryptfs raw encrypted stores
                dirnames[:] = [d for d in dirnames
                               if os.path.join(str(root), d)
                               not in ("/home/.ecryptfs", "/.ecryptfs")]
                for fname in filenames:
                    f = Path(root) / fname
                    if not f.is_symlink() and f.is_file():
                        if _is_scannable(f, ext_set):
                            all_files.append(str(f))
                if progress_cb and len(all_files) % 2000 == 0 and all_files:
                    progress_cb(0, f"Collecting files... ({len(all_files)} found)")
    results["files_scanned"] = len(all_files)

    # ── YARA phase ────────────────────────────────────────────────────────
    try:
        import yara  # yara-python is a hard runtime dep (packaged in Depends)
    except ImportError:
        results["details"].append({
            "file": "N/A", "threat": "yara-python not installed", "action": "error",
        })
        yara = None

    rule_files = sorted(RULES_DIR.glob("*.yar")) if RULES_DIR.exists() else []
    linux_rule_files = [f for f in rule_files if "linux" in f.name]
    if not linux_rule_files:
        # fall back to any bundled rules
        linux_rule_files = [f for f in rule_files if f.name != "windows-malware-rules.yar"]
    if linux_rule_files and yara is not None:
        try:
            rule_paths = {f.stem: str(f) for f in linux_rule_files}
            compiled = yara.compile(filepaths=rule_paths)
            for idx, fp in enumerate(all_files):
                try:
                    # Distro-owned files are never auto-quarantined on a YARA
                    # keyword match — same policy as the GUI scanner path.
                    distro_owned = fp.startswith(("/usr/", "/bin/", "/sbin/",
                                                  "/lib/", "/lib64/",
                                                  "/opt/", "/boot/"))
                    if distro_owned:
                        try:
                            chk = subprocess.run(["dpkg", "-S", fp],
                                                 capture_output=True, timeout=10)
                            distro_owned = (chk.returncode == 0)
                        except Exception:
                            distro_owned = False
                    matches = compiled.match(fp)
                    for m in matches:
                        if distro_owned:
                            results["details"].append({
                                "file": fp,
                                "threat": f"YARA: {m.rule} (distro-owned file — review, no auto-quarantine)",
                                "action": "flag",
                            })
                            # flagged review items don't count as threats
                        else:
                            results["threats_found"] += 1
                            results["details"].append({
                                "file": fp, "threat": f"YARA: {m.rule}",
                                "action": "quarantine",
                            })
                except Exception:  # per-file error is non-fatal
                    continue
                if progress_cb and idx % 200 == 0:
                    progress_cb(int(0.5 * 50 * idx / max(len(all_files), 1)),
                                f"YARA: {idx}/{len(all_files)}")
            results["engines"]["yara"] = True
        except Exception as e:
            results["details"].append({
                "file": "N/A", "threat": f"YARA compile failed: {e}", "action": "error",
            })
    else:
        results["details"].append({
            "file": "N/A", "threat": "No YARA rules installed", "action": "info",
        })

    # ── ClamAV phase ──────────────────────────────────────────────────────
    clam_results = run_clamscan_on_files(
        all_files, progress_cb, progress_start=50, progress_end=100)
    # ADD, don't overwrite: when clamscan is unavailable the ClamAV result
    # carries 0 files, and overwriting here silently erased the YARA phase's
    # count (files_scanned reported 0 on clamscan-less hosts).
    results["files_scanned"] += clam_results["files_scanned"]
    results["threats_found"] += clam_results["threats_found"]
    results["details"].extend(clam_results["details"])
    if any(d.get("action") != "error" for d in clam_results["details"]) or \
            clam_results["files_scanned"]:
        results["engines"]["clamav"] = True

    return results


QUICK_SCAN_EXTENSIONS = frozenset({
    ".so", ".elf", ".bin", ".sh", ".bash", ".py", ".pl", ".rb",
    ".php", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".wsf", ".hta",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm",
    ".conf", ".service", ".desktop", ".timer", ".socket",
})

SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", ".cache", "cache",
    "snap", "flatpak", ".snap", ".var",
    ".mozilla", ".config/Microsoft", ".config/google-chrome",
    ".config/chromium", ".config/BraveSoftware", ".local/share/containers",
    ".local/share/Trash", ".local/share/baloo", ".local/share/akonadi",
    ".gvfs", ".Trash-0", ".Trash-1000",
    "proc", "sys", "dev", "run", "boot", "lost+found",
})


def _is_scannable(path: Path, ext_whitelist=None) -> bool:
    """File filter mirroring scanner.py's _is_scannable_file."""
    try:
        st = os.stat(path)
    except (OSError, PermissionError):
        return False
    if st.st_size == 0 or st.st_size > 250 * 1024 * 1024:
        return False
    import stat as _stat
    mode = st.st_mode
    if (_stat.S_ISCHR(mode) or _stat.S_ISBLK(mode)
            or _stat.S_ISFIFO(mode) or _stat.S_ISSOCK(mode)):
        return False
    if ext_whitelist is not None:
        ext = path.suffix.lower()
        if ext and ext not in ext_whitelist:
            return False
    return True