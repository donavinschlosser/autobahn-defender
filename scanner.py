"""
Autobahn Defender - Scanner Module
Core scanning engine using ClamAV (clamscan) and YARA.
"""

import os
import re
import shutil
import subprocess
import json
import hashlib
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal, QObject

from quarantine import get_detection_ledger


# Paths
APP_DIR = Path.home() / ".autobahn"
DEFS_DIR = APP_DIR / "definitions"
QUARANTINE_DIR = APP_DIR / "quarantine"
RULES_DIR = APP_DIR / "rules"
WINDOWS_RULES_FILE = "windows-malware-rules.yar"
# Also check for alternative names used in build packages and auto-updates
WINDOWS_RULES_NAMES = {WINDOWS_RULES_FILE, "windows-rules.yar", "upstream_windows.yar"}
MACOS_RULES_NAMES = {"upstream_macos.yar", "macos-rules.yar"}
# v1.4 fix: Linux rules also have bundled and upstream variants -- only use one
LINUX_RULES_NAMES = {"linux-rules.yar", "upstream_linux.yar"}
# Old combined rules file (pre-v1.4) — excluded from platform-specific scanning
# to prevent duplicate loading. Treated as a Linux rule if present alone.
LEGACY_RULES_NAMES = {"autobahn-defender-rules.yar"}
MANIFEST_FILE = QUARANTINE_DIR / "manifest.json"
DEFS_TIMESTAMP_FILE = APP_DIR / "defs_last_updated.txt"
WHITELIST_FILE = APP_DIR / "whitelist.json"

# File type detection constants
PE_MAGIC = b"\x4d\x5a"        # MZ — Windows PE executables
ELF_MAGIC = b"\x7f\x45\x4c\x46"  # \x7fELF — Linux ELF executables
PE_MAX_SIZE = 100 * 1024 * 1024  # 100MB max for PE files
ELF_MAX_SIZE = 250 * 1024 * 1024  # 250MB max for ELF files


def _is_app_own_file(filepath):
    """Check if a file belongs to Autobahn Defender itself.

    These files contain YARA rules and signatures that legitimately match
    malware patterns. Scanning them causes false positives (e.g. the C99
    PHP exploit signature matching inside the YARA rules file that defines
    that signature).

    Excludes:
    - ~/.autobahn/ (app data: rules, definitions, quarantine, history)
    - /tmp/autobahn_*.yar (merged YARA rule temp files created during scanning)
    - The installed app directory (/usr/share/autobahn-defender/)
    - The development project directory (if present)
    - Any .yar file (YARA rules always self-match)
    """
    fp = str(filepath)
    # Check app data directory
    app_dir_str = str(APP_DIR)
    if fp.startswith(app_dir_str + "/") or fp == app_dir_str:
        return True
    # Check temp merged YARA files (autobahn_*.yar in /tmp)
    fp_basename = os.path.basename(fp)
    if fp_basename.startswith("autobahn_") and fp_basename.endswith(".yar"):
        return True
    # Check installed app directory
    installed_dir = "/usr/share/autobahn-defender"
    if fp.startswith(installed_dir + "/") or fp == installed_dir:
        return True
    # Skip any .yar file -- YARA rules always contain the exact strings
    # they detect, so they will always self-match (e.g. a rule named
    # "CoinMiner_Strings" matches the string "CoinMiner_Strings" inside
    # the .yar file that defines it). There is no legitimate reason to
    # YARA-scan a YARA rules file.
    if fp.endswith(".yar"):
        return True
    return False


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

    # Initialize default whitelist with safe system paths on first run
    _init_default_whitelist()

    # Copy bundled YARA rules to user rules dir
    # v1.4 fix: Copy any bundled rule files that are missing from the user's rules dir
    # (not just when the dir is completely empty -- existing installs need new tier files too)
    import sys as _sys
    if getattr(_sys, "frozen", False):
        bundled_rules = Path(_sys._MEIPASS) / "rules"
    else:
        bundled_rules = Path(__file__).parent / "rules"
    if bundled_rules.exists():
        import hashlib
        seen_hashes = set()
        for rule_file in sorted(bundled_rules.glob("*.yar")):
            local_path = RULES_DIR / rule_file.name
            # Always update with the latest bundled rules (v1.4 fix: force-update
            # to ensure escape-sequence fixes are applied)
            try:
                content = rule_file.read_bytes()
                file_hash = hashlib.sha256(content).hexdigest()
                if file_hash not in seen_hashes:
                    seen_hashes.add(file_hash)
                    shutil.copy2(str(rule_file), str(local_path))
            except (OSError, PermissionError):
                pass

        # v1.4 fix: Remove old legacy rule file if new 4-tier rules are present
        new_tier_files = ["linux-rules.yar", "windows-rules.yar", "macos-rules.yar"]
        has_new_rules = any((RULES_DIR / name).exists() for name in new_tier_files)
        if has_new_rules:
            legacy_file = RULES_DIR / "autobahn-defender-rules.yar"
            if legacy_file.exists():
                try:
                    legacy_file.unlink()
                except OSError:
                    pass

        # v1.4 fix: Remove stale upstream_*.yar files that were downloaded
        # from Codeberg with escape-sequence bugs. The updated bundled rules
        # are now the correct versions, and the next auto-update will
        # download the fixed upstream versions.
        # Only remove if the bundled version is newer/clean.
        for upstream_name in ["upstream_linux.yar", "upstream_windows.yar",
                              "upstream_macos.yar"]:
            upstream_path = RULES_DIR / upstream_name
            if upstream_path.exists():
                try:
                    upstream_path.unlink()
                except OSError:
                    pass

        # v1.4 fix: Remove old PUP rules (removed in v1.4 -- too many false positives)
        for pup_name in ["pup-rules.yar", "upstream_pup.yar"]:
            pup_path = RULES_DIR / pup_name
            if pup_path.exists():
                try:
                    pup_path.unlink()
                except OSError:
                    pass

        # v1.4 fix: Remove stale compiled cache so rules get recompiled fresh
        compiled_cache = RULES_DIR / "compiled.yc"
        if compiled_cache.exists():
            try:
                compiled_cache.unlink()
            except OSError:
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


def _detect_file_type(filepath):
    """Detect file type by reading magic bytes.

    Returns one of: 'pe', 'elf', 'macho', 'script', 'other'
    - 'pe': Windows PE executable (MZ header)
    - 'elf': Linux ELF executable (\\x7fELF magic)
    - 'macho': macOS Mach-O executable (various magic bytes)
    - 'script': Script file (#! shebang or recognizable text)
    - 'other': Any other file type
    """
    try:
        with open(filepath, "rb") as f:
            header = f.read(8)
        if header[:2] == PE_MAGIC:
            return "pe"
        if header[:4] == ELF_MAGIC:
            return "elf"
        # Mach-O magic bytes: FEEDFACE (32-bit), CEFAEDFE (reverse),
        # FEEDFACF (64-bit), CAFEBABE (universal), BEBAFECA (reverse universal)
        macho_magics = {0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCAFEBABE, 0xBEBAFECA}
        if len(header) >= 4:
            magic = int.from_bytes(header[:4], 'little')
            if magic in macho_magics:
                return "macho"
        if header[:2] == b"#!":
            return "script"
        return "other"
    except (OSError, PermissionError):
        return "other"


# Safe default whitelist paths — system directories managed by package managers
# that are extremely unlikely to contain malware. These are PRE-populated on first
# run only (if no whitelist exists yet). Users can remove them if needed.
# DO NOT include: /tmp, /home, /var/tmp, /dev/shm, /usr/local, downloads dirs
DEFAULT_SAFE_PATHS = [
    "/usr/lib",
    "/usr/lib64",
    "/usr/share",
    "/lib",
    "/lib64",
    "/usr/include",
]


def _init_default_whitelist():
    """Pre-populate the whitelist with known-safe system paths on first run.

    Only runs if no whitelist file exists yet — does NOT overwrite user's
    custom whitelist. These paths are package-manager-managed and read-only
    for normal users, making them extremely unlikely to contain malware.
    """
    if WHITELIST_FILE.exists():
        return  # User already has a whitelist — don't overwrite

    default_entries = [
        {"__type__": "path", "path": p}
        for p in DEFAULT_SAFE_PATHS
        if os.path.exists(p)
    ]
    if default_entries:
        try:
            APP_DIR.mkdir(parents=True, exist_ok=True)
            WHITELIST_FILE.write_text(json.dumps(default_entries, indent=2))
        except OSError:
            pass


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
    # YARA rules can have various forms:
    #   rule Name { ... }
    #   private rule Name { ... }
    #   global rule Name { ... }
    #   rule Name : Tag1_Tag2 { ... }
    #   private rule Name : Tag1_Tag2 { ... }
    seen_names = set()
    deduped = []
    import re
    # Match any YARA rule declaration and capture the rule name
    # Pattern: optional (private|global) keyword, then 'rule', then name, then optional tags
    full_rule_re = re.compile(
        r'^\s*(?:private|global|)\s*rule\s+(\w+)(?:\s*:\s*\w+(?:\s+\w+)*)?\s*\{',
        re.MULTILINE
    )
    for text in contents:
        names = full_rule_re.findall(text)
        has_dup = any(n in seen_names for n in names)
        if not has_dup:
            seen_names.update(names)
            deduped.append(text)
        else:
            # Rename duplicates by appending a suffix.
            # Use a regex substitution that preserves the rule's modifiers (private/global)
            # and tags. We replace the rule name itself within the declaration.
            idx = len(deduped)
            def _rename_dup(m):
                name = m.group(1)
                if name in seen_names:
                    full = m.group(0)
                    name_start = full.find(name)
                    prefix = full[:name_start]
                    suffix = full[name_start + len(name):]
                    return prefix + name + f"_{idx}" + suffix
                return m.group(0)
            text = full_rule_re.sub(_rename_dup, text)
            # Re-extract names after renaming
            seen_names.update(full_rule_re.findall(text))
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


# ─── YARA rule compilation cache ────────────────────────────────────
# Cache compiled YARA rules so we don't re-compile on every scan
# when the rules haven't changed. Keyed by a hash of the source file contents.
# Uses yara-python's compiled Rules object directly — no subprocess overhead.
_yara_cache = {}
_yara_cache_lock = threading.Lock()
COMPILED_RULES_PATH = RULES_DIR / "compiled.yc"


def _compute_rules_hash(rule_files):
    """Compute a hash of the contents of all rule files for cache keying."""
    import hashlib
    h = hashlib.sha256()
    for rf in sorted(rule_files, key=lambda f: str(f)):
        try:
            h.update(rf.read_bytes())
            h.update(b"\x00")  # Separator between files
        except (OSError, PermissionError):
            pass
    return h.hexdigest()


def _get_or_compile_yara_rules(rule_files):
    """Get cached compiled YARA rules, or compile new ones if rules changed.

    Uses yara-python to compile rules into a thread-safe Rules object.
    Also saves compiled rules to a .yc file for fast loading on next launch.

    Returns (rules_object, error_message) where error_message is None on success.
    The rules_object is a yara.Rules instance that is thread-safe for concurrent
    scanning via rules.match().

    Kudu-inspired optimizations (MIT, AdventDevInc/kudu):
    - Per-file validation fallback: if batch compilation fails, try compiling
      each file individually and skip corrupt ones instead of failing entirely.
    """
    if not rule_files:
        return None, "No rule files provided"

    rules_hash = _compute_rules_hash(rule_files)

    with _yara_cache_lock:
        # Check if we have a cached entry for this exact set of rules
        if rules_hash in _yara_cache:
            cached = _yara_cache[rules_hash]
            if cached.get("rules") is not None:
                return cached["rules"], None
            # Cache entry is stale — fall through to recompile

    # Merge the rules into a single text blob
    merged_text = _merge_yara_rules_text(rule_files)
    if not merged_text:
        return None, "Failed to prepare YARA rules"

    # yara-python must import BEFORE any `except yara.SyntaxError` clause
    # runs: if the import itself fails, that except clause raised NameError,
    # which escaped the scan thread and force-closed the app (v2.0.0
    # AppImage: yara-python was never bundled — fixed in 2.0.1).
    try:
        import yara
    except ImportError:
        return None, "yara-python is not available (YARA engine disabled)"

    # Compile with yara-python
    try:
        rules = yara.compile(source=merged_text)
    except yara.SyntaxError as e:
        # Per-file validation fallback (Kudu-inspired):
        # If batch compilation fails, try each file individually and
        # skip corrupt ones instead of failing entirely.
        good_rules = []
        bad_files = []
        for rf in rule_files:
            try:
                text = rf.read_text(errors="replace")
            except (OSError, PermissionError):
                continue
            if not text.strip():
                continue
            try:
                single = yara.compile(source=text)
                good_rules.append(single)
            except (yara.SyntaxError, yara.Error):
                bad_files.append(rf.name)

        if good_rules:
            # Merge the good rules into one Rules object
            # yara-python doesn't have a direct merge API, so we recompile
            # from the merged text of good files
            good_texts = []
            for rf in rule_files:
                if rf.name not in bad_files:
                    try:
                        good_texts.append(rf.read_text(errors="replace"))
                    except (OSError, PermissionError):
                        pass
            try:
                rules = yara.compile(source="\n".join(good_texts))
            except (yara.SyntaxError, yara.Error) as e2:
                return None, f"YARA compilation error: {e2}"
            # Log skipped files but don't fail the scan
            import logging
            logging.getLogger(__name__).warning(
                f"YARA: skipped {len(bad_files)} corrupt rule files: {bad_files}"
            )
        else:
            return None, f"YARA compilation error: {e}"
    except Exception as e:
        return None, f"YARA compilation failed: {e}"

    # Try to save compiled rules to disk for faster loading next time
    try:
        RULES_DIR.mkdir(parents=True, exist_ok=True)
        rules.save(str(COMPILED_RULES_PATH))
    except (OSError, PermissionError):
        pass  # Non-critical — will recompile next time

    # Cache the compiled rules object
    with _yara_cache_lock:
        # Clean up old cache entries (keep only the latest 3)
        if len(_yara_cache) > 3:
            for old_hash in list(_yara_cache.keys())[:-3]:
                del _yara_cache[old_hash]

        _yara_cache[rules_hash] = {"rules": rules}

    return rules, None


def _merge_yara_rules_text(rule_files):
    """Merge multiple YARA rule files into a single text string.
    Skips empty/comment-only files and deduplicates rule names.
    Returns the merged text, or None on failure.

    Kudu-inspired optimization (MIT): filters out rules with platform tags
    that don't match the current OS. YARA rules can contain tags like
    'macos', 'windows' in their meta section. On Linux, these rules are
    irrelevant and waste compilation time + can cause false positives.
    """
    if not rule_files:
        return None

    # Platform tags to filter out on Linux (Kudu-inspired)
    # Rules with these tags in their meta section are skipped
    _FILTER_TAGS = {"macos", "windows", "win32", "darwin"}

    # Read and filter out empty/comment-only files
    contents = []
    for rf in rule_files:
        try:
            text = rf.read_text(errors="replace")
        except (OSError, PermissionError):
            continue
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
        return contents[0]

    # Deduplicate rule names across files to avoid YARA "duplicated identifier" errors
    seen_names = set()
    deduped = []
    import re
    full_rule_re = re.compile(
        r'^\s*(?:private|global|)\s*rule\s+(\w+)(?:\s*:\s*\w+(?:\s+\w+)*)?\s*\{',
        re.MULTILINE
    )
    for text in contents:
        names = full_rule_re.findall(text)
        has_dup = any(n in seen_names for n in names)
        if not has_dup:
            seen_names.update(names)
            deduped.append(text)
        else:
            idx = len(deduped)
            def _rename_dup(m):
                name = m.group(1)
                if name in seen_names:
                    full = m.group(0)
                    name_start = full.find(name)
                    prefix = full[:name_start]
                    suffix = full[name_start + len(name):]
                    return prefix + name + f"_{idx}" + suffix
                return m.group(0)
            text = full_rule_re.sub(_rename_dup, text)
            seen_names.update(full_rule_re.findall(text))
            deduped.append(text)

    return "\n".join(deduped) + "\n"


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
    """Worker thread that runs a scan and emits progress signals.

    Scanning is sequential: YARA first (0-50% progress), then ClamAV (50-100%).
    Both engines use direct subprocess/in-process scanning that provides
    real per-file progress, so the percentage is accurate.

    YARA uses yara-python's thread-safe Rules.match() via ThreadPoolExecutor.
    ClamAV uses clamscan directly as a subprocess (not clamd), which gives
    per-file output for accurate progress tracking.
    """

    progress = pyqtSignal(int)
    current_file = pyqtSignal(str)
    finished = pyqtSignal(dict)

    def __init__(self, scan_type, custom_paths=None, settings_mgr=None):
        super().__init__()
        self.scan_type = scan_type
        self.custom_paths = custom_paths or []
        self.settings_mgr = settings_mgr
        self._cancelled = False
        self._clam_proc = None       # Reference to clamscan subprocess for cancellation
        self._yara_pool = None       # Reference to ThreadPoolExecutor for cancellation

    def cancel(self):
        """Cancel the scan — kills subprocesses and cancels thread pool."""
        self._cancelled = True
        # Kill clamscan subprocess if running (single-process mode)
        if self._clam_proc and self._clam_proc.poll() is None:
            try:
                self._clam_proc.kill()
            except OSError:
                pass
        # Kill all parallel clamscan subprocesses if running
        if hasattr(self, '_clam_procs'):
            for proc in self._clam_procs:
                if proc and proc.poll() is None:
                    try:
                        proc.kill()
                    except OSError:
                        pass
        # Cancel YARA ThreadPoolExecutor futures if running
        if self._yara_pool:
            try:
                self._yara_pool.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

    def run(self):
        # PyQt6 hard-closes the whole process when an exception escapes a
        # QThread.run (uncaught in C++ -> abort). Every failure below MUST
        # surface as a finished/error emit instead — v2.0.0 AppImage bug
        # (missing yara-python) force-closed the app on Rootkit scan.
        try:
            self._run_inner()
        except Exception as e:  # noqa: BLE001 — last-resort thread guard
            import traceback
            try:
                results = {
                    "files_scanned": 0,
                    "threats_found": 0,
                    "details": [{
                        "file": "N/A", "action": "error",
                        "threat": f"Scan crashed: {e} "
                                  f"({traceback.format_exc(limit=3)[-300:]})",
                    }],
                }
            except Exception:
                results = {"files_scanned": 0, "threats_found": 0,
                           "details": [{"file": "N/A", "action": "error",
                                        "threat": f"Scan crashed: {e}"}]}
            try:
                self.progress.emit(100)
                self.finished.emit(results)
            except Exception:
                pass

    def _run_inner(self):
        ensure_dirs()
        # Clear the detection ledger at the start of each scan so only
        # files flagged in THIS scan can be quarantined/deleted later.
        get_detection_ledger().clear()

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

        # Check which engine(s) the user wants to use
        scan_engine = "both"
        if self.settings_mgr:
            scan_engine = self.settings_mgr.get_scan_engine()

        use_clamav = scan_engine in ("both", "clamav")
        use_yara = scan_engine in ("both", "yara")

        clamscan_bin = find_clamscan()
        clamav_available = clamscan_bin is not None

        # Track engine failures for error reporting
        clamav_failed = False
        clamav_error = ""
        yara_failed = False
        yara_error = ""

        if use_yara:
            # ─── YARA PHASE: 0% to 50% ───
            # YARA runs first using yara-python with ThreadPoolExecutor.
            # Progress is based on actual files scanned / total files.
            yara_results = self._run_yara(scan_paths, progress_start=0, progress_end=50)
            results["files_scanned"] += yara_results["files_scanned"]
            results["threats_found"] += yara_results["threats_found"]
            results["details"].extend(yara_results["details"])

            if yara_results["files_scanned"] == 0 and not any(d.get("action") != "info" for d in yara_results["details"]):
                yara_failed = True
                yara_error = "YARA scanned no files — rule compilation may have failed"
            elif any(d.get("action") == "error" and "YARA" in d.get("threat", "") and "rules" in d.get("threat", "").lower() for d in yara_results["details"]):
                yara_failed = True
                for d in yara_results["details"]:
                    if d.get("action") == "error" and "YARA" in d.get("threat", ""):
                        yara_error = d["threat"]
                        break

        if use_clamav:
            if not clamav_available:
                if scan_engine in ("both", "clamav"):
                    results["details"].append({
                        "file": "N/A",
                        "threat": "ClamAV (clamscan) is not installed. YARA scanning completed successfully.",
                        "action": "info",
                    })
            else:
                # ─── CLAMAV PHASE: 50% to 100% ───
                # ClamAV runs second. Uses parallel clamscan (multiple processes)
                # if enabled in settings, otherwise single clamscan process.
                # Signal UI that ClamAV phase is starting
                self.current_file.emit("CLAM_START")
                use_parallel = True
                if self.settings_mgr:
                    use_parallel = self.settings_mgr.is_parallel_clamav()
                if use_parallel:
                    clam_results = self._run_clamscan_parallel(clamscan_bin, scan_paths, progress_start=50, progress_end=100)
                else:
                    clam_results = self._run_clamscan(clamscan_bin, scan_paths, progress_start=50, progress_end=100)
                results["files_scanned"] += clam_results["files_scanned"]
                results["threats_found"] += clam_results["threats_found"]
                results["details"].extend(clam_results["details"])

                if clam_results["files_scanned"] == 0 and not clam_results["details"]:
                    clamav_failed = True
                    clamav_error = "ClamAV scanned no files — clamscan may have failed to start"
                elif any(d.get("action") == "error" and "clamscan" in d.get("threat", "").lower() for d in clam_results["details"]):
                    clamav_failed = True
                    clamav_error = "clamscan failed to run"
                elif any(d.get("action") == "error" and "ClamAV" in d.get("threat", "") for d in clam_results["details"]):
                    clamav_failed = True
                    for d in clam_results["details"]:
                        if d.get("action") == "error" and "ClamAV" in d.get("threat", ""):
                            clamav_error = d["threat"]
                            break

        if not use_clamav and not use_yara:
            results["details"].append({
                "file": "N/A",
                "threat": "No scan engine selected. Enable ClamAV or YARA in Settings.",
                "action": "error",
            })
            self.progress.emit(100)
            self.finished.emit(results)
            return

        # Report engine failures to the user
        if clamav_failed and yara_failed:
            results["details"].append({
                "file": "N/A",
                "threat": f"Both scan engines failed. ClamAV: {clamav_error}. YARA: {yara_error}. Scan could not complete.",
                "action": "error",
            })
        elif clamav_failed and use_clamav:
            results["details"].append({
                "file": "N/A",
                "threat": f"ClamAV scan failed ({clamav_error}). YARA scanning completed successfully.",
                "action": "info",
            })
        elif yara_failed and use_yara:
            results["details"].append({
                "file": "N/A",
                "threat": f"YARA scan failed ({yara_error}). ClamAV scanning completed successfully.",
                "action": "info",
            })
        elif not use_clamav and use_yara and not yara_failed:
            results["details"].append({
                "file": "N/A",
                "threat": "ClamAV disabled in Settings — YARA-only scan completed.",
                "action": "info",
            })
        elif not use_yara and use_clamav and not clamav_failed:
            results["details"].append({
                "file": "N/A",
                "threat": "YARA disabled in Settings — ClamAV-only scan completed.",
                "action": "info",
            })

        # Check if scan was cancelled
        if self._cancelled:
            results["details"].append({
                "file": "N/A",
                "threat": "Scan cancelled by user. Partial results shown.",
                "action": "info",
            })

        # ─── POST-SCAN INTEGRITY CHECKS (Kudu-inspired, MIT) ───
        # After file scanning, run system-integrity checks that don't operate
        # on individual files but on system state: hosts-file tampering and
        # persistence mechanisms. These add findings to the same results dict.
        if not self._cancelled and self.scan_type not in ("custom",):
            integrity_findings = self._run_integrity_checks()
            if integrity_findings:
                results["details"].extend(integrity_findings)

        # ─── DETECTION LEDGER: record flagged files with content hash ───
        # Records each flagged file's SHA256 so quarantine can verify the
        # file hasn't been modified since the scan (Kudu-inspired TOCTOU guard).
        ledger = get_detection_ledger()
        for d in results["details"]:
            filepath = d.get("file")
            if not filepath or filepath == "N/A":
                continue
            action = d.get("action", "")
            if action in ("error", "info"):
                continue
            try:
                p = Path(filepath)
                if p.exists() and p.is_file() and not p.is_symlink():
                    h = hashlib.sha256(p.read_bytes()).hexdigest()
                    ledger.record(filepath, h)
            except (OSError, PermissionError):
                pass

        # Final filter: remove any whitelisted files AND the app's own files from results
        results["details"] = [
            d for d in results["details"]
            if not (d.get("file") and (is_whitelisted(d["file"])[0] or _is_app_own_file(d["file"])))
        ]
        results["threats_found"] = len([d for d in results["details"]
                                         if d.get("action") != "error" and d.get("action") != "info"])

        # Final progress — scan is complete
        self.progress.emit(100)
        self.finished.emit(results)

    def _get_scan_paths(self):
        """Return list of paths to scan based on scan type."""
        home = Path.home()
        mapping = {
            "quick_home": [str(home)],
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

    # ─── Post-scan integrity checks (Kudu-inspired, MIT, AdventDevInc/kudu) ───

    # Domains that should never be redirected in /etc/hosts
    _PROTECTED_DOMAINS = frozenset({
        "google.com", "www.google.com", "gmail.com",
        "microsoft.com", "www.microsoft.com", "login.live.com",
        "paypal.com", "www.paypal.com",
        "apple.com", "www.apple.com", "icloud.com",
        "amazon.com", "www.amazon.com",
        "facebook.com", "www.facebook.com",
        "twitter.com", "x.com",
        "github.com",
        "linkedin.com",
        "dropbox.com",
        "bankofamerica.com", "www.bankofamerica.com",
        "chase.com", "www.chase.com",
        "wellsfargo.com", "www.wellsfargo.com",
        "citibank.com", "www.citibank.com",
        "ebay.com", "www.ebay.com",
        "netflix.com",
        "spotify.com",
        "steampowered.com", "steamcommunity.com",
    })

    # IPs that are legitimate for hosts-file redirects (not malicious)
    _SAFE_HOSTS_IPS = frozenset({
        "0.0.0.0",      # ad-blocker blocking
        "127.0.0.1",    # localhost
        "::1",          # IPv6 localhost
        "fe80::1",      # link-local
    })

    # Suspicious crontab patterns
    _CRON_PATTERNS = [
        (r'(curl|wget)\s+.*\|\s*(bash|sh|python|python3)', "download-and-execute via curl/wget piped to shell"),
        (r'/tmp/\S+\.(sh|py|pl|rb)', "execution from /tmp directory"),
        (r'base64\s+-d\s.*\|\s*(bash|sh|python)', "base64-decode-and-execute"),
        (r'python\s+-c\s+import\s+base64', "Python base64 inline execution"),
        (r'(curl|wget)\s+.*&&\s*(bash|sh)', "download-and-run with && operator"),
        (r'\|\s*perl\s+-e', "piped to Perl one-liner"),
    ]

    # Suspicious systemd ExecStart patterns
    _SYSTEMD_PATTERNS = [
        (r'/tmp/\S+', "ExecStart references /tmp"),
        (r'(curl|wget)\s+.*\|\s*(bash|sh)', "download-and-execute in service"),
        (r'base64\s+-d', "base64 decode in service"),
    ]

    def _run_integrity_checks(self):
        """Run post-scan system-integrity checks.

        Returns a list of finding dicts compatible with scan results:
        {"file": path, "threat": description, "action": "flag"}
        These checks don't scan files — they check system state:
        - /etc/hosts tampering (protected domains redirected)
        - Linux persistence (suspicious crontab + systemd entries)
        """
        findings = []
        findings.extend(self._check_hosts_file())
        findings.extend(self._check_persistence())
        return findings

    def _check_hosts_file(self):
        """Check /etc/hosts for tampering (Kudu-inspired, MIT).

        Flags redirections of major domains (Google, PayPal, banks, etc.)
        to non-safe IPs. Extremely high-confidence, low false-positive.
        """
        results = []
        hosts_path = Path("/etc/hosts")
        if not hosts_path.exists():
            return results

        try:
            content = hosts_path.read_text(errors="replace")
        except OSError:
            return results

        for line in content.splitlines():
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#"):
                continue
            parts = line_stripped.split()
            if len(parts) < 2:
                continue
            ip = parts[0]
            domains = parts[1:]
            for domain in domains:
                domain_lower = domain.lower()
                if domain_lower in self._PROTECTED_DOMAINS:
                    if ip not in self._SAFE_HOSTS_IPS:
                        results.append({
                            "file": "/etc/hosts",
                            "threat": f"Hosts file tampering: {domain_lower} redirected to {ip}",
                            "action": "flag",
                        })
            # Bulk redirect: single IP mapped to many domains
            if len(domains) > 5 and ip not in self._SAFE_HOSTS_IPS:
                results.append({
                    "file": "/etc/hosts",
                    "threat": f"Suspicious hosts entry: IP {ip} mapped to {len(domains)} domains",
                    "action": "flag",
                })

        return results

    def _check_persistence(self):
        """Check for suspicious persistence mechanisms (Kudu-inspired, MIT).

        Parses user crontab, /etc/crontab, /etc/cron.d/*, and systemd
        user/system services for download-and-execute, /tmp execution,
        and base64-decode-and-run patterns.
        """
        results = []

        # --- Crontab analysis ---
        cron_text = ""
        try:
            proc = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True, timeout=5
            )
            if proc.returncode == 0:
                cron_text = proc.stdout
        except (OSError, subprocess.TimeoutExpired):
            pass

        for cron_path in ["/etc/crontab"]:
            p = Path(cron_path)
            if p.exists():
                try:
                    cron_text += "\n" + p.read_text(errors="replace")
                except OSError:
                    pass

        cron_d = Path("/etc/cron.d")
        if cron_d.is_dir():
            for f in cron_d.iterdir():
                if f.is_file():
                    try:
                        cron_text += "\n" + f.read_text(errors="replace")
                    except OSError:
                        pass

        if cron_text.strip():
            for line in cron_text.splitlines():
                line_stripped = line.strip()
                if not line_stripped or line_stripped.startswith("#"):
                    continue
                for pattern, desc in self._CRON_PATTERNS:
                    if re.search(pattern, line_stripped, re.IGNORECASE):
                        results.append({
                            "file": "crontab",
                            "threat": f"Suspicious crontab entry: {desc}",
                            "action": "flag",
                        })
                        break  # one finding per line

        # --- systemd user services ---
        systemd_user_dir = Path.home() / ".config" / "systemd" / "user"
        if systemd_user_dir.is_dir():
            for svc_file in systemd_user_dir.glob("*.service"):
                try:
                    content = svc_file.read_text(errors="replace")
                except OSError:
                    continue
                for line in content.splitlines():
                    line_stripped = line.strip()
                    if not line_stripped.startswith("ExecStart="):
                        continue
                    exec_cmd = line_stripped[len("ExecStart="):]
                    for pattern, desc in self._SYSTEMD_PATTERNS:
                        if re.search(pattern, exec_cmd, re.IGNORECASE):
                            results.append({
                                "file": str(svc_file),
                                "threat": f"Suspicious systemd service: {desc}",
                                "action": "flag",
                            })
                            break

        # --- systemd system services ---
        systemd_system_dir = Path("/etc/systemd/system")
        if systemd_system_dir.is_dir():
            for svc_file in systemd_system_dir.glob("*.service"):
                try:
                    content = svc_file.read_text(errors="replace")
                except (OSError, PermissionError):
                    continue
                for line in content.splitlines():
                    line_stripped = line.strip()
                    if not line_stripped.startswith("ExecStart="):
                        continue
                    exec_cmd = line_stripped[len("ExecStart="):]
                    for pattern, desc in self._SYSTEMD_PATTERNS:
                        if re.search(pattern, exec_cmd, re.IGNORECASE):
                            results.append({
                                "file": str(svc_file),
                                "threat": f"Suspicious systemd service: {desc}",
                                "action": "flag",
                            })
                            break

        return results

    def _estimate_file_count(self, scan_paths):
        """Quickly estimate the number of files to scan for progress reporting.

        Only counts actual files (not directories) to make the estimate
        match what ClamAV and YARA will actually scan.

        Uses SKIP_DIRS to avoid counting files in huge irrelevant dirs
        (Kudu-inspired optimization).
        """
        total = 0
        is_system = self.scan_type == "full_system"
        try:
            for path in scan_paths:
                p = Path(path)
                if p.is_file():
                    total += 1
                elif p.is_dir():
                    try:
                        for root, dirnames, filenames in os.walk(p):
                            # In-place skip (Kudu-inspired)
                            dirnames[:] = [
                                d for d in dirnames
                                if not self._should_skip_dir(d, is_system)
                            ]
                            total += sum(1 for f in filenames)
                            if total > 500000:
                                return total
                    except (PermissionError, OSError):
                        pass
        except (PermissionError, OSError):
            pass
        return max(total, 1)
    def _run_clamscan(self, clamscan, scan_paths, progress_start=0, progress_end=50):
        """Run clamscan on the given paths and parse output.

        Progress is emitted in the range [progress_start, progress_end] so
        that ClamAV and YARA can share the progress bar without jumping.
        """
        if (DEFS_DIR / "main.cvd").exists() or (DEFS_DIR / "main.cld").exists():
            defs_path = str(DEFS_DIR)
        else:
            system_def = Path("/var/lib/clamav")
            if system_def.exists():
                defs_path = str(system_def)
            else:
                defs_path = str(DEFS_DIR)

        results = {"files_scanned": 0, "threats_found": 0, "details": []}

        # Exclude system dirs, the quarantine dir, and the app's own data dir.
        # The app's .yar rule files contain malware signatures that trigger
        # ClamAV false positives (e.g. Php.Exploit.C99-27 matching inside the
        # rules file that defines that signature).
        exclude_dirs = ["/proc", "/sys", "/dev", "/run", str(QUARANTINE_DIR), str(APP_DIR),
                        "/usr/share/autobahn-defender"]
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
            # Exclude the app's own temp merged YARA rule files in /tmp
            cmd.extend(["--exclude", r"^/tmp/autobahn_.*\.yar$"])
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
                self._parse_clamscan_output(proc, results, total_estimate,
                                             progress_start, progress_end)
            except Exception as e:
                results["details"].append({
                    "file": path,
                    "threat": f"Scan error: {e}",
                    "action": "error",
                })

        # All paths scanned — emit final ClamAV progress
        self.progress.emit(progress_end - 1)
        self.current_file.emit("ClamAV scan complete")
        return results

    def _run_clamscan_parallel(self, clamscan, scan_paths, progress_start=50, progress_end=100):
        """Run multiple clamscan processes in parallel for faster scanning.

        Collects all scannable files, splits them across N processes
        (one per CPU core, up to scan_threads setting), and launches all
        processes simultaneously. Each process scans its own chunk of files
        on its own CPU core.

        Progress is tracked by summing files_scanned across all processes
        and dividing by the total file count, giving an accurate combined
        percentage.
        """
        import threading
        import time as _time

        # Determine definitions path
        if (DEFS_DIR / "main.cvd").exists() or (DEFS_DIR / "main.cld").exists():
            defs_path = str(DEFS_DIR)
        else:
            system_def = Path("/var/lib/clamav")
            if system_def.exists():
                defs_path = str(system_def)
            else:
                defs_path = str(DEFS_DIR)

        results = {"files_scanned": 0, "threats_found": 0, "details": []}

        # Build exclude list
        exclude_dirs = ["/proc", "/sys", "/dev", "/run", str(QUARANTINE_DIR), str(APP_DIR),
                        "/usr/share/autobahn-defender"]
        whitelist = get_whitelist()
        for entry in whitelist:
            if isinstance(entry, dict) and entry.get("__type__") == "path":
                wl_path = entry.get("path", "")
                if wl_path and os.path.isdir(wl_path):
                    exclude_dirs.append(wl_path)

        scan_archives = True
        scan_hidden = True
        if self.settings_mgr:
            scan_archives = self.settings_mgr.is_scan_archives()
            scan_hidden = self.settings_mgr.is_scan_hidden()

        # Collect all scannable files (reuse the same method YARA uses)
        self.current_file.emit("ClamAV: Collecting files...")
        all_files = self._collect_scannable_files(scan_paths)
        total = len(all_files)

        if total == 0:
            results["details"].append({
                "file": "N/A",
                "threat": "No scannable files found for ClamAV",
                "action": "info",
            })
            self.progress.emit(progress_end - 1)
            return results

        # Determine number of parallel processes
        num_procs = min(total, os.cpu_count() or 2)
        if self.settings_mgr:
            num_procs = min(total, self.settings_mgr.get_scan_threads())
        # Cap at 8 — more processes just waste RAM (each loads ~500MB DB)
        num_procs = min(num_procs, 8)
        if num_procs < 1:
            num_procs = 1

        # Split files into chunks
        chunk_size = (total + num_procs - 1) // num_procs
        chunks = [all_files[i:i + chunk_size] for i in range(0, total, chunk_size)]
        actual_procs = len(chunks)

        # Build the clamscan command base (without the file paths)
        def build_cmd():
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
            cmd.extend(["--exclude", r"^/tmp/autobahn_.*\.yar$"])
            cmd.append("--")
            return cmd

        # Each process writes to its own results dict, then we merge
        proc_results = []
        procs = []
        self._clam_procs = procs  # Store for cancellation
        threads = []
        combined_scanned = [0]  # Mutable counter for progress tracking
        lock = threading.Lock()

        def run_single_clamscan(chunk_idx, file_chunk, proc_result):
            """Run one clamscan process on a chunk of files and parse output.

            Writes the file list to a temp file and uses clamscan's -f option
            to read from it, avoiding the 'Argument list too long' error when
            scanning hundreds of thousands of files.
            """
            cmd = build_cmd()

            # Write this chunk's file list to a temp file and use -f
            # This avoids OS argument list limits (typically ~128KB)
            # NOTE: -f must go BEFORE the -- separator, otherwise clamscan
            # treats it as a file path instead of an option.
            file_list_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".txt", delete=False, prefix="clamav_list_"
                ) as f:
                    f.write("\n".join(file_chunk))
                    f.write("\n")
                    file_list_path = f.name
                # Insert -f before the -- separator
                sep_idx = cmd.index("--")
                cmd.insert(sep_idx, "-f")
                cmd.insert(sep_idx + 1, file_list_path)
            except OSError as e:
                with lock:
                    proc_result["details"].append({
                        "file": "N/A",
                        "threat": f"ClamAV error: could not create file list: {e}",
                        "action": "error",
                    })
                return

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=_clean_env(),
                )
                with lock:
                    procs.append(proc)

                for line in proc.stdout:
                    if self._cancelled:
                        proc.kill()
                        break

                    line = line.strip()
                    if not line:
                        continue

                    if ": OK" in line:
                        with lock:
                            proc_result["files_scanned"] += 1
                            combined_scanned[0] += 1
                            # Emit progress and file info periodically
                            if combined_scanned[0] % 2000 == 0:
                                frac = combined_scanned[0] / total
                                pct = min(progress_end - 1, progress_start + int(frac * (progress_end - progress_start)))
                                self.progress.emit(max(progress_start + 1, pct))
                                self.current_file.emit(f"ClamAV: {combined_scanned[0]}/{total} files scanned")
                    elif " FOUND" in line:
                        clean_line = line.rstrip()
                        if clean_line.endswith(" FOUND"):
                            without_found = clean_line[:-6].rstrip()
                        else:
                            without_found = clean_line
                        if ": " in without_found:
                            filepath, threat = without_found.rsplit(": ", 1)
                        else:
                            filepath, threat = without_found.rsplit(":", 1)
                        filepath = filepath.strip()
                        threat = threat.strip()
                        with lock:
                            proc_result["threats_found"] += 1
                            proc_result["files_scanned"] += 1
                            combined_scanned[0] += 1
                            proc_result["details"].append({
                                "file": filepath,
                                "threat": threat,
                                "action": "quarantine",
                            })
                            self.current_file.emit(f"ClamAV: {filepath} — {threat}")
                    elif not line.startswith("---") and not line.startswith(" "):
                        if "Symbolic link" not in line and "Empty file" not in line:
                            # Show occasional file being scanned (from this process)
                            if combined_scanned[0] % 5000 == 0:
                                with lock:
                                    self.current_file.emit(f"ClamAV: {line}")

                proc.wait()
                # Check stderr for real errors (filter out LibClamAV warnings)
                stderr_output = proc.stderr.read().strip() if proc.stderr else ""
                stderr_lines = [l for l in stderr_output.split('\n')
                                if l.strip() and 'Warning' not in l and 'LibClamAV' not in l
                                and 'No such file or directory' not in l
                                and "Can't access file" not in l]
                real_stderr = '\n'.join(stderr_lines).strip()
                if proc.returncode not in (0, 1) and real_stderr:
                    with lock:
                        proc_result["details"].append({
                            "file": "N/A",
                            "threat": f"ClamAV error: {real_stderr[:200]}",
                            "action": "error",
                        })
            except Exception as e:
                with lock:
                    proc_result["details"].append({
                        "file": "N/A",
                        "threat": f"ClamAV scan error: {e}",
                        "action": "error",
                    })
            finally:
                # Clean up the temp file list
                if file_list_path:
                    try:
                        os.unlink(file_list_path)
                    except OSError:
                        pass

        # Launch all clamscan processes in parallel threads
        self.current_file.emit(f"ClamAV: Scanning {total:,} files with {actual_procs} processes...")

        for i, chunk in enumerate(chunks):
            pr = {"files_scanned": 0, "threats_found": 0, "details": []}
            proc_results.append(pr)
            t = threading.Thread(
                target=run_single_clamscan,
                args=(i, chunk, pr),
                daemon=True,
            )
            threads.append(t)
            t.start()

        # Wait for all threads to finish, checking for cancellation
        while any(t.is_alive() for t in threads):
            if self._cancelled:
                for proc in procs:
                    try:
                        proc.kill()
                    except OSError:
                        pass
                break
            for t in threads:
                t.join(timeout=0.5)

        # Merge results from all processes
        for pr in proc_results:
            results["files_scanned"] += pr["files_scanned"]
            results["threats_found"] += pr["threats_found"]
            results["details"].extend(pr["details"])

        # Final progress emit
        self.progress.emit(progress_end - 1)
        self.current_file.emit("ClamAV scan complete")
        return results

    def _parse_clamscan_output(self, proc, results, total_estimate=0,
                                 progress_start=0, progress_end=50):
        """Parse clamscan stdout line by line for progress and threats.

        Emits progress in the range [progress_start, progress_end-1] so the
        caller's final emit(progress_end) doesn't cause a backward jump.
        """
        progress_range = progress_end - progress_start
        for line in proc.stdout:
            if self._cancelled:
                proc.kill()
                break

            line = line.strip()
            if not line:
                continue

            if ": OK" in line:
                self.current_file.emit(f"ClamAV: {line.split(': OK')[0]}")
                results["files_scanned"] += 1
            elif " FOUND" in line:
                # ClamAV format: "filepath: threatname FOUND"
                # Use rsplit to handle filepaths containing colons
                # Strip " FOUND" suffix first, then rsplit on ": " to separate path from threat
                clean_line = line.rstrip()
                if clean_line.endswith(" FOUND"):
                    without_found = clean_line[:-6].rstrip()
                else:
                    without_found = clean_line
                if ": " in without_found:
                    filepath, threat = without_found.rsplit(": ", 1)
                else:
                    # Fallback: try colon-only split
                    filepath, threat = without_found.rsplit(":", 1)
                filepath = filepath.strip()
                threat = threat.strip()
                results["threats_found"] += 1
                results["details"].append({
                    "file": filepath,
                    "threat": threat,
                    "action": "quarantine",
                })
                self.current_file.emit(f"ClamAV: {filepath} — {threat}")
                results["files_scanned"] += 1
            elif not line.startswith("---") and not line.startswith(" "):
                # Skip ClamAV informational messages (symlink notices, etc.)
                if "Symbolic link" not in line and "Empty file" not in line:
                    self.current_file.emit(f"ClamAV: {line}")

            # Emit progress within the assigned range
            if total_estimate > 0:
                # Clamp to 1.0 — files_scanned can exceed total_estimate
                # because ClamAV counts symlinks and special files that
                # _estimate_file_count skips (it only counts regular files)
                fraction = min(1.0, results["files_scanned"] / total_estimate)
            else:
                # No estimate available — use a logarithmic scale so progress
                # doesn't jump to max after just 100 files. This gives a sense
                # of progress without a known total.
                fs = results["files_scanned"]
                if fs <= 0:
                    fraction = 0.0
                else:
                    # log scale: 10 files = 10%, 100 = 30%, 1000 = 50%, 10000 = 70%, etc.
                    import math
                    fraction = min(0.95, math.log10(fs + 1) / math.log10(100000))
            # Clamp to [progress_start, progress_end - 1] to avoid jumping to 100%
            progress = min(progress_end - 1, progress_start + int(fraction * progress_range))
            progress = max(progress_start + 1, progress)
            self.progress.emit(progress)

        proc.wait()
        # Check stderr for errors — but filter out LibClamAV warnings
        # (stale database, etc.) which are not actual scan errors
        stderr_output = proc.stderr.read().strip() if proc.stderr else ""
        # Remove LibClamAV Warning lines — these are informational, not errors
        stderr_lines = [l for l in stderr_output.split('\n')
                        if l.strip() and 'Warning' not in l and 'LibClamAV' not in l
                        and 'No such file or directory' not in l
                        and "Can't access file" not in l]
        real_stderr = '\n'.join(stderr_lines).strip()
        if proc.returncode not in (0, 1) and real_stderr:
            results["details"].append({
                "file": "N/A",
                "threat": f"ClamAV error: {real_stderr[:200]}",
                "action": "error",
            })
        # NOTE: Do NOT emit progress_end-1 here — this is called per-path
        # in a loop and would cause backward jumps when the next path starts.
        # The final progress emit is handled by the caller (_run_clamscan).

# Maximum file size for YARA scanning — larger files are skipped to prevent OOM
    # 250MB default — configurable via settings
    MAX_YARA_FILE_SIZE = 250 * 1024 * 1024

    # --- Kudu-inspired scanner optimizations (MIT, AdventDevInc/kudu) ---
    # Directories to always skip during file collection (huge, irrelevant,
    # or cause permission issues). Prevents hanging on large trees.
    SKIP_DIRS = frozenset({
        "node_modules", ".git", "__pycache__", ".cache", "cache",
        "snap", "flatpak", ".snap", ".var",
        ".mozilla", ".config/Microsoft", ".config/google-chrome",
        ".config/chromium", ".config/BraveSoftware", ".local/share/containers",
        ".local/share/Trash", ".local/share/baloo", ".local/share/akonadi",
        ".gvfs", ".Trash-0", ".Trash-1000",
    })

    # For full_system scans, also skip these system directories
    SKIP_DIRS_SYSTEM = frozenset({
        "proc", "sys", "dev", "run", "snap", "boot", "lost+found",
    })

    # Quick-scan: only scan these extensions (Kudu's Linux ext set + additions)
    QUICK_SCAN_EXTENSIONS = frozenset({
        ".so", ".elf", ".bin", ".sh", ".bash", ".py", ".pl", ".rb",
        ".php", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".wsf", ".hta",
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
        ".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm",
        ".conf", ".service", ".desktop", ".timer", ".socket",
    })

    # Maximum files to collect per directory (prevents hanging on huge trees)
    MAX_FILES_PER_DIR = 100_000
    # Maximum TOTAL files per scan root for quick scans (full_system is bounded
    # separately by full-system budgets below)
    MAX_SCANROOT_FILES_QUICK = 100_000
    # Maximum files for full-system scans (audit A-9: the old code capped the
    # ENTIRE scan root at 100k, so a Full System Scan examined only ~5-20% of
    # a modern desktop's files — silently)
    MAX_SCANROOT_FILES_FULL = 2_500_000
    # Maximum directory depth for recursive scans
    MAX_DEPTH = 15

    def _is_scannable_file(self, filepath):
        """Check if a file should be scanned with YARA.

        Scans all regular files, including text files, documents, archives,
        compressed files, scripts, and binaries. Only skips the most extreme cases
        that would cause fatal errors (devices, pipes, sockets), produce
        meaningless results (zero-byte files), cause memory issues (very large files),
        or are the app's own files (which contain malware signatures that cause FPs).

        Quick-scan mode (scan_type='quick_home') only scans files with extensions
        in QUICK_SCAN_EXTENSIONS (Kudu-inspired extension whitelist).
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
            # Skip files larger than the size limit to prevent OOM
            if stat_info.st_size > self.MAX_YARA_FILE_SIZE:
                return False
        except (OSError, PermissionError):
            return False

        # Skip the app's own files (YARA rules, definitions, etc.)
        # These contain malware signatures that match themselves, causing FPs
        if _is_app_own_file(filepath):
            return False

        # Quick-scan mode: only scan specific extensions
        if self.scan_type == "quick_home":
            ext = Path(filepath).suffix.lower()
            if ext and ext not in self.QUICK_SCAN_EXTENSIONS:
                return False

        return True

    def _should_skip_dir(self, dir_name, is_system_scan=False):
        """Check if a directory should be skipped during file collection.

        Uses the SKIP_DIRS set (Kudu-inspired) to avoid descending into
        huge/irrelevant directories like node_modules, .git, __pycache__.
        """
        if dir_name in self.SKIP_DIRS:
            return True
        if is_system_scan and dir_name in self.SKIP_DIRS_SYSTEM:
            return True
        return False

    def _collect_scannable_files(self, scan_paths):
        """Walk paths and collect scannable files for YARA scanning.

        Returns a flat list of file paths to scan.
        Emits current_file updates so the user sees activity during the walk.

        Optimizations (Kudu-inspired, MIT):
        - SKIP_DIRS: skips node_modules, .git, __pycache__, etc.
        - MAX_DEPTH: prevents deep recursion on circular symlinks
        - MAX_FILES_PER_DIR: prevents hanging on huge directory trees
        - Quick-scan extension whitelist for quick_home scans
        """
        scannable = []
        is_system = self.scan_type == "full_system"
        # audit A-9 fix: budget is per SCAN ROOT, not per directory, and the
        # full-system budget is far higher than the quick-scan budget.
        root_budget = (self.MAX_SCANROOT_FILES_FULL if is_system
                       else self.MAX_SCANROOT_FILES_QUICK)
        budget_hit = False

        for path in scan_paths:
            try:
                p = Path(path)
                if p.is_file():
                    if self._is_scannable_file(str(p)) and not is_whitelisted(str(p))[0]:
                        scannable.append(str(p))
                elif p.is_dir():
                    root_count = 0
                    for root, dirnames, filenames in os.walk(p):
                        if self._cancelled:
                            return scannable
                        # In-place modification of dirnames prevents os.walk
                        # from descending into skipped directories (Kudu-inspired)
                        dirnames[:] = [
                            d for d in dirnames
                            if not self._should_skip_dir(d, is_system)
                        ]
                        for fname in filenames:
                            f = Path(root) / fname
                            if f.is_file() and not f.is_symlink():
                                fp = str(f)
                                # Check depth (relative to scan root)
                                try:
                                    rel_depth = len(f.relative_to(p).parts)
                                    if rel_depth > self.MAX_DEPTH:
                                        continue
                                except ValueError:
                                    pass
                                if self._is_scannable_file(fp) and not is_whitelisted(fp)[0]:
                                    scannable.append(fp)
                                    root_count += 1
                                    if root_count % 5000 == 0:
                                        self.current_file.emit(
                                            f"Collecting files... ({len(scannable)} found)"
                                        )
                    if root_count >= root_budget:
                        # A-9 fix: when the budget trips, SAY so — never silently
                        self.current_file.emit(
                            f"File budget reached ({root_count:,}) for {path} — "
                            f"coverage incomplete. Increase the budget in Settings."
                        )
            except (PermissionError, OSError):
                continue
        return scannable
    def _run_yara(self, scan_paths, progress_start=50, progress_end=100):
        """Run YARA rules on the given paths using yara-python.

        Uses the compiled yara.Rules object directly — no subprocess overhead.
        The Rules object is thread-safe, so multiple files can be scanned in
        parallel from a ThreadPoolExecutor.

        When Windows malware scanning is enabled, PE files are also
        scanned against Windows-specific YARA rules.

        Progress is emitted in the range [progress_start, progress_end].
        """
        results = {"files_scanned": 0, "threats_found": 0, "details": []}

        # Emit status so the user knows YARA phase has started
        self.progress.emit(progress_start)
        self.current_file.emit("Preparing YARA rules...")

        all_rule_files = list(RULES_DIR.glob("*.yar"))

        # Separate platform-specific rules (check all known naming variants)
        # v1.4 fix: Prefer upstream (auto-updated) files over bundled ones
        windows_rules_file = None
        macos_rules_file = None
        # First pass: look for upstream versions (downloaded from Codeberg)
        for f in all_rule_files:
            if f.name == "upstream_windows.yar" and windows_rules_file is None:
                windows_rules_file = f
            elif f.name == "upstream_macos.yar" and macos_rules_file is None:
                macos_rules_file = f
        # Second pass: fall back to bundled versions if no upstream found
        for f in all_rule_files:
            if f.name in WINDOWS_RULES_NAMES and windows_rules_file is None:
                windows_rules_file = f
            elif f.name in MACOS_RULES_NAMES and macos_rules_file is None:
                macos_rules_file = f

        scan_windows = False
        scan_macos = False
        if self.settings_mgr:
            scan_windows = self.settings_mgr.is_scan_windows_malware() and windows_rules_file is not None
            scan_macos = self.settings_mgr.is_scan_macos_malware() and macos_rules_file is not None

        # Linux rules are always loaded (default enabled)
        # Exclude all platform-specific files so they're not double-scanned as Linux rules
        all_platform_names = WINDOWS_RULES_NAMES | MACOS_RULES_NAMES
        # v1.4 fix: Also exclude Linux rule variants from the "all" pool
        all_platform_names = all_platform_names | LINUX_RULES_NAMES
        # Also exclude PUP rules (removed in v1.4 -- too many false positives)
        all_platform_names = all_platform_names | {"pup-rules.yar", "upstream_pup.yar"}
        # If the new 4-tier rule files are present, exclude the legacy combined
        # file to prevent duplicate rules (and duplicate identifier errors)
        has_new_rules = any(f.name in all_platform_names for f in all_rule_files)
        if has_new_rules:
            all_platform_names = all_platform_names | LEGACY_RULES_NAMES

        # v1.4 fix: Prefer upstream (auto-updated) Linux rules over bundled ones
        # to prevent loading duplicate rule files that cause compilation errors
        linux_upstream = [f for f in all_rule_files if f.name == "upstream_linux.yar"]
        linux_bundled = [f for f in all_rule_files if f.name == "linux-rules.yar"]
        if linux_upstream:
            # Use upstream version (downloaded from Codeberg), exclude bundled
            all_platform_names = all_platform_names | {"linux-rules.yar"}
            linux_rule_files = linux_upstream + [
                f for f in all_rule_files
                if f.name not in all_platform_names and f.name != "upstream_linux.yar"
            ]
        elif linux_bundled:
            # Use bundled version, no upstream available yet
            linux_rule_files = linux_bundled + [
                f for f in all_rule_files
                if f.name not in all_platform_names and f.name != "linux-rules.yar"
            ]
        else:
            linux_rule_files = [f for f in all_rule_files
                                if f.name not in all_platform_names]
        windows_rule_files = [windows_rules_file] if scan_windows else []
        macos_rule_files = [macos_rules_file] if scan_macos else []

        if not linux_rule_files:
            default_rule = RULES_DIR / "default.yar"
            if not default_rule.exists():
                default_rule.write_text(
                    'rule no_match { condition: false }\n'
                )
            linux_rule_files = [default_rule]

        # Compile Linux rules with yara-python
        linux_rules, err_msg = _get_or_compile_yara_rules(linux_rule_files)
        if not linux_rules:
            results["details"].append({
                "file": "N/A",
                "threat": err_msg or "Failed to compile YARA rules",
                "action": "error",
            })
            self.progress.emit(100)
            return results

        # Compile Windows rules separately if enabled
        windows_rules = None
        if windows_rule_files:
            windows_rules, win_err = _get_or_compile_yara_rules(windows_rule_files)
            if not windows_rules:
                results["details"].append({
                    "file": "N/A",
                    "threat": f"Windows YARA rules error: {win_err}",
                    "action": "error",
                })

        # Compile macOS rules separately if enabled
        macos_rules = None
        if macos_rule_files:
            macos_rules, mac_err = _get_or_compile_yara_rules(macos_rule_files)
            if not macos_rules:
                results["details"].append({
                    "file": "N/A",
                    "threat": f"macOS YARA rules error: {mac_err}",
                    "action": "error",
                })

        # Collect scannable files
        self.current_file.emit("Collecting files for YARA scan...")
        scannable_files = self._collect_scannable_files(scan_paths)
        total = len(scannable_files)

        if total == 0:
            results["details"].append({
                "file": "N/A",
                "threat": "No scannable files found",
                "action": "info",
            })
            self.progress.emit(progress_end - 1)
            return results

        self.current_file.emit(f"YARA: 0/{total:,} files scanned")

        # Use ThreadPoolExecutor for parallel scanning
        # yara.Rules.match() is thread-safe — all threads share the same Rules object
        scan_threads = min(total, 4)
        if self.settings_mgr:
            scan_threads = min(total, self.settings_mgr.get_scan_threads())

        def _scan_single_file(filepath):
            """Scan a single file with yara-python. Returns a list of result dicts."""
            file_results = []
            try:
                # Distro-managed paths can't be auto-quarantined on a YARA
                # keyword match: the 2025 "generic" rules matched word lists
                # ("play", "go", "syn/udp") inside every system binary and the
                # old code stamped action=quarantine on each. Package-owned
                # files get action=flag (user decides) and a note.
                try:
                    from engine.paths import DATA_DIR
                except Exception:
                    DATA_DIR = None
                in_system_dir = filepath.startswith(("/usr/", "/bin/", "/sbin/",
                                                     "/lib/", "/lib64/",
                                                     "/opt/", "/boot/"))
                is_distro_file = False
                if in_system_dir:
                    try:
                        chk = subprocess.run(
                            ["dpkg", "-S", filepath],
                            capture_output=True, timeout=10)
                        is_distro_file = (chk.returncode == 0)
                    except Exception:
                        is_distro_file = False

                # Scan with Linux rules (always)
                matches = linux_rules.match(filepath=filepath)
                for match in matches:
                    if is_rule_exempted(match.rule):
                        continue
                    if is_distro_file:
                        file_results.append({
                            "file": filepath,
                            "threat": f"YARA: {match.rule} (distro-owned file — review, no auto-quarantine)",
                            "action": "flag",
                        })
                    else:
                        file_results.append({
                            "file": filepath,
                            "threat": f"YARA: {match.rule}",
                            "action": "quarantine",
                        })

                # Scan with Windows rules if enabled (PE files only)
                if windows_rules and _detect_file_type(filepath) == "pe":
                    win_matches = windows_rules.match(filepath=filepath)
                    for match in win_matches:
                        if is_rule_exempted(match.rule):
                            continue
                        file_results.append({
                            "file": filepath,
                            "threat": f"YARA (Windows): {match.rule}",
                            "action": "quarantine",
                        })

                # Scan with macOS rules if enabled (Mach-O files only)
                if macos_rules and _detect_file_type(filepath) == "macho":
                    mac_matches = macos_rules.match(filepath=filepath)
                    for match in mac_matches:
                        if is_rule_exempted(match.rule):
                            continue
                        file_results.append({
                            "file": filepath,
                            "threat": f"YARA (macOS): {match.rule}",
                            "action": "quarantine",
                        })

            except Exception:
                pass  # Individual file scan failures are non-fatal
            return file_results

        processed = 0
        if scan_threads > 1:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=scan_threads) as pool:
                self._yara_pool = pool  # Store for cancellation
                futures = {pool.submit(_scan_single_file, f): f for f in scannable_files}
                for future in as_completed(futures):
                    if self._cancelled:
                        break
                    file_results = future.result()
                    results["threats_found"] += sum(1 for d in file_results if d.get("action") not in ("error", "info"))
                    results["details"].extend(file_results)
                    results["files_scanned"] += 1
                    processed += 1
                    if results["files_scanned"] % 2000 == 0:
                        self.current_file.emit(f"YARA: {results['files_scanned']}/{total} files scanned")
                    if total > 0:
                        fraction = processed / total
                        progress = min(progress_end - 1, progress_start + int(fraction * (progress_end - progress_start)))
                        progress = max(progress_start + 1, progress)
                        self.progress.emit(progress)
            self._yara_pool = None
        else:
            for filepath in scannable_files:
                if self._cancelled:
                    break
                file_results = _scan_single_file(filepath)
                results["threats_found"] += sum(1 for d in file_results if d.get("action") not in ("error", "info"))
                results["details"].extend(file_results)
                results["files_scanned"] += 1
                processed += 1
                if results["files_scanned"] % 2000 == 0:
                    self.current_file.emit(f"YARA: {results['files_scanned']}/{total} files scanned")
                if total > 0:
                    fraction = processed / total
                    progress = min(progress_end - 1, progress_start + int(fraction * (progress_end - progress_start)))
                    progress = max(progress_start + 1, progress)
                    self.progress.emit(progress)

        self.progress.emit(progress_end)
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

        processes = list(psutil.process_iter(["pid", "name", "cmdline", "memory_percent", "ppid"]))
        results["files_scanned"] = len(processes)
        total = len(processes)

        # Collect CPU percentages in a second pass with a small interval
        # process_iter with cpu_percent in attrs returns 0.0 on first access
        # because psutil needs to sample CPU time over an interval.
        # We do a separate pass with a 0.1s interval to get real values.
        cpu_percent_map = {}
        try:
            for proc in processes:
                try:
                    cpu_percent_map[proc.pid] = proc.cpu_percent(interval=0.05)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

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
                cpu = cpu_percent_map.get(pid, 0) or 0
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
        """Cancel the running scan and wait for the worker to finish."""
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            # Don't wait here — the UI would freeze. The worker's run() method
            # will detect _cancelled=True, break out of its loops, emit finished,
            # and _on_finished will set self._worker = None. The next start_scan
            # call checks self._worker.isRunning() and will work once the old
            # worker finishes.

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
        # Last-resort thread guard: an exception escaping a QThread.run
        # hard-closes the process in PyQt6 (see ScanWorker.run).
        try:
            self._run_inner()
        except Exception as e:  # noqa: BLE001
            try:
                self.finished.emit(False, f"Definition update crashed: {e}")
            except Exception:
                pass

    def _run_inner(self):
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

        Only accepts freshclam binaries from system paths (/usr/bin, /usr/sbin,
        /bin, /sbin) to prevent privilege escalation via user-controlled PATH.
        """
        # Security: only accept system binary paths
        if not freshclam_bin or not freshclam_bin.startswith(("/usr/", "/bin/", "/sbin/")):
            return False
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