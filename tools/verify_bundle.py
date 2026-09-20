#!/usr/bin/env python3
"""Verify a PyInstaller bundle actually contains the GUI modules.

Why this exists (v2.0.1): PyInstaller only WARNS when a hiddenimports entry
doesn't resolve, so the v2.0.0 AppImage shipped with ai_agent_tab.py,
security_tab.py, and security_news_tab.py missing from its PYZ archive —
users saw no AI Agent tab. This tool parses the PYZ TOC directly and fails
the build if any required module is absent. It also verifies the yara
extension module and the bundled rules files.

Usage: verify_bundle.py <dist-dir|appdir/usr/bin/autobahn-defender-dir>
       e.g. python3 tools/verify_bundle.py dist/autobahn-defender
Exit codes: 0 = all required modules present; 1 = missing/incomplete.
"""
from __future__ import annotations

import marshal
import struct
import sys
import zlib
from pathlib import Path

# Modules that MUST be in the PYZ (GUI tabs were silently dropped in v2.0.0).
# NOTE: the entry script (main.py) is NOT in the PYZ — PyInstaller stores it
# as a CArchive script entry ('s' type); it's checked separately below.
REQUIRED_MODULES = [
    "scanner", "quarantine", "settings", "ui_tabs", "history_db",
    "kernel_checker", "firewall", "hardening", "updater", "usb_monitor",
    "yara_updater",
    "security_tab", "security_news_tab", "ai_agent_tab",
    "ai", "ai.rss_feeds", "ai.intel_db",
    "engine", "engine.scanner_core", "engine.scan_cache", "engine.scan_feed",
    "engine.runner", "engine.checks", "engine.advisor", "engine.cve",
    "engine.alerts", "engine.remediate", "engine.paths",
    # v2.0.4: the dpkg ownership index. Both scan paths import it on every
    # scan; if it is absent from the bundle the YARA phase raises on the
    # first file, so gate on it here rather than discovering it in the field.
    "engine.dpkg_ownership",
    "cli", "cli.main", "cli.parsers", "cli.mcp_server",
    "PyQt6", "psutil",
]

# Extension modules that MUST be loadable from the bundle (yara was absent
# in the v2.0.0 AppImage → Rootkit scan force-closed the app)
REQUIRED_EXT_SUFFIXES = ("yara", "yara.c")

REQUIRED_DATA = ["rules"]  # bundled YARA rules directory


def _pyz_blob(data: bytes) -> bytes:
    magic = b"MEI\014\013\012\013\016"
    pos = data.rfind(magic)
    if pos == -1:
        raise SystemExit("not a PyInstaller archive (no cookie magic)")
    lengthofPackage, toc, tocLen, _pyvers = struct.unpack(
        "!IIII", data[pos + 8:pos + 24])
    base = pos + 88 - lengthofPackage  # v6 cookie: magic+4 uints+64-byte name
    p, end = base + toc, base + toc + tocLen
    while p < end:
        (entry_len,) = struct.unpack("!I", data[p:p + 4])
        entry_pos, csize, _usize, cflag, _t = struct.unpack(
            "!IIIBc", data[p + 4:p + 18])
        name = data[p + 18:p + entry_len].rstrip(b"\0").decode()
        if name == "PYZ-00.pyz":
            blob = data[base + entry_pos: base + entry_pos + csize]
            if cflag:
                blob = zlib.decompress(blob)
            return blob
        p += entry_len
    raise SystemExit("PYZ-00.pyz not found in archive")


def _pyz_modules(blob: bytes) -> set:
    # PYZ header: 4B magic 'PYZ\0' + 4B pyc magic + 4B TOC offset (big-endian
    # on py3.10 builds; the offset has been LE on some versions — try both)
    for fmt in ("!I", "<I"):
        try:
            toc_off = struct.unpack(fmt, blob[8:12])[0]
            toc = marshal.loads(blob[toc_off:])
            return {n for n, (_t, _p, _l) in toc}
        except Exception:
            continue
    raise SystemExit("cannot parse PYZ TOC")


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "dist/autobahn-defender")
    # --pre-clamav: run BEFORE the ClamAV bundling step (build order); the
    # ClamAV checks are skipped and happen in the post-bundle run instead.
    pre_clamav = "--pre-clamav" in sys.argv
    exe = root / "autobahn-defender"
    if not exe.exists():
        print(f"FAIL: {exe} not found", file=sys.stderr)
        return 1
    blob = _pyz_blob(exe.read_bytes())
    have = _pyz_modules(blob)
    missing = [m for m in REQUIRED_MODULES if m not in have]
    if missing:
        print("FAIL: modules missing from PYZ:", ", ".join(missing),
              file=sys.stderr)
        return 1

    # Entry script check: 'main' must exist as a CArchive script entry.
    data = exe.read_bytes()
    magic = b"MEI\014\013\012\013\016"
    pos = data.rfind(magic)
    entry_ok = False
    if pos != -1:
        lengthofPackage, toc, tocLen, _pyvers = struct.unpack(
            "!IIII", data[pos + 8:pos + 24])
        base = pos + 88 - lengthofPackage
        p, end = base + toc, base + toc + tocLen
        while p < end:
            (entry_len,) = struct.unpack("!I", data[p:p + 4])
            _epos, _cs, _us, _cf, ttype = struct.unpack("!IIIBc", data[p + 4:p + 18])
            name = data[p + 18:p + entry_len].rstrip(b"\0").decode()
            if ttype == b"s" and name == "main":
                entry_ok = True
                break
            p += entry_len
    if not entry_ok:
        print("FAIL: entry script 'main' not found in CArchive", file=sys.stderr)
        return 1

    internal = root / "_internal"
    if not internal.is_dir():
        print(f"FAIL: {internal} not found (onedir layout changed?)",
              file=sys.stderr)
        return 1
    ext_ok = []
    for ext in internal.glob("**/*.so"):
        name = ext.name
        if any(s in name for s in ("yara",)):
            ext_ok.append(name)
    if not ext_ok:
        # yara may also live inside lib-dynload or as yara/*.so
        yara_pkgs = list(internal.glob("yara/**/*.so"))
        ext_ok = [str(p.relative_to(internal)) for p in yara_pkgs]
    if not ext_ok:
        print("FAIL: yara extension module not found in bundle — YARA scans "
              "would crash (v2.0.0 AppImage bug)", file=sys.stderr)
        return 1

    rules = internal / "rules"
    yar_count = len(list(rules.glob("*.yar"))) if rules.is_dir() else 0
    if yar_count == 0:
        print("FAIL: no bundled YARA rules in _internal/rules", file=sys.stderr)
        return 1

    # v2.0.2: the bundled ClamAV must exist AND run (self-contained AppImage)
    clam = internal / "clamav" / "clamscan"
    clam_lib = internal / "clamav" / "lib"
    if pre_clamav:
        print("OK (pre-clamav): PYZ has all "
              f"{len(REQUIRED_MODULES)} required modules + entry script, "
              f"yara extension present ({ext_ok[0]}), {yar_count} rules files "
              f"bundled — ClamAV check deferred to post-bundle pass")
        return 0
    if not clam.exists() or not clam_lib.is_dir() or not list(clam_lib.glob("*.so*")):
        print("FAIL: bundled ClamAV missing (clamav/clamscan + clamav/lib) — "
              "AppImage would prompt for system installs again", file=sys.stderr)
        return 1
    try:
        import subprocess as _sp
        probe = _sp.run([str(clam), "--version"], capture_output=True,
                        timeout=30, cwd=str(root))
        if probe.returncode != 0:
            print(f"FAIL: bundled clamscan --version failed (rc={probe.returncode}): "
                  f"{(probe.stderr or b'')[:200]!r}", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"FAIL: bundled clamscan --version could not run: {e}", file=sys.stderr)
        return 1

    print(f"OK: PYZ has all {len(REQUIRED_MODULES)} required modules + entry script, "
          f"yara extension present ({ext_ok[0]}), {yar_count} rules files bundled, "
          f"ClamAV bundled and running ({probe.stdout.decode(errors='replace').strip().splitlines()[0] if probe.stdout else clam.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())