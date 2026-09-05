# -*- mode: python ; coding: utf-8 -*-
# Autobahn Defender v2.0 PyInstaller spec
# - Excludes OpenSSL libs (avoids ClamAV's system OpenSSL conflict)
# - Includes the v2 module layout: engine/ (+intel/, +watch/), cli/, live ai/
# - No AI modules, no Ollama, no GGUF
#
# OpenSSL exclusion: libcrypto/libssl are provided by the host system
# (clamav links against them), bundling them breaks clamscan interop.

import os

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[
        ("rules/*.yar", "rules"),
        ("256.png", "."),
        ("512.png", "."),
        ("icons", "icons"),
        # live ai/ subset only (rss_feeds + intel_db + __init__)
        ("ai/__init__.py", "ai"),
        ("ai/rss_feeds.py", "ai"),
        ("ai/intel_db.py", "ai"),
        ("engine/*.py", "engine"),
        ("engine/intel/*.py", "engine/intel"),
        ("engine/watch/__init__.py", "engine/watch"),
        ("engine/watch/inotify_watch.py", "engine/watch"),
        ("cli/*.py", "cli"),
        ("docs/AGENTS.md", "docs"),
        ("templates", "templates"),
        ("ATTRIBUTION.md", "."),
        ("256.png", "."),
        ("512.png", "."),
        ("icons", "icons"),
    ],
    hiddenimports=[
        "PyQt6", "PyQt6.QtCore", "PyQt6.QtGui", "PyQt6.QtWidgets",
        "psutil", "yara", "yara_updater",
        "feedparser", "bs4", "requests",
        "ai", "ai.rss_feeds", "ai.intel_db",
        "engine", "engine.checks", "engine.advisor", "engine.cve",
        "engine.cve_filter", "engine.versions", "engine.patches",
        "engine.alerts", "engine.findings", "engine.paths", "engine.version",
        "engine.apply", "engine.network_watch", "engine.privacy",
        "engine.startup", "engine.persistence", "engine.remediate",
        "engine.runner", "engine.scanner_core", "engine.scan_cache",
        "engine.scan_feed",
        "engine.intel.kev", "engine.intel.epss", "engine.intel.poc",
        "engine.intel.store", "engine.intel.match",
        "engine.intel.ubuntu_osv", "engine.intel.poll",
        "engine.watch.inotify_watch",
        "cli", "cli.main", "cli.parsers", "cli.envelope", "cli.exitcodes",
        "cli.formatters", "cli.mcp_server", "cli.doctor", "cli.verbs_intel",
        "ai_agent_tab",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "ollama", "ai_tab", "ai.tools", "ai.worker",
              "ai.ollama_manager", "ai.threat_monitor", "ai.knowledge_base"],
    noarchive=False,
    optimize=0,
)


def filter_openssl(binaries):
    def keep(path):
        base = os.path.basename(path if isinstance(path, str) else path[0])
        return not (base.startswith("libcrypto.so")
                    or base.startswith("libssl.so"))
    return [b for b in binaries if keep(b[0] if isinstance(b, tuple) else b)]


a.binaries = filter_openssl(a.binaries)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="autobahn-defender",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    name="autobahn-defender",
)