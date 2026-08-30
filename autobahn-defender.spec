# -*- mode: python ; coding: utf-8 -*-
# Autobahn Defender PyInstaller spec
# Excludes OpenSSL libraries (libcrypto.so.3, libssl.so.3) to avoid conflicts
# with ClamAV's system OpenSSL on Debian/Ubuntu

import os
import glob

# Get path to this script's directory for hookspath
SPEC_DIR = '/home/kristopher/Projects/Autobahn Defender'


def filter_openssl_from_binaries(binaries):
    """
    Filter out libcrypto.so and libssl.so from the binary collection.
    """
    # Convert to regular list if needed
    if hasattr(binaries, "copy"):
        # Tree or list-like - convert to list
        items = list(binaries)
    elif hasattr(binaries, "__iter__"):
        items = list(binaries)
    else:
        items = []
    
    filtered = []
    for item in items:
        # Handle different item formats
        if isinstance(item, tuple) and len(item) >= 2:
            binary_path = item[0]
        else:
            binary_path = item
        
        if isinstance(binary_path, str):
            basename = os.path.basename(binary_path)
            # Skip OpenSSL libraries
            if basename.startswith("libcrypto.so") or basename.startswith("libssl.so"):
                continue
        
        filtered.append(item)
    
    return filtered


a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[
        ("yara/*.yar", "rules"),
        ("banner.png", "."),
        ("256.png", "."),
        ("512.png", "."),
        ("icons", "icons"),
        # v2.0 AI Security module
        ("ai", "ai"),
        ("ai_tab.py", "."),
        ("templates", "templates"),
    ],
    hiddenimports=[
        "PyQt6", "PyQt6.QtCore", "PyQt6.QtGui", "PyQt6.QtWidgets",
        "yaml", "psutil", "yara", "yara_updater",
        # v2.1 AI deps (no duckduckgo_search, no trafilatura)
        "feedparser", "httpx",
        "bs4", "requests",
        "ai", "ai_tab", "ai.ollama_manager", "ai.intel_db",
        "ai.rss_feeds", "ai.tools", "ai.worker",
        "ai.alerts", "ai.threat_monitor", "ai.knowledge_base",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

# Apply filter to remove OpenSSL libraries from binaries
filtered_binaries = filter_openssl_from_binaries(a.binaries)

# Assign the filtered list back to binaries
a.binaries = filtered_binaries


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
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="autobahn-defender",
)
