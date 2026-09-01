#!/usr/bin/env python3
"""Install Autobahn Defender from source to a prefix (any distro).

Mirrors the deb layout:
  <prefix>/share/autobahn-defender/    application tree
  <prefix>/bin/autobahn-defender       launcher
  <prefix>/share/applications/…desktop
  <prefix>/share/icons/hicolor/…png

Usage:
  sudo python3 tools/install_from_source.py            # prefix=/usr
  python3 tools/install_from_source.py --prefix ~/.local
Uninstall:
  python3 tools/install_from_source.py --uninstall
"""
import argparse
import os
import shutil
import sys
from pathlib import Path

APP_FILES = [
    "main.py", "scanner.py", "quarantine.py", "settings.py", "updater.py",
    "yara_updater.py", "history_db.py", "firewall.py", "hardening.py",
    "kernel_checker.py", "usb_monitor.py", "security_tab.py",
    "security_news_tab.py", "ai_agent_tab.py", "ui_tabs.py",
    "ATTRIBUTION.md", "requirements.txt", "256.png", "512.png",
]
SUBDIRS = ["engine", "engine/intel", "engine/watch", "cli", "ai",
           "rules", "templates", "icons", "docs"]

LAUNCHER = """#!/bin/bash
# Autobahn Defender v2.0 launcher — CLI verbs run headless; bare launch = GUI
APP_DIR="{app_share}"
export PYTHONPATH="${{APP_DIR}}:${{PYTHONPATH}}"
exec /usr/bin/env python3 "${{APP_DIR}}/main.py" "$@"
"""


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--prefix", default="/usr")
    ap.add_argument("--uninstall", action="store_true")
    args = ap.parse_args()

    app_share = Path(args.prefix) / "share" / "autobahn-defender"
    bin_path = Path(args.prefix) / "bin" / "autobahn-defender"

    if args.uninstall:
        for p in (app_share, bin_path,
                  Path(args.prefix) / "share/applications/com.digitalautobahn.AutobahnDefender.desktop",
                  Path(args.prefix) / "share/icons/hicolor/256x256/apps/autobahn-defender.png",
                  Path(args.prefix) / "share/icons/hicolor/512x512/apps/autobahn-defender.png"):
            try:
                if p.is_dir():
                    shutil.rmtree(p)
                    print(f"removed {p}")
                elif p.exists():
                    p.unlink()
                    print(f"removed {p}")
            except FileNotFoundError:
                pass
        print("User data in ~/.autobahn was kept (your history/quarantine/rules).")
        return 0

    if not (repo / "main.py").exists():
        print("run from a repository checkout (main.py not found)", file=sys.stderr)
        return 2

    app_share.mkdir(parents=True, exist_ok=True)
    for name in APP_FILES:
        src = repo / name
        if src.exists():
            shutil.copy2(src, app_share / name)
    for sub in SUBDIRS:
        srcdir = repo / sub
        if not srcdir.is_dir():
            continue
        dst = app_share / sub
        dst.mkdir(parents=True, exist_ok=True)
        for src in srcdir.iterdir():
            if src.is_file():
                shutil.copy2(src, dst / src.name)

    bin_path.parent.mkdir(parents=True, exist_ok=True)
    bin_path.write_text(LAUNCHER.format(app_share=app_share))
    os.chmod(bin_path, 0o755)

    for src, dst in (
        (repo / "com.digitalautobahn.AutobahnDefender.desktop",
         Path(args.prefix) / "share/applications/com.digitalautobahn.AutobahnDefender.desktop"),
        (repo / "256.png",
         Path(args.prefix) / "share/icons/hicolor/256x256/apps/autobahn-defender.png"),
        (repo / "512.png",
         Path(args.prefix) / "share/icons/hicolor/512x512/apps/autobahn-defender.png"),
    ):
        if src.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

    print(f"Installed to {app_share}")
    print(f"Launcher:   {bin_path}")
    print("Try: autobahn-defender doctor")
    if "share/icons" in str(args.prefix):
        print("(icon cache may need: gtk-update-icon-cache -f)",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())