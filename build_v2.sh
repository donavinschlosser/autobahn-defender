#!/bin/bash
# Build Autobahn Defender v2.0.1 .deb — fresh staging from current source.
# Hygiene per audit C-11: no __pycache__, no stale AI files, corrected
# Description, valid appdata, clean prerm. v2 code + CLI + intel + watch.
set -euo pipefail

PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE="$PROJ/build_deb_v2.0/autobahn-defender_2.0.1_amd64"
OUT="$PROJ/autobahn-defender_2.0.1_amd64.deb"

cd "$PROJ"

echo "── 1. Fresh staging tree ──────────────────────────────"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" \
         "$STAGE/usr/share/autobahn-defender/ai" \
         "$STAGE/usr/share/autobahn-defender/engine/intel" \
         "$STAGE/usr/share/autobahn-defender/engine/watch" \
         "$STAGE/usr/share/autobahn-defender/cli" \
         "$STAGE/usr/share/autobahn-defender/rules" \
         "$STAGE/usr/share/autobahn-defender/templates" \
         "$STAGE/usr/share/autobahn-defender/docs" \
         "$STAGE/usr/share/applications" \
         "$STAGE/usr/share/icons/hicolor/256x256/apps" \
         "$STAGE/usr/share/icons/hicolor/512x512/apps" \
         "$STAGE/usr/share/metainfo" \
         "$STAGE/usr/bin"

echo "── 2. Copy application code ───────────────────────────"
install -m 644 main.py scanner.py quarantine.py settings.py updater.py \
    yara_updater.py history_db.py firewall.py hardening.py kernel_checker.py \
    usb_monitor.py security_tab.py security_news_tab.py ai_agent_tab.py ui_tabs.py \
    "$STAGE/usr/share/autobahn-defender/"
install -m 644 engine/*.py "$STAGE/usr/share/autobahn-defender/engine/"
install -m 644 engine/intel/*.py "$STAGE/usr/share/autobahn-defender/engine/intel/"
install -m 644 engine/watch/*.py "$STAGE/usr/share/autobahn-defender/engine/watch/"
install -m 644 cli/*.py "$STAGE/usr/share/autobahn-defender/cli/"
install -m 644 ai/__init__.py ai/rss_feeds.py ai/intel_db.py \
    "$STAGE/usr/share/autobahn-defender/ai/"
install -m 644 rules/*.yar "$STAGE/usr/share/autobahn-defender/rules/"
[ -f templates/report_template.html ] && install -m 644 templates/report_template.html "$STAGE/usr/share/autobahn-defender/templates/"
[ -f ATTRIBUTION.md ] && install -m 644 ATTRIBUTION.md "$STAGE/usr/share/autobahn-defender/"
[ -f docs/AGENTS.md ] && install -m 644 docs/AGENTS.md "$STAGE/usr/share/autobahn-defender/docs/"

# icons
install -m 644 256.png "$STAGE/usr/share/icons/hicolor/256x256/apps/autobahn-defender.png"
install -m 644 512.png "$STAGE/usr/share/icons/hicolor/512x512/apps/autobahn-defender.png"

# desktop file
cat > "$STAGE/usr/share/applications/com.digitalautobahn.AutobahnDefender.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Autobahn Defender
GenericName=Antivirus
Comment=Linux antivirus with deterministic security engine (v2.0)
Exec=/usr/bin/autobahn-defender
Icon=autobahn-defender
Categories=System;Security;
StartupNotify=true
Terminal=false
EOF

# launcher (CLI dispatch + GUI in one binary path)
cat > "$STAGE/usr/bin/autobahn-defender" <<'EOF'
#!/bin/bash
# Autobahn Defender v2.0 launcher — CLI verbs run headless; bare launch = GUI
APP_DIR="/usr/share/autobahn-defender"
export PYTHONPATH="${APP_DIR}:${PYTHONPATH}"
exec /usr/bin/python3 "${APP_DIR}/main.py" "$@"
EOF
chmod 755 "$STAGE/usr/bin/autobahn-defender"

# appdata (valid minimal)
cat > "$STAGE/usr/share/metainfo/com.digitalautobahn.AutobahnDefender.appdata.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>com.digitalautobahn.AutobahnDefender</id>
  <name>Autobahn Defender</name>
  <summary>Linux antivirus with deterministic security engine</summary>
  <metadata_license>MIT</metadata_license>
  <project_license>MIT</project_license>
  <releases>
    <release version="2.0.1" date="2026-09-06">
      <description>
        <p>Hotfix + AI scan engine: AppImage bundles the missing AI Agent /
        Security Center / News tabs and yara-python (Rootkit scan
        force-close fixed); QThread crash guards; new autobahn.scan MCP
        tool — scan any file/folder/drive as a detached job with a live
        progress feed and blocking wait.</p>
      </description>
    </release>
    <release version="2.0.0" date="2026-08-31">
      <description>
        <p>First production 2.0 release: deterministic engine, full CLI,
        CISA KEV/USN/EPSS/PoC intel monitor, MCP server, remediation lifecycle.</p>
      </description>
    </release>
  </releases>
</component>
EOF

# DEBIAN/control (trailing newline is REQUIRED — pitfall from skill)
cat > "$STAGE/DEBIAN/control" <<'EOF'
Package: autobahn-defender
Version: 2.0.1
Architecture: all
Maintainer: Digital Autobahn <digitalautobahn@xmpp.brax.me>
Depends: python3, python3-pyqt6, python3-psutil, python3-yara, python3-requests, python3-bs4, python3-feedparser, clamav
Recommends: clamav-freshclam, whois, policykit-1, unattended-upgrades
Suggests: fail2ban, ufw, auditd, clamav-daemon
Section: utils
Priority: optional
Description: Linux antivirus with deterministic security engine (v2.0)
 Autobahn Defender is a modern Linux antivirus application that uses
 ClamAV and YARA to detect rootkits, cryptominers, backdoors, and
 ransomware, plus a deterministic security engine for vulnerability
 scanning, patch tracking, and system hardening.
 .
 v2.0 highlights:
  * Deterministic security engine — no AI model, no Ollama, no GPU
  * CLI: every feature drivable headless (autobahn-defender <verb>)
  * MCP server mode for AI agents (autobahn-defender mcp)
  * CVE scanning via OSV.dev with Debian-policy version comparison
  * CVSS 3.1 severity scoring (CRITICAL/HIGH/MEDIUM/LOW)
  * Patch tracker with verified-fixed loop (inconclusive != fixed)
  * Threat-intel monitor: CISA KEV + Ubuntu USN + EPSS + PoC feeds
  * Remediation lifecycle: contain, update, verify, restore
  * Active watch: inotify persistence/downloads monitor
  * Unified findings schema across GUI, CLI, and MCP
  * All privileged actions pkexec-gated with review-first confirm
  * Contact: XMPP digitalautobahn@xmpp.brax.me
EOF
printf "\n" >> "$STAGE/DEBIAN/control"

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/bash
set -e
mkdir -p /var/log/clamav 2>/dev/null || true
chown clamav:clamav /var/log/clamav 2>/dev/null || true

if command -v update-desktop-database >/dev/null; then
    update-desktop-database /usr/share/applications 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null; then
    gtk-update-icon-cache -f /usr/share/icons/hicolor 2>/dev/null || true
fi

echo ""
echo "=========================================="
echo " Autobahn Defender v2.0 installed."
echo ""
echo "  GUI:      launch from your application menu"
echo "  CLI:      autobahn-defender --help"
echo "  AI agent: autobahn-defender mcp  (see docs/AGENTS.md)"
echo ""
echo "  Try: autobahn-defender doctor"
echo "=========================================="
EOF

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/bash
# v2.0 pre-remove (audit C-11b: Ollama-sidecar hunt removed — no bundled daemons).
set -e
# User data (~/.autobahn, ~/.local/share/autobahn-defender) preserved.
exit 0
EOF
chmod 755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm"

echo "── 3. Permissions ─────────────────────────────────────"
find "$STAGE" -type d -exec chmod 755 {} +
find "$STAGE" -name "*.py" -exec chmod 644 {} +
find "$STAGE" -name "*.yar" -exec chmod 644 {} +
chmod 644 "$STAGE/DEBIAN/control"

echo "── 4. Strip __pycache__ (audit C-11a) ─────────────────"
find "$STAGE" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -name "*.pyc" -delete 2>/dev/null || true

echo "── 5. Verify no AI leftovers / GGUF / ollama ──────────"
if find "$STAGE/usr/share/autobahn-defender" \( -name "*.gguf" -o -name "ollama*" -o -name "worker.py" -o -name "ollama_manager.py" \) | grep -q .; then
  echo "ERROR: stale AI files staged"; exit 1
fi
# engine must not import scanner (headless rule) — check live tree only
if grep -rnE "^\s*(from scanner import|import scanner)" "$STAGE/usr/share/autobahn-defender/engine/" ; then
  echo "ERROR: engine still imports scanner (breaks headless CLI)"; exit 1
fi
echo "   clean"

echo "── 6. Build ───────────────────────────────────────────"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT" 2>&1 | tail -2
echo
dpkg-deb --info "$OUT" | head -8
ls -la "$OUT"
echo "DONE: $OUT"