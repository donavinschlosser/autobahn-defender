#!/bin/bash
# Build Autobahn Defender v2.0.0 AppImage (Docker, Ubuntu 22.04 base for
# glibc compat). Copies the v2 layout: main.py + core modules + engine/ + cli/
# + the live ai/ subset (rss_feeds/intel_db) + rules.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_appimage"
WORK_DIR="${BUILD_DIR}/docker_build"

echo "=== Autobahn Defender v2.0 AppImage build (Docker, glibc 2.35) ==="

mkdir -p "$WORK_DIR"

# ── copy current source into the docker build context ────────────────────
cp "${SCRIPT_DIR}/main.py"          "$WORK_DIR/"
cp "${SCRIPT_DIR}/scanner.py"       "$WORK_DIR/"
cp "${SCRIPT_DIR}/quarantine.py"    "$WORK_DIR/"
cp "${SCRIPT_DIR}/settings.py"      "$WORK_DIR/"
cp "${SCRIPT_DIR}/updater.py"       "$WORK_DIR/"
cp "${SCRIPT_DIR}/ui_tabs.py"       "$WORK_DIR/"
cp "${SCRIPT_DIR}/history_db.py"    "$WORK_DIR/"
cp "${SCRIPT_DIR}/kernel_checker.py" "$WORK_DIR/"
cp "${SCRIPT_DIR}/firewall.py"      "$WORK_DIR/"
cp "${SCRIPT_DIR}/hardening.py"     "$WORK_DIR/"
cp "${SCRIPT_DIR}/usb_monitor.py"   "$WORK_DIR/"
cp "${SCRIPT_DIR}/yara_updater.py"  "$WORK_DIR/"
cp "${SCRIPT_DIR}/security_tab.py"  "$WORK_DIR/"
cp "${SCRIPT_DIR}/security_news_tab.py" "$WORK_DIR/"
cp "${SCRIPT_DIR}/autobahn-defender.spec" "$WORK_DIR/"
# v2 packages
rm -rf "${WORK_DIR}/engine" "${WORK_DIR}/cli"
cp -r "${SCRIPT_DIR}/engine" "$WORK_DIR/engine"
cp -r "${SCRIPT_DIR}/cli"    "$WORK_DIR/cli"
find "${WORK_DIR}/engine" "${WORK_DIR}/cli" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
rm -rf "${WORK_DIR}/ai"
mkdir -p "${WORK_DIR}/ai"
cp "${SCRIPT_DIR}/ai/__init__.py" "${SCRIPT_DIR}/ai/rss_feeds.py" \
   "${SCRIPT_DIR}/ai/intel_db.py" "${WORK_DIR}/ai/"
cp -r "${SCRIPT_DIR}/rules" "${WORK_DIR}/rules"
cp -r "${SCRIPT_DIR}/templates" "$WORK_DIR/" 2>/dev/null || true
cp -r "${SCRIPT_DIR}/docs" "$WORK_DIR/" 2>/dev/null || true
cp "${SCRIPT_DIR}/256.png" "${SCRIPT_DIR}/512.png" "$WORK_DIR/" 2>/dev/null || true
mkdir -p "${WORK_DIR}/icons" && cp "${SCRIPT_DIR}"/icons/* "${WORK_DIR}/icons/" 2>/dev/null || true
# banner no longer needed, skip

# spec must include engine+cli packages — patch the PyInstaller spec hiddenimports
# if the spec already lists them (v2 spec), fine; else the data tree covers it.

# v2.0.1: GUI tabs must be importable at build time — PyInstaller only WARNS
# on hiddenimports that don't resolve, so a missing file silently ships an
# AppImage without the AI Agent tab (v2.0.0 release bug).
for _tab in security_tab.py security_news_tab.py ai_agent_tab.py; do
    if [ ! -f "${SCRIPT_DIR}/${_tab}" ]; then
        echo "ERROR: required module missing from source tree: ${_tab}" >&2
        exit 1
    fi
done

echo ""
echo "=== Building in Docker (Ubuntu 22.04, system PyQt6) ==="
docker run --rm \
  -v "$WORK_DIR:/work" \
  -w /work \
  ubuntu:22.04 \
  bash -c "
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    python3 python3-pip python3-pyqt6 python3-yara python3-requests \
    python3-bs4 python3-feedparser python3-psutil clamav \
    patchelf file >/dev/null 2>&1
pip3 install --quiet pyinstaller websockets 2>/dev/null || true
# yara-python must be importable INSIDE the venv PyInstaller builds from —
# system python3-yara doesn't count for the bundle (v2.0.0 shipped without it)
pip3 install --quiet yara-python 2>/dev/null || true

echo '── pyinstaller ──'
python3 -m PyInstaller autobahn-defender.spec --noconfirm --clean

mkdir -p /out
cp -r dist/autobahn-defender /out/

# ── bundle verification (v2.0.1): fail the build, never ship a broken bundle ──
python3 /work/tools/verify_bundle.py /out/autobahn-defender || {
    echo "BUNDLE VERIFICATION FAILED — refusing to continue" >&2
    exit 1
}
"

echo "=== staging AppImage dir ==="
APPDIR="${BUILD_DIR}/appdir"
rm -rf "$APPDIR"
mkdir -p "${APPDIR}/usr/share/applications" \
         "${APPDIR}/usr/share/icons/hicolor/512x512/apps" \
         "${APPDIR}/usr/share/metainfo"
cp -r "${WORK_DIR}/dist/autobahn-defender" "${APPDIR}/usr/bin" 2>/dev/null \
  || { echo "PyInstaller output missing; cannot continue"; exit 1; }
# the binary must be a file named autobahn-defender
if [ -d "${APPDIR}/usr/bin/autobahn-defender" ]; then
    # PyInstaller onedir layout — keep the dir but make a wrapper
    mv "${APPDIR}/usr/bin" "${APPDIR}/usr/lib/autobahn-defender-app"
    mkdir -p "${APPDIR}/usr/bin"
    cat > "${APPDIR}/usr/bin/autobahn-defender" <<'EOF'
#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${DIR}/autobahn-defender.real" "$@"
EOF
    chmod +x "${APPDIR}/usr/bin/autobahn-defender"
fi

echo "AppImage staging done under ${APPDIR} (docker_build approach)."
echo "NOTE: finalize with docker_build/build/autobahn-defender AppImage tooling."