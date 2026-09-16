#!/bin/bash
# Build script for Autobahn Defender portable AppImage
# Builds inside Docker with Ubuntu 22.04 for glibc 2.35 compatibility
# This ensures the AppImage works on Linux Mint 20+ and other older systems

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_appimage"
DIST_DIR="${SCRIPT_DIR}/dist"

echo "=== Building Autobahn Defender Portable AppImage ==="
echo "Using Docker for glibc compatibility"

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed or not in PATH"
    echo ""
    echo "To build without Docker, run these commands on Linux Mint:"
    echo "  python3 -m pip install pyinstaller PyQt6"
    echo "  pyinstaller autobahn-defender.spec"
    exit 1
fi

# Create work directory
WORK_DIR="${BUILD_DIR}/docker_build"
mkdir -p "${WORK_DIR}"

# Copy necessary files
cp -r "${SCRIPT_DIR}/icons" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/256.png" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/512.png" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/banner.png" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/main.py" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/autobahn-defender.spec" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/scanner.py" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/settings.py" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/quarantine.py" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/updater.py" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/ui_tabs.py" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/history_db.py" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/kernel_checker.py" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/firewall.py" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/hardening.py" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/usb_monitor.py" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/yara_updater.py" "${WORK_DIR}/"
# v2.0 GUI tabs — MUST be copied explicitly AND be importable at build time:
# PyInstaller only WARNS on hiddenimports that don't resolve (missing file in
# the build context), so a stale copy list silently ships an AppImage whose
# AI Agent tab / Security Center / News tab are missing (v2.0.0 release bug).
for _tab in security_tab.py security_news_tab.py ai_agent_tab.py; do
    if [ ! -f "${SCRIPT_DIR}/${_tab}" ]; then
        echo "ERROR: required module missing from source tree: ${_tab}" >&2
        exit 1
    fi
    cp "${SCRIPT_DIR}/${_tab}" "${WORK_DIR}/"
done
cp -r "${SCRIPT_DIR}/engine" "${WORK_DIR}/"
cp -r "${SCRIPT_DIR}/cli" "${WORK_DIR}/"
# v2.0 live ai/ subset only (dead AI modules excluded from bundle)
rm -rf "${WORK_DIR}/ai"
mkdir -p "${WORK_DIR}/ai"
for f in __init__.py rss_feeds.py intel_db.py; do
  cp "${SCRIPT_DIR}/ai/${f}" "${WORK_DIR}/ai/"
done
cp -r "${SCRIPT_DIR}/rules" "${WORK_DIR}/"
cp -r "${SCRIPT_DIR}/tools" "${WORK_DIR}/" 2>/dev/null || true
cp -r "${SCRIPT_DIR}/templates" "${WORK_DIR}/" 2>/dev/null || true
cp -r "${SCRIPT_DIR}/docs" "${WORK_DIR}/" 2>/dev/null || true
cp "${SCRIPT_DIR}/ATTRIBUTION.md" "$WORK_DIR/" 2>/dev/null || true

# Build inside Docker with Ubuntu 22.04 (glibc 2.35)
# Use system PyQt6 from apt which has Qt6 libraries compatible with glibc 2.35
echo ""
echo "Building inside Docker container (Ubuntu 22.04 with system PyQt6)..."

docker run --rm \
    -v "${WORK_DIR}:/src" \
    -v "${BUILD_DIR}:/output" \
    -w "/src" \
    --platform linux/amd64 \
    --network host \
    ubuntu:22.04 /bin/bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive

echo "Updating package lists..."
apt-get update

echo "Installing dependencies..."
apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv python3-setuptools libpython3.10-dev \
    build-essential wget curl \
    libgl1 libglx0 libegl1 libglib2.0-0 libxkbcommon0 libxkbcommon-x11-0 \
    libxcb-cursor0 libxcb-icccm4 libxcb-keysyms1 libxcb-shape0 \
    libxcb-util1 libxcb-image0 libxcb-render-util0 \
    libxcursor1 libxinerama1 libgtk-3-0 libdbus-1-3 \
    libatspi2.0-0 libsecret-1-0 libsm6 libice6 libfontconfig1 \
    libgdk-pixbuf2.0-0 libpangocairo-1.0-0 libpangoft2-1.0-0 \
    libharfbuzz0b libfreetype6 libpng16-16 libjpeg-turbo8 \
    libxrender1 libxrandr2

echo "Creating virtual environment..."
cd /src
python3 -m venv /output/venv
source /output/venv/bin/activate

pip install --no-cache-dir pyinstaller==6.11.1

# Use pip for PyQt6 since python3-pyqt6 is not available in Ubuntu 22.04 repos
pip install --no-cache-dir PyQt6
pip install --no-cache-dir psutil
# yara-python is REQUIRED in the bundle: without it every YARA-phase scan
# (Rootkit button, all GUI scans) force-closed the app in the v2.0.0
# AppImage — the scanner except-clause referenced yara before the import
# succeeded, raising NameError inside the QThread. 2.0.1 bundles it and
# the build now verifies the bundle before shipping.
pip install --no-cache-dir yara-python

# v2.1 AI deps: feedparser, httpx, beautifulsoup4, requests
# (no duckduckgo_search, no trafilatura -- removed in v2.1)
pip install --no-cache-dir feedparser httpx beautifulsoup4 requests

echo "Building PyInstaller binary..."
pyinstaller autobahn-defender.spec --noconfirm

if [ ! -f "dist/autobahn-defender/autobahn-defender" ]; then
    echo "ERROR: PyInstaller binary not found (expected dist/autobahn-defender/autobahn-defender)"
    exit 1
fi

echo "PyInstaller binary built successfully:"
ls -lh dist/autobahn-defender/autobahn-defender

# Verify OpenSSL libraries are not bundled
echo ""
echo "Checking for OpenSSL libraries in bundle..."
OPENSSL_LIBS=$(find dist/autobahn-defender -name 'libcrypto.so*' -o -name 'libssl.so*' 2>/dev/null)
if [ -n "$OPENSSL_LIBS" ]; then
    echo "ERROR: OpenSSL libraries found in bundle (should be excluded):"
    echo "$OPENSSL_LIBS"
    exit 1
else
    echo "OK: No OpenSSL libraries (libcrypto/libssl) found in bundle"
fi

# v2.0.1: verify the bundle actually contains the GUI modules + yara
# extension — PyInstaller only WARNS on unresolvable hiddenimports, so the
# v2.0.0 AppImage shipped without ai_agent_tab/security_tab/yara (missing
# AI Agent tab; Rootkit scan force-closed the app). Fail the build instead.
# (The ClamAV-bundling gate runs AFTER the bundling step below.)
echo ""
echo "Verifying bundle contents (GUI modules + yara + rules)..."
python3 tools/verify_bundle.py dist/autobahn-defender --pre-clamav || {
    echo "ERROR: bundle verification FAILED — see above" >&2
    exit 1
}

echo "AppDir created successfully"
'

# v2.0.2: bundle ClamAV (clamscan + full library closure) — HOST side.
# NOTE: the docker build runs as root, so dist/ is root-owned; do the
# bundling with sudo when needed (same pattern as appimagetool below).
echo ""
echo "Bundling ClamAV into the AppImage..."
CLAM_SRC=$(command -v clamscan)
if [ -z "$CLAM_SRC" ]; then
    echo "ERROR: clamscan not found on build host" >&2
    exit 1
fi
CLAM_DIR="${WORK_DIR}/dist/autobahn-defender/_internal/clamav"  # dist/ lives under WORK_DIR
CLAM_CP=""
if [ "$(stat -c '%U' "${WORK_DIR}/dist/autobahn-defender")" = "root" ]; then
    # sudo -A with a temp askpass (pattern from v2-release-publish.md);
    # password never enters the script. SUDO_PASS may be provided via env.
    if [ -n "${SUDO_PASS:-}" ]; then
        ASKPASS_FILE=$(mktemp /tmp/.ad_askpass.XXXXXX)
        chmod 700 "$ASKPASS_FILE"
        printf '#!/bin/bash\necho "%s"\n' "$SUDO_PASS" > "$ASKPASS_FILE"
        CLAM_CP="sudo -A"
        export SUDO_ASKPASS="$ASKPASS_FILE"
    else
        CLAM_CP="sudo -A"  # relies on cached credentials or desktop askpass
    fi
fi
${CLAM_CP} mkdir -p "$CLAM_DIR/lib"
${CLAM_CP} cp "$CLAM_SRC" "$CLAM_DIR/clamscan"
${CLAM_CP} chmod 755 "$CLAM_DIR/clamscan"
# Copy the complete shared-library closure (ldd), excluding the dynamic
# loader + core glibc pieces the host always provides (bundling glibc
# itself breaks the host loader).
ldd "$CLAM_SRC" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^\//) print $i}' | sort -u | while read -r lib; do
    base=$(basename "$lib")
    case "$base" in
        ld-linux*|libc.so*|libm.so*|libpthread*|libdl*|librt*) continue ;;
    esac
    ${CLAM_CP} cp -L "$lib" "$CLAM_DIR/lib/"
done
# RPATH: clamscan + bundled libs resolve dependencies from the private dir
if [ -n "$CLAM_CP" ]; then
    ${CLAM_CP} patchelf --set-rpath '$ORIGIN/lib' "$CLAM_DIR/clamscan" 2>/dev/null || true
    for lib in "$CLAM_DIR"/lib/*.so*; do
        [ -e "$lib" ] || continue
        if head -c 4 "$lib" | grep -q $'\x7fELF'; then
            ${CLAM_CP} patchelf --set-rpath '$ORIGIN' "$lib" 2>/dev/null || true
        fi
    done
else
    patchelf --set-rpath '$ORIGIN/lib' "$CLAM_DIR/clamscan" 2>/dev/null || true
    for lib in "$CLAM_DIR"/lib/*.so*; do
        [ -e "$lib" ] || continue
        if head -c 4 "$lib" | grep -q $'\x7fELF'; then
            patchelf --set-rpath '$ORIGIN' "$lib" 2>/dev/null || true
        fi
    done
fi
# The bundled clamscan must RUN in the build container — hard gate
if ! "$CLAM_DIR/clamscan" --version >/dev/null 2>&1; then
    echo "ERROR: bundled clamscan failed to run (--version) — library closure incomplete" >&2
    "$CLAM_DIR/clamscan" --version || true
    exit 1
fi
echo "ClamAV bundled OK: $("$CLAM_DIR/clamscan" --version | head -1)"

# ── post-bundle verification (full gate incl. ClamAV) ────────────────────────
python3 tools/verify_bundle.py "${WORK_DIR}/dist/autobahn-defender" || {
    echo "ERROR: post-bundle verification FAILED — see above" >&2
    exit 1
}

# Create AppDir structure (host side now — root-owned leftovers from
# previous docker runs are removed with the same sudo-askpass as above)
if [ -d "${BUILD_DIR}/appdir" ] && [ "$(stat -c '%U' "${BUILD_DIR}/appdir")" = "root" ]; then
    ${CLAM_CP} rm -rf "${BUILD_DIR}/appdir"
fi
mkdir -p "${BUILD_DIR}/appdir/usr/bin"
# Clean old _internal to prevent stale files from previous builds
# (may be root-owned even when appdir itself is user-owned)
if [ -d "${BUILD_DIR}/appdir/usr/bin/_internal" ]; then
    OWNER=$(stat -c '%U' "${BUILD_DIR}/appdir/usr/bin/_internal" 2>/dev/null || echo "user")
    if [ "$OWNER" = "root" ]; then
        ${CLAM_CP} rm -rf "${BUILD_DIR}/appdir/usr/bin/_internal"
    else
        rm -rf "${BUILD_DIR}/appdir/usr/bin/_internal"
    fi
fi
cp -a "${WORK_DIR}/dist/autobahn-defender/_internal" "${BUILD_DIR}/appdir/usr/bin/"
cp "${WORK_DIR}/dist/autobahn-defender/autobahn-defender" "${BUILD_DIR}/appdir/usr/bin/"
chmod +x "${BUILD_DIR}/appdir/usr/bin/autobahn-defender"

# Copy icons
mkdir -p "${BUILD_DIR}/appdir/usr/share/icons/hicolor/256x256/apps"
mkdir -p "${BUILD_DIR}/appdir/usr/share/icons/hicolor/512x512/apps"
cp "${WORK_DIR}/256.png" "${BUILD_DIR}/appdir/usr/share/icons/hicolor/256x256/apps/autobahn-defender.png" 2>/dev/null || true
cp "${WORK_DIR}/512.png" "${BUILD_DIR}/appdir/usr/share/icons/hicolor/512x512/apps/autobahn-defender.png" 2>/dev/null || true
cp "${WORK_DIR}/512.png" "${BUILD_DIR}/appdir/autobahn-defender.png" 2>/dev/null || true

# Create desktop file
mkdir -p "${BUILD_DIR}/appdir/usr/share/applications"
cat > "${BUILD_DIR}/appdir/usr/share/applications/com.digitalautobahn.AutobahnDefender.desktop" << "DESKTOP"
[Desktop Entry]
Type=Application
Name=Autobahn Defender
GenericName=Antivirus
Comment=Linux antivirus application by Digital Autobahn
Exec=autobahn-defender
Icon=autobahn-defender
Categories=System;Security;
StartupNotify=true
Terminal=false
DESKTOP

cp "${BUILD_DIR}/appdir/usr/share/applications/com.digitalautobahn.AutobahnDefender.desktop" "${BUILD_DIR}/appdir/"

# Create AppStream metadata
mkdir -p "${BUILD_DIR}/appdir/usr/share/metainfo"
cat > "${BUILD_DIR}/appdir/usr/share/metainfo/com.digitalautobahn.AutobahnDefender.appdata.xml" << "APPDATA"
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>com.digitalautobahn.AutobahnDefender</id>
  <metadata_license>MIT</metadata_license>
  <project_license>MIT</project_license>
  <name>Autobahn Defender</name>
  <summary>Linux antivirus application</summary>
  <description>
    <p>Autobahn Defender is a modern Linux antivirus application using ClamAV and YARA engines.</p>
  </description>
  <launchable type="desktop-id">com.digitalautobahn.AutobahnDefender.desktop</launchable>
  <url type="homepage">https://codeberg.org/donavinschlosser/Autobahn-Defender</url>
  <provides>
    <binary>autobahn-defender</binary>
  </provides>
  <developer id="com.digitalautobahn">
    <name>Donavin K. Schlosser</name>
  </developer>
  <releases>
    <release version="2.0.3" date="2026-09-16">
      <description><p>Parallel ClamAV silent-skip fix: the scan block sat outside the batch loop, so worker threads died with UnboundLocalError and the orphaned block hit an unbound 'clam_env' — parallel ClamAV scans reported 0 files scanned. Fixed (indentation + env binding); structural + runtime regression tests added. YARA unaffected.</p></description>
    </release>
    <release version="2.0.2" date="2026-09-07">
      <description><p>Self-contained AppImage: ClamAV bundled inside (no system installs; definitions download to the user folder); eCryptfs scan-hang fixed (stderr pipe deadlock); stall watchdog; fairer work distribution.</p></description>
    </release>
    <release version="2.0.1" date="2026-09-06">
      <description><p>Hotfix + AI scan engine: bundles the missing AI Agent / Security Center / News tabs and yara-python (fixes the Rootkit scan force-close); QThread crash guards; new autobahn.scan MCP tool for detached file/folder/drive scans with a live progress feed.</p></description>
    </release>
    <release version="2.0.0" date="2026-09-01">
      <description><p>First production 2.0 release: deterministic security engine (no AI model), full CLI (autobahn-defender &lt;verb&gt;), MCP server for AI agents, CISA KEV + Ubuntu USN + EPSS + PoC intel monitor, remediation lifecycle, CVE scanning with Debian-policy version comparison and CVSS 3.1 scoring, patch tracker with verified-fixed loop, active inotify watch, unified findings schema across GUI/CLI/MCP.</p></description>
    </release>
    <release version="1.4" date="2026-07-06">
      <description><p>Version 1.4 release with parallel ClamAV scanning, yara-python integration, 3-tier YARA rules with auto-update from Codeberg, scan engine selection, and security fixes.</p></description>
    </release>
  </releases>
</component>
APPDATA

# Create AppRun launcher
cat > "${BUILD_DIR}/appdir/AppRun" << "APPRUN"
#!/bin/bash
SELF=$(readlink -f "$0")
HERE=${SELF%/*}
export PATH="${HERE}/usr/bin:${PATH}"
exec "${HERE}/usr/bin/autobahn-defender" "$@"
APPRUN
chmod +x "${BUILD_DIR}/appdir/AppRun"

# Create AppImage
echo ""
echo "Creating AppImage..."

if [ ! -f "${SCRIPT_DIR}/appimagetool" ]; then
    echo "Downloading appimagetool..."
    wget -q "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" -O "${SCRIPT_DIR}/appimagetool"
    chmod +x "${SCRIPT_DIR}/appimagetool"
fi

cd "${SCRIPT_DIR}"
# AppDir is root-owned (created inside Docker), use sudo for appimagetool if needed
APPIMAGETOOL_PATH="${SCRIPT_DIR}/appimagetool"
APPIMAGETOOL_SUDO=""
if [ "$(stat -c '%U' "${BUILD_DIR}/appdir")" = "root" ]; then
    if [ -n "${SUDO_PASS:-}" ] && [ -n "${SUDO_ASKPASS:-}" ] && [ -f "${SUDO_ASKPASS}" ]; then
        APPIMAGETOOL_SUDO="sudo -A"  # askpass helper from the bundling step
    else
        APPIMAGETOOL_SUDO="sudo -A"
    fi
fi
${APPIMAGETOOL_SUDO} env ARCH=x86_64 "${APPIMAGETOOL_PATH}" -n "${BUILD_DIR}/appdir"

# Handle different naming conventions
if [ -f "Autobahn_Defender-x86_64.AppImage" ]; then
    mv "Autobahn_Defender-x86_64.AppImage" "${SCRIPT_DIR}/AutobahnDefender.AppImage"
elif [ -f "AutobahnDefender-x86_64.AppImage" ]; then
    mv "AutobahnDefender-x86_64.AppImage" "${SCRIPT_DIR}/AutobahnDefender.AppImage"
fi

# Fix ownership if created by root
if [ -f "${SCRIPT_DIR}/AutobahnDefender.AppImage" ] && [ "$(stat -c '%U' "${SCRIPT_DIR}/AutobahnDefender.AppImage")" = "root" ]; then
    chown "${USER:=$(whoami)}:${USER}" "${SCRIPT_DIR}/AutobahnDefender.AppImage" 2>/dev/null || true
fi

if [ -f "${SCRIPT_DIR}/AutobahnDefender.AppImage" ]; then
    echo ""
    echo "=== Build Complete ==="
    echo "AppImage created: ${SCRIPT_DIR}/AutobahnDefender.AppImage"
    echo "Size: $(du -h "${SCRIPT_DIR}/AutobahnDefender.AppImage" | cut -f1)"
else
    echo "ERROR: AppImage creation failed"
    exit 1
fi

# Cleanup
if [ -n "${ASKPASS_FILE:-}" ]; then
    rm -f "$ASKPASS_FILE"  # delete the askpass helper immediately
fi
sudo rm -rf "${WORK_DIR}" 2>/dev/null || rm -rf "${WORK_DIR}" 2>/dev/null || true
