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
cp -r "${SCRIPT_DIR}/rules" "${WORK_DIR}/"

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

# Create AppDir structure
mkdir -p /output/appdir/usr/bin
# Clean old _internal to prevent stale files from previous builds
rm -rf /output/appdir/usr/bin/_internal 2>/dev/null || true
cp -a dist/autobahn-defender/_internal /output/appdir/usr/bin/
cp dist/autobahn-defender/autobahn-defender /output/appdir/usr/bin/
chmod +x /output/appdir/usr/bin/autobahn-defender

# Copy icons
cp 256.png /output/appdir/usr/share/icons/hicolor/256x256/apps/autobahn-defender.png 2>/dev/null || true
cp 512.png /output/appdir/usr/share/icons/hicolor/512x512/apps/autobahn-defender.png 2>/dev/null || true
cp 512.png /output/appdir/autobahn-defender.png 2>/dev/null || true

# Create desktop file
mkdir -p /output/appdir/usr/share/applications
cat > /output/appdir/usr/share/applications/com.digitalautobahn.AutobahnDefender.desktop << "DESKTOP"
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

cp /output/appdir/usr/share/applications/com.digitalautobahn.AutobahnDefender.desktop /output/appdir/

# Create AppStream metadata
mkdir -p /output/appdir/usr/share/metainfo
cat > /output/appdir/usr/share/metainfo/com.digitalautobahn.AutobahnDefender.appdata.xml << "APPDATA"
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
    <release version="1.3" date="2026-06-26">
      <description><p>Version 1.3 release with start minimized to tray, Windows malware detection (opt-in), file-type pre-filtering, YARA rule caching and batch scanning, color-coded UI with tab fade transitions, and numerous security fixes.</p></description>
    </release>
    <release version="1.2" date="2026-05-30">
      <description><p>Version 1.2 release with consolidated fixes, broadened file scanning, process exemptions, first-launch setup wizard, and smart update detection.</p></description>
    </release>
  </releases>
</component>
APPDATA

# Create AppRun launcher
cat > /output/appdir/AppRun << "APPRUN"
#!/bin/bash
SELF=$(readlink -f "$0")
HERE=${SELF%/*}
export PATH="${HERE}/usr/bin:${PATH}"
exec "${HERE}/usr/bin/autobahn-defender" "$@"
APPRUN
chmod +x /output/appdir/AppRun

echo "AppDir created successfully"
'

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
    APPIMAGETOOL_SUDO="sudo"
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
sudo rm -rf "${WORK_DIR}" 2>/dev/null || rm -rf "${WORK_DIR}" 2>/dev/null || true
