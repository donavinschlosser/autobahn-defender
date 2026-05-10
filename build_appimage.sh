#!/bin/bash
# Build script for Autobahn Defender portable AppImage
# Packages the PyInstaller binary for a fully self-contained, portable AppImage
# Requires: pyinstaller, appimagetool

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_appimage"
APPDIR="${BUILD_DIR}/AutobahnDefender.AppDir"
DIST_DIR="${SCRIPT_DIR}/dist"

echo "=== Building Autobahn Defender Portable AppImage ==="

# Step 1: Build the PyInstaller binary first
echo "Building PyInstaller binary..."
cd "${SCRIPT_DIR}"
rm -rf "${SCRIPT_DIR}/build/AutobahnDefender"
pyinstaller AutobahnDefender.spec --noconfirm

if [ ! -f "${DIST_DIR}/autobahn-defender" ]; then
    echo "ERROR: PyInstaller binary not found at ${DIST_DIR}/autobahn-defender"
    exit 1
fi

echo "PyInstaller binary built successfully ($(du -h "${DIST_DIR}/autobahn-defender" | cut -f1))"

# Step 2: Create AppDir structure
echo "Creating AppDir..."
rm -rf "${APPDIR}"
mkdir -p "${APPDIR}/usr/bin"
mkdir -p "${APPDIR}/usr/share/applications"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/256x256/apps"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/512x512/apps"
mkdir -p "${APPDIR}/usr/share/metainfo"

# Step 3: Copy the self-contained PyInstaller binary and bundled data
echo "Copying PyInstaller binary and data..."
cp "${DIST_DIR}/autobahn-defender" "${APPDIR}/usr/bin/"
chmod +x "${APPDIR}/usr/bin/autobahn-defender"

# Copy icons for desktop integration
cp "${SCRIPT_DIR}/256.png" "${APPDIR}/usr/share/icons/hicolor/256x256/apps/autobahn-defender.png"
cp "${SCRIPT_DIR}/512.png" "${APPDIR}/usr/share/icons/hicolor/512x512/apps/autobahn-defender.png"
cp "${SCRIPT_DIR}/512.png" "${APPDIR}/autobahn-defender.png"

# Step 4: Create desktop file
cat > "${APPDIR}/usr/share/applications/com.digitalautobahn.AutobahnDefender.desktop" << EOF
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
EOF

cp "${APPDIR}/usr/share/applications/com.digitalautobahn.AutobahnDefender.desktop" "${APPDIR}/"

# Step 5: Create AppStream metadata
cat > "${APPDIR}/usr/share/metainfo/com.digitalautobahn.AutobahnDefender.appdata.xml" << EOF
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
    <release version="1.0" date="2025-05-09">
      <description><p>Initial release of Autobahn Defender.</p></description>
    </release>
  </releases>
</component>
EOF

# Step 6: Create AppRun launcher
cat > "${APPDIR}/AppRun" << 'APPRUN'
#!/bin/bash
SELF=$(readlink -f "$0")
HERE=${SELF%/*}
export PATH="${HERE}/usr/bin:${PATH}"
exec "${HERE}/usr/bin/autobahn-defender" "$@"
APPRUN
chmod +x "${APPDIR}/AppRun"

echo "AppDir created at: ${APPDIR}"
echo ""
echo "To create the portable AppImage, run:"
echo "  ARCH=x86_64 appimagetool ${APPDIR}"
echo ""
echo "This AppImage is fully self-contained — no Python or PyQt6 needed on the target system."