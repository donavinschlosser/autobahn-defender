#!/bin/bash
# Build script for Linux Mint
# Run this in the "Autobahn Defender" directory on Linux Mint

set -e

echo "=== Building Autobahn Defender for Linux Mint ==="

# Activate virtual environment if it exists
if [ -d "$HOME/autobahn-venv" ]; then
    source "$HOME/autobahn-venv/bin/activate"
    echo "Using virtual environment: $HOME/autobahn-venv"
fi

# Step 1: Clean and build PyInstaller binary
echo ""
echo "Step 1: Building PyInstaller binary..."
rm -rf build dist
pyinstaller AutobahnDefender.spec --noconfirm

if [ ! -f "dist/autobahn-defender" ]; then
    echo "ERROR: PyInstaller binary not found"
    exit 1
fi
echo "PyInstaller binary built successfully: $(du -h dist/autobahn-defender | cut -f1)"

# Step 2: Create AppDir structure
echo ""
echo "Step 2: Creating AppDir structure..."
rm -rf build_appimage
mkdir -p build_appimage/AutobahnDefender.AppDir/usr/bin
mkdir -p build_appimage/AutobahnDefender.AppDir/usr/share/applications
mkdir -p build_appimage/AutobahnDefender.AppDir/usr/share/icons/hicolor/256x256/apps
mkdir -p build_appimage/AutobahnDefender.AppDir/usr/share/icons/hicolor/512x512/apps
mkdir -p build_appimage/AutobahnDefender.AppDir/usr/share/metainfo

# Step 3: Copy files to AppDir
echo ""
echo "Step 3: Copying files to AppDir..."
cp dist/autobahn-defender build_appimage/AutobahnDefender.AppDir/usr/bin/
chmod +x build_appimage/AutobahnDefender.AppDir/usr/bin/autobahn-defender

cp 256.png build_appimage/AutobahnDefender.AppDir/usr/share/icons/hicolor/256x256/apps/autobahn-defender.png
cp 512.png build_appimage/AutobahnDefender.AppDir/usr/share/icons/hicolor/512x512/apps/autobahn-defender.png
cp 512.png build_appimage/AutobahnDefender.AppDir/autobahn-defender.png

# Step 4: Create desktop file
echo ""
echo "Step 4: Creating desktop file..."
cat > build_appimage/AutobahnDefender.AppDir/usr/share/applications/com.digitalautobahn.AutobahnDefender.desktop << 'DESKTOP'
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

cp build_appimage/AutobahnDefender.AppDir/usr/share/applications/com.digitalautobahn.AutobahnDefender.desktop build_appimage/AutobahnDefender.AppDir/

# Step 5: Create AppStream metadata
echo ""
echo "Step 5: Creating AppStream metadata..."
cat > build_appimage/AutobahnDefender.AppDir/usr/share/metainfo/com.digitalautobahn.AutobahnDefender.appdata.xml << 'APPDATA'
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
APPDATA

# Step 6: Create AppRun launcher
echo ""
echo "Step 6: Creating AppRun launcher..."
cat > build_appimage/AutobahnDefender.AppDir/AppRun << 'APPRUN'
#!/bin/bash
SELF=$(readlink -f "$0")
HERE=${SELF%/*}
export PATH="${HERE}/usr/bin:${PATH}"
exec "${HERE}/usr/bin/autobahn-defender" "$@"
APPRUN
chmod +x build_appimage/AutobahnDefender.AppDir/AppRun

# Step 7: Download appimagetool if needed
echo ""
echo "Step 7: Checking appimagetool..."
if [ ! -f appimagetool ]; then
    echo "Downloading appimagetool..."
    wget -q "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" -O appimagetool
    chmod +x appimagetool
fi

# Step 8: Create AppImage
echo ""
echo "Step 8: Creating AppImage..."
ARCH=x86_64 ./appimagetool -n build_appimage/AutobahnDefender.AppDir

# Check for AppImage with either naming convention
APPIMAGE_FILE=""
for name in "AutobahnDefender-x86_64.AppImage" "Autobahn_Defender-x86_64.AppImage"; do
    if [ -f "$name" ]; then
        APPIMAGE_FILE="$name"
        break
    fi
done

if [ -n "$APPIMAGE_FILE" ]; then
    mkdir -p Packages
    mv "$APPIMAGE_FILE" Packages/
    echo "AppImage created: Packages/AutobahnDefender-x86_64.AppImage"
else
    echo "ERROR: AppImage creation failed"
    exit 1
fi

# Step 9: Create DEB package
echo ""
echo "Step 9: Creating DEB package..."
mkdir -p Packages/DEBIAN
mkdir -p Packages/usr/bin
mkdir -p Packages/usr/share/applications
mkdir -p Packages/usr/share/icons/hicolor/256x256/apps
mkdir -p Packages/usr/share/icons/hicolor/512x512/apps
mkdir -p Packages/usr/share/metainfo

cp dist/autobahn-defender Packages/usr/bin/
chmod +x Packages/usr/bin/autobahn-defender

cp 256.png Packages/usr/share/icons/hicolor/256x256/apps/autobahn-defender.png
cp 512.png Packages/usr/share/icons/hicolor/512x512/apps/autobahn-defender.png

cp build_appimage/AutobahnDefender.AppDir/usr/share/applications/com.digitalautobahn.AutobahnDefender.desktop Packages/usr/share/applications/
cp build_appimage/AutobahnDefender.AppDir/usr/share/metainfo/com.digitalautobahn.AutobahnDefender.appdata.xml Packages/usr/share/metainfo/

cat > Packages/DEBIAN/control << 'CONTROL'
Package: autobahn-defender
Version: 1.0
Architecture: amd64
Maintainer: Donavin Schlosser <donavinschlosser@live.com>
Description: Linux antivirus application using ClamAV and YARA engines
 Autobahn Defender provides real-time protection, scheduled scanning,
 and quarantine management for Linux systems.
Depends: libgl1, libxkbcommon0, libxcb-xinerama0
Section: security
Priority: optional
CONTROL

dpkg-deb --build --root-owner-group Packages/ Packages/autobahn-defender_1.0_amd64.deb

echo ""
echo "=== Build Complete ==="
echo "All packages are in the Packages folder:"
ls -la Packages/
