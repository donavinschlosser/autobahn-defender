#!/bin/bash
# Build script for Autobahn Defender DEB package
# This creates a DEB package from the AppImage for distribution

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_NAME="autobahn-defender"
PACKAGE_VERSION="1.1"

echo "=== Building Autobahn Defender DEB Package ==="

# Check if AppImage exists
if [ ! -f "${SCRIPT_DIR}/AutobahnDefender.AppImage" ]; then
    echo "ERROR: AppImage not found. Please build it first:"
    echo "  cd '${SCRIPT_DIR}' && ./build_appimage.sh"
    exit 1
fi

# Create temporary build directory
BUILD_DIR="${SCRIPT_DIR}/build_deb_temp"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/bin"
mkdir -p "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/applications"
mkdir -p "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/icons/hicolor/256x256/apps"
mkdir -p "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/icons/hicolor/512x512/apps"
mkdir -p "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/metainfo"

# Extract the AppImage
echo "Extracting AppImage..."
cd "${BUILD_DIR}"

# Try to extract using the AppImage's built-in extraction (with FUSE-less env var)
if env APPIMAGE_EXTRACT_AND_RUN=1 "${SCRIPT_DIR}/AutobahnDefender.AppImage" --appimage-extract >/dev/null 2>&1; then
    echo "AppImage extracted via --appimage-extract"
elif command -v unsquashfs &>/dev/null; then
    echo "Trying direct squashfs extraction..."
    python3 -c "
import struct
with open('${SCRIPT_DIR}/AutobahnDefender.AppImage', 'rb') as f:
    data = f.read()
for i in range(0, min(1000000, len(data)), 4):
    if data[i:i+4] == b'hsqs':
        with open('${BUILD_DIR}/autobahn.squashfs', 'wb') as out:
            out.write(data[i:])
        break
" 2>/dev/null
    if [ -f "${BUILD_DIR}/autobahn.squashfs" ]; then
        unsquashfs -f -d "${BUILD_DIR}/squashfs-root" "${BUILD_DIR}/autobahn.squashfs" >/dev/null 2>&1
        rm -f "${BUILD_DIR}/autobahn.squashfs"
    fi
fi

if [ ! -d "${BUILD_DIR}/squashfs-root" ]; then
    echo "ERROR: Could not extract AppImage"
    echo "Try: sudo apt-get install squashfs-tools"
    exit 1
fi

echo "AppImage extracted to squashfs-root"

# Copy the binary and its _internal directory
cp "${BUILD_DIR}/squashfs-root/usr/bin/autobahn-defender" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/bin/"
chmod +x "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/bin/autobahn-defender"

# Copy the _internal directory (needed by PyInstaller --onedir mode)
if [ -d "${BUILD_DIR}/squashfs-root/usr/bin/_internal" ]; then
    cp -a "${BUILD_DIR}/squashfs-root/usr/bin/_internal" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/bin/"
fi

# Copy icons
cp "${BUILD_DIR}/squashfs-root/usr/share/icons/hicolor/256x256/apps/autobahn-defender.png" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/icons/hicolor/256x256/apps/" 2>/dev/null || cp "${SCRIPT_DIR}/256.png" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/icons/hicolor/256x256/apps/autobahn-defender.png"
cp "${BUILD_DIR}/squashfs-root/usr/share/icons/hicolor/512x512/apps/autobahn-defender.png" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/icons/hicolor/512x512/apps/" 2>/dev/null || cp "${SCRIPT_DIR}/512.png" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/icons/hicolor/512x512/apps/autobahn-defender.png"

# Copy desktop file
cp "${BUILD_DIR}/squashfs-root/usr/share/applications/com.digitalautobahn.AutobahnDefender.desktop" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/applications/" 2>/dev/null || cp "${SCRIPT_DIR}/build_deb/autobahn-defender_1.1_amd64/com.digitalautobahn.AutobahnDefender.desktop" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/applications/"

# Copy AppStream metadata
cp "${BUILD_DIR}/squashfs-root/usr/share/metainfo/com.digitalautobahn.AutobahnDefender.appdata.xml" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/metainfo/" 2>/dev/null || true

# Copy DEBIAN control files
cp -r "${SCRIPT_DIR}/build_deb/autobahn-defender_1.1_amd64/DEBIAN" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/"

# Verify OpenSSL libraries are not bundled (before building DEB)
echo ""
echo "Checking for OpenSSL libraries in extracted AppImage..."
OPENSSL_LIBS=$(find "${BUILD_DIR}/squashfs-root/usr/bin" -name 'libcrypto.so*' -o -name 'libssl.so*' 2>/dev/null)
if [ -n "$OPENSSL_LIBS" ]; then
    echo "ERROR: OpenSSL libraries found in extracted AppImage (should be excluded):"
    echo "$OPENSSL_LIBS"
    exit 1
else
    echo "OK: No OpenSSL libraries (libcrypto/libssl) found in bundle"
fi

# Build the DEB package
echo ""
echo "Building DEB package..."

# Create the DEB package
dpkg-deb --build --root-owner-group "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64" "${SCRIPT_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64.deb"

echo ""
echo "=== Build Complete ==="
echo "DEB package created: ${SCRIPT_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64.deb"
echo "Size: $(du -h "${SCRIPT_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64.deb" | cut -f1)"

# Cleanup
rm -rf "${BUILD_DIR}" "${SCRIPT_DIR}/squashfs-root" 2>/dev/null || sudo rm -rf "${BUILD_DIR}" "${SCRIPT_DIR}/squashfs-root" 2>/dev/null || true

# Show package info
echo ""
echo "Package contents:"
dpkg-deb -c "${SCRIPT_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64.deb"

echo ""
echo "Package info:"
dpkg-deb -I "${SCRIPT_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64.deb"
