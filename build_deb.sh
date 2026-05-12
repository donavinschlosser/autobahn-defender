#!/bin/bash
# Build script for Autobahn Defender DEB package
# This creates a DEB package from the AppImage for distribution

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_NAME="autobahn-defender"
PACKAGE_VERSION="1.0"

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

# Extract the AppImage using the built-in extraction
echo "Extracting AppImage..."
cd "${BUILD_DIR}"

# Try to extract using the AppImage's built-in extraction
if ! "${SCRIPT_DIR}/AutobahnDefender.AppImage" --appimage-extract >/dev/null 2>&1; then
    echo "ERROR: Could not extract AppImage"
    exit 1
fi

if [ ! -d "${BUILD_DIR}/squashfs-root" ]; then
    echo "ERROR: Extraction failed - squashfs-root not found"
    exit 1
fi

echo "AppImage extracted to squashfs-root"

# Copy the binary
cp "${BUILD_DIR}/squashfs-root/usr/bin/autobahn-defender" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/bin/"
chmod +x "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/bin/autobahn-defender"

# Copy icons
cp "${BUILD_DIR}/squashfs-root/usr/share/icons/hicolor/256x256/apps/autobahn-defender.png" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/icons/hicolor/256x256/apps/" 2>/dev/null || cp "${SCRIPT_DIR}/256.png" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/icons/hicolor/256x256/apps/autobahn-defender.png"
cp "${BUILD_DIR}/squashfs-root/usr/share/icons/hicolor/512x512/apps/autobahn-defender.png" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/icons/hicolor/512x512/apps/" 2>/dev/null || cp "${SCRIPT_DIR}/512.png" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/icons/hicolor/512x512/apps/autobahn-defender.png"

# Copy desktop file
cp "${BUILD_DIR}/squashfs-root/usr/share/applications/com.digitalautobahn.AutobahnDefender.desktop" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/applications/" 2>/dev/null || cp "${SCRIPT_DIR}/build_deb/autobahn-defender_1.0_amd64/com.digitalautobahn.AutobahnDefender.desktop" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/applications/"

# Copy AppStream metadata
cp "${BUILD_DIR}/squashfs-root/usr/share/metainfo/com.digitalautobahn.AutobahnDefender.appdata.xml" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/metainfo/" 2>/dev/null || cp "${SCRIPT_DIR}/build_deb/autobahn-defender_1.0_amd64/com.digitalautobahn.AutobahnDefender.desktop" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/usr/share/metainfo/"

# Copy DEBIAN control files
cp -r "${SCRIPT_DIR}/build_deb/autobahn-defender_1.0_amd64/DEBIAN" "${BUILD_DIR}/${PACKAGE_NAME}_${PACKAGE_VERSION}_amd64/"

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
