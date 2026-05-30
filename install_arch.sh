#!/bin/bash
# Autobahn Defender - Arch Linux / Manjaro / EndeavourOS Installer
# Just double-click this script or run: bash install_arch.sh
# Detects your distro and installs the package with the right tool.

set -e

PKG_FILE="build_arch/autobahn-defender-1.2-5-x86_64.pkg.tar.zst"

echo "====================================="
echo " Autobahn Defender Arch Installer"
echo "====================================="
echo ""

# Check if running on an Arch-based distro
if [ ! -f /etc/arch-release ] && [ ! -f /etc/manjaro-release ] && [ ! -f /etc/endeavouros-release ] && ! grep -qi "arch" /etc/os-release 2>/dev/null; then
    echo "WARNING: This installer is for Arch Linux, Manjaro, EndeavourOS, or"
    echo "         other Arch-based distributions."
    echo ""
    echo "If you're on Debian/Ubuntu, use the .deb package instead."
    echo "If you're on another distro, use the AppImage (works everywhere)."
    echo ""
    read -rp "Continue anyway? [y/N] " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "Installation cancelled."
        exit 1
    fi
fi

# Find the script directory (works even when double-clicked or sourced)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_PATH="${SCRIPT_DIR}/${PKG_FILE}"

# Check if the package file exists
if [ ! -f "$PKG_PATH" ]; then
    echo "ERROR: Package file not found at:"
    echo "  ${PKG_PATH}"
    echo ""
    echo "Make sure you're running this script from inside the Autobahn Defender"
    echo "repository directory, or run 'build_arch.sh' first to build the package."
    exit 1
fi

echo "Package: $(basename "${PKG_PATH}")"
echo "Size:    $(du -h "${PKG_PATH}" | cut -f1)"
echo ""

# Check if running as root
if [ "$(id -u)" -eq 0 ]; then
    echo "Running as root — installing directly..."
    echo ""
    pacman -U "${PKG_PATH}"
else
    # Check for sudo
    if ! command -v sudo &>/dev/null; then
        echo "ERROR: 'sudo' is required but not found."
        echo "Please run this script as root instead:"
        echo "  su -c 'bash install_arch.sh'"
        exit 1
    fi

    echo "Installing with sudo..."
    echo "Your password may be required to install system packages."
    echo ""

    # Install dependencies first
    echo "Checking dependencies..."
    MISSING_DEPS=()
    for dep in clamav yara libgl; do
        if ! pacman -Qi "$dep" &>/dev/null; then
            MISSING_DEPS+=("$dep")
        fi
    done

    if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
        echo "Installing missing dependencies: ${MISSING_DEPS[*]}"
        sudo pacman -S --needed "${MISSING_DEPS[@]}"
    else
        echo "All dependencies already satisfied."
    fi

    echo ""
    echo "Installing Autobahn Defender..."
    sudo pacman -U "${PKG_PATH}"
fi

echo ""
echo "====================================="
echo " Installation Complete!"
echo "====================================="
echo ""
echo "You can now launch Autobahn Defender from your application menu"
echo "or by running: autobahn-defender"
echo ""
echo "Scanning engines:"
echo "  - ClamAV: Already installed (definitions may download on first launch)"
echo "  - YARA:   Already installed"
echo ""
echo "Need help? Visit:"
echo "  https://codeberg.org/donavinschlosser/Autobahn-Defender"
