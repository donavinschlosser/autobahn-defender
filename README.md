<div align="center">
  <img src="512.png" alt="Autobahn Defender Logo" width="128" height="128">
  <h1>Autobahn Defender</h1>
  <p>A modern Linux antivirus application using ClamAV and YARA engines, built with PyQt6.</p>
</div>

## Screenshots

| Dashboard | Scan | Quarantine | Settings |
|-----------|------|------------|----------|
| ![Dashboard](Screenshots/dashboard.png) | ![Scan](Screenshots/scan.png) | ![Quarantine](Screenshots/quarantine.png) | ![Settings](Screenshots/settings.png) |

| History | About | System Tray (Zorin OS) | Scan Report |
|---------|-------|------------------------|-------------|
| ![History](Screenshots/history.png) | ![About](Screenshots/about.png) | ![System Tray](Screenshots/systemtray_zorinOS.png) | ![Scan Report](Screenshots/scan_report.png) |

## Features

### Scanning Engines
- **ClamAV Integration** — Full ClamAV scanning with custom or system definitions
- **YARA Rules** — Ships with the YARA Forge Core rule set (5,083 curated rules) out of the box
- **Process Scanning** — Detect suspicious processes, crypto-miners, and high-CPU anomalies

### Scan Types
- **Home Scan** — Scans Downloads, Documents, and Desktop directories
- **Full System Scan** — Complete filesystem scan (best with root privileges)
- **External Drives Scan** — Scans mounted USB and external media
- **Custom Scan** — Choose a specific directory to scan
- **Rootkit Scan** — Scans `/usr/bin`, `/usr/sbin`, and `/usr/lib` for rootkits
- **Process Scan** — Analyzes running processes for suspicious activity

### Scan Options (Configurable in Settings)
- **Archive Scanning** — Scan inside compressed files (zip, tar, rar, 7z, etc.). On by default, can be toggled off for speed.
- **Hidden File Scanning** — Scan hidden files and directories (dotfiles). On by default.
- **Parallel Scan Threads** — Configure how many paths YARA scans simultaneously. Defaults to 25% of CPU cores (minimum 1).

### Real-Time Protection
- **USB Monitoring** — Auto-scan newly connected USB/removable drives
- **File Watching** — Monitor up to 3 custom directories for real-time scanning
- **Scheduled Scans** — Set up recurring scans at configurable intervals (12h, daily, 5/15/30 days)

### Quarantine Management
- Move infected files to a secure quarantine directory
- Restore or permanently delete quarantined files
- SHA256 hash verification for quarantined files
- 3-pass secure file deletion with overwrite

### System Security Tools
- **Kernel Module Checker** — Detect suspicious, unsigned, or unknown kernel modules
- **System Audit (Hardening)** — Check firewall, SSH config, file permissions, and more
- **Firewall Management** — View and apply UFW/firewalld rules

### Definition Updates
- Download and update ClamAV virus definitions directly from within the app
- One-click definition updates from the Settings tab or Dashboard
- Automatic 24-hour periodic definition check on launch and in background
- Downloads all three definition databases (main.cvd, daily.cvd, bytecode.cvd) with HTTP fallback

### Application Updates
- Check for new versions from Codeberg releases
- Download and install updates (AppImage, deb, or Arch package)

### History & Reporting
- Scan history with timestamps, file counts, and threat counts
- Quarantine history log
- Audit history for hardening checks
- Export scan reports to HTML

## Installation

### AppImage (Recommended for all distributions)

The AppImage is fully self-contained — no Python, PyQt6, or other dependencies needed. Built with glibc 2.35 compatibility for broad Linux support (Linux Mint 20+, Ubuntu 20.04+, etc.).

1. Download `AutobahnDefender.AppImage` from the [latest release](https://codeberg.org/donavinschlosser/Autobahn-Defender/releases)
2. Make it executable:
   ```bash
   chmod +x AutobahnDefender.AppImage
   ```
3. Run it:
   ```bash
   ./AutobahnDefender.AppImage
   ```

**Installing with Gear Lever (recommended):**

Gear Lever is a graphical AppImage manager that creates desktop entries and keeps AppImages organized.

1. Install Gear Lever from your distribution's package manager or [Flathub](https://flathub.org/en/apps/it.mijorus.gearlever)
2. Open Gear Lever
3. Drag and drop the `AutobahnDefender.AppImage` file into Gear Lever
4. Gear Lever will integrate it into your application menu automatically

On first run, the app will also automatically install a `.desktop` file to `~/.local/share/applications/` for proper window grouping, icon resolution, and Wayland portal support.

### Debian/Ubuntu (.deb package)

1. Download `autobahn-defender_1.0_amd64.deb` from the [latest release](https://codeberg.org/donavinschlosser/Autobahn-Defender/releases)
2. Install it:
   ```bash
   sudo dpkg -i autobahn-defender_1.0_amd64.deb
   sudo apt-get install -f  # Fix any missing dependencies
   ```
3. Launch from your application menu or run `autobahn-defender`
4. On first launch, the app will prompt to install ClamAV and YARA if missing. You can also install them manually:
   ```bash
   sudo apt install clamav clamav-freshclam yara python3-psutil
   ```

The .deb package also:
- Runs freshclam during installation to pre-download virus definitions
- Disables the system `clamav-freshclam` service (the app manages its own definition updates internally)

### Arch Linux (.pkg.tar.zst package)

1. Download `autobahn-defender-1.0-5-x86_64.pkg.tar.zst` from the [latest release](https://codeberg.org/donavinschlosser/Autobahn-Defender/releases)
2. Install it:
   ```bash
   sudo pacman -U autobahn-defender-1.0-5-x86_64.pkg.tar.zst
   ```
3. Launch from your application menu or run `autobahn-defender`
4. Install scanning engines:
   ```bash
   sudo pacman -S clamav yara python-psutil
   ```

### From Source

**Prerequisites:**
- Python 3.10+
- PyQt6
- ClamAV (optional, for virus scanning)
- YARA (optional, for pattern matching)
- psutil (optional, for process scanning)

**Steps:**
```bash
git clone https://codeberg.org/donavinschlosser/Autobahn-Defender.git
cd Autobahn-Defender
pip install -r requirements.txt
python main.py
```

**Building a standalone binary (PyInstaller):**
```bash
pip install pyinstaller
pyinstaller AutobahnDefender.spec --noconfirm
```
The binary will be at `dist/autobahn-defender`.

**Building an AppImage (Docker-based for glibc compatibility):**
```bash
bash build_appimage.sh
```
This builds inside Docker with Ubuntu 22.04 (glibc 2.35) for maximum compatibility.
The resulting `AutobahnDefender.AppImage` will work on Linux Mint 20+, Ubuntu 20.04+, and other older distributions.

**Building a DEB package:**
```bash
bash build_deb.sh
```
This extracts an existing AppImage and packages it into a `.deb`. Requires `AutobahnDefender.AppImage` to exist first.

## Dependencies for Scanning

Autobahn Defender works without scanning engines installed, but for actual virus detection you need at least one:

| Engine | Install | Used For |
|--------|---------|----------|
| ClamAV | `sudo apt install clamav` or `sudo pacman -S clamav` | Virus scanning with signature database |
| YARA | `sudo apt install yara` or `sudo pacman -S yara` | Pattern matching and YARA Forge rule scanning |
| psutil | `pip install psutil` | Process scanning (crypto-miner detection) |

The app will detect missing dependencies on launch and offer to install them for you.

## YARA Rules

Autobahn Defender ships with the **YARA Forge Core** rule set (5,083 curated rules from 45+ security repositories) as a single file, providing production-quality malware detection **out of the box** with no download or configuration required. The Core set is a curated subset focused on high-accuracy, low false-positive detection of Linux malware, cryptominers, rootkits, trojans, and ransomware.

Sources include: ESET, BlackBerry, CAPE, FireEye, Check Point, Florian Roth (Nextron Systems), Arkbird SOLG, DitekSHen, Elastic, and many more.

The bundled rules file is `rules/autobahn-defender-rules.yar` and is automatically copied to `~/.autobahn/rules/` on first launch. Custom rules can be added to `~/.autobahn/rules/` (any `.yar` file) and are automatically merged on the next scan.

## Configuration

Settings are stored using Qt's QSettings and persist across sessions:

- **Real-Time Monitoring** — File watching and USB auto-scan
- **Scheduled Scans** — Frequency, time, and scan type
- **YARA Rules** — Custom rule editor with download capability
- **Virus Definitions** — Update ClamAV definitions from within the app
- **Scan Options** — Archive scanning, hidden file scanning, thread count
- **Whitelist** — Exclude paths from all scans
- **Firewall** — View and apply firewall rules

## Project Structure

```
main.py              — Application entry point, main window, and tray icon
ui_tabs.py           — All UI tab widgets (Dashboard, Scan, Quarantine, etc.)
scanner.py           — Core scanning engine (ClamAV + YARA + process scanning)
settings.py          — Persistent settings manager
quarantine.py        — Quarantine file management with secure deletion
updater.py           — Application update checker and installer
history_db.py        — SQLite database for scan/quarantine/audit history
kernel_checker.py    — Kernel module security checker
firewall.py          — Firewall detection and rule management
hardening.py         — System hardening audit checks
usb_monitor.py       — USB device detection and auto-scanning

AutobahnDefender.spec — PyInstaller build specification
build_appimage.sh     — Docker-based AppImage builder (glibc 2.35)
build_deb.sh          — DEB package builder
build_arch/           — Arch Linux PKGBUILD and package builder

rules/                — YARA Forge Core rule set (5,083 rules)
icons/                — Application icons
Screenshots/          — Screenshots for README
```

### Build Notes

**OpenSSL Compatibility:** The PyInstaller spec (`AutobahnDefender.spec`) excludes bundled `libcrypto*` and `libssl*` to avoid conflicts with the system ClamAV's OpenSSL version. The system's OpenSSL is used at runtime instead, ensuring compatibility across distributions.

**ClamAV Definition Updates:** Definitions are downloaded via freshclam in the user's home directory (`~/.autobahn/definitions/`). If freshclam exits with only partial downloads (e.g., only `daily.cvd`), the app falls back to direct HTTP download from ClamAV mirrors to ensure all three databases (`main.cvd`, `daily.cvd`, `bytecode.cvd`) are present.

## License

MIT License — See [LICENSE](LICENSE) for details.
