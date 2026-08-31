#!/usr/bin/env python3
"""
Autobahn Defender v2.0 - Main Application Entry Point
A modern Linux antivirus application by Digital Autobahn.
v2.0 Security Center: deterministic security engine (no AI model required)
with CVE scanning, patch tracking, hardening actions, network watch,
privacy shield, and persistence scanning.

Contact: XMPP digitalautobahn@xmpp.brax.me
"""

import os
import shutil
import sys
import threading

# Suppress KDE/KIO warnings that appear on KDE Plasma
os.environ.setdefault("QT_LOGGING_RULES", "kf.kio.core=false;kf.windowsystem=false;qt.qpa.services=false")
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStackedWidget, QSystemTrayIcon, QMessageBox,
    QSplashScreen, QMenu, QDialog, QTextEdit, QProgressBar
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QObject
from PyQt6.QtGui import QPixmap, QIcon, QFont, QColor

from scanner import Scanner, ensure_dirs, get_defs_last_updated, DEFS_DIR
from settings import SettingsManager
from quarantine import QuarantineManager
from ui_tabs import DashboardTab, ScanTab, QuarantineTab, SettingsTab, AboutTab, HistoryTab, STYLESHEET, DefsUpdateDialog
from updater import AppUpdater
from yara_updater import YaraRuleUpdater, get_yara_last_updated
from history_db import init_db

# v2.0 Security Center (deterministic engine — no AI model required)
# Replaces the old AI Security module (Ollama/LFM2.5 sidecar).
try:
    from security_tab import SecurityTab
    from engine import alerts as engine_alerts, patches as engine_patches
    _SECURITY_TAB_OK = True
    _SECURITY_TAB_ERROR = None
except Exception as _e:
    _SECURITY_TAB_OK = False
    _SECURITY_TAB_ERROR = str(_e)
try:
    from ai_agent_tab import AIAgentTab
    _AGENT_TAB_OK = True
except Exception as _e:
    AIAgentTab = None
    _AGENT_TAB_ERROR = str(_e)
    _AGENT_TAB_OK = False

# Security News tab import (RSS feeds — no AI required)
try:
    from security_news_tab import SecurityNewsTab
    _NEWS_TAB_OK = True
except Exception as _e:
    _NEWS_TAB_OK = False
    _NEWS_TAB_ERROR = str(_e)

AUTOSTART_DIR = Path.home() / ".config" / "autostart"
AUTOSTART_FILE = AUTOSTART_DIR / "com.digitalautobahn.AutobahnDefender.desktop"

APP_NAME = "Autobahn Defender"
APP_VERSION = "2.0.0"
ORG_NAME = "Digital Autobahn"

# Dark theme colors
SIDEBAR_BG = "#0A0A0A"
SIDEBAR_ACTIVE = "#1A237E"
SIDEBAR_HOVER = "#1A1A2E"
ACCENT = "#2962FF"


def _get_app_icon():
    """Build a multi-size QIcon from the app's icon files."""
    search_paths = [
        Path(__file__).parent / "icons",
        Path(__file__).parent,
        Path(__file__).parent / "bin" / "icons",
        Path("/usr/share/icons/hicolor/256x256/apps"),
        Path("/usr/share/icons/hicolor/512x512/apps"),
    ]

    icon = QIcon()
    for size_name in ("256.png", "512.png"):
        for base in search_paths:
            p = base / size_name
            if p.exists():
                icon.addFile(str(p))
                break

    if icon.isNull():
        fallback = QIcon.fromTheme("autobahn-defender")
        if not fallback.isNull():
            return fallback

    return icon


def _ensure_desktop_file():
    """Install a .desktop file if one isn't already installed.

    This lets the XDG desktop portal find the app for icon resolution,
    window grouping, and D-Bus registration on Wayland.
    """
    data_dir = Path(os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share")))
    desktop_dir = data_dir / "applications"
    icon_dir = data_dir / "icons" / "hicolor" / "512x512" / "apps"
    desktop_file = desktop_dir / "com.digitalautobahn.AutobahnDefender.desktop"

    # Resolve the actual binary path (works for PyInstaller and source runs)
    if getattr(sys, "frozen", False):
        exec_path = sys.executable
    else:
        exec_path = str(Path(__file__).resolve())

    # Copy icon to a stable location so the desktop file always works
    # even inside a PyInstaller bundle where the temp dir evaporates.
    icon_dest = icon_dir / "autobahn-defender.png"
    icon_source = Path(__file__).resolve().parent / "512.png"
    need_update_icon = False
    try:
        icon_dir.mkdir(parents=True, exist_ok=True)
        if icon_source.exists():
            if not icon_dest.exists():
                shutil.copy2(str(icon_source), str(icon_dest))
                need_update_icon = True
    except OSError:
        pass

    icon_ref = "autobahn-defender"

    desktop_entry = f"""\
[Desktop Entry]
Type=Application
Name=Autobahn Defender
GenericName=Antivirus
Comment=Linux antivirus application by Digital Autobahn
Exec={exec_path}
Icon={icon_ref}
Categories=System;Security;
StartupNotify=true
Terminal=false
"""

    # Always rewrite if missing or Exec line is stale (binary moved or old AppImage mount)
    need_write = True
    if desktop_file.exists():
        try:
            existing = desktop_file.read_text()
            # Detect stale AppImage FUSE mount paths that no longer exist
            stale_appimage = False
            for line in existing.splitlines():
                if line.strip().startswith("Exec=") and "/tmp/.mount_" in line:
                    stale_appimage = True
                    break
            if f"Exec={exec_path}" in existing and not stale_appimage:
                need_write = False
        except OSError:
            pass

    if need_write:
        try:
            desktop_dir.mkdir(parents=True, exist_ok=True)
            desktop_file.write_text(desktop_entry)
        except OSError:
            pass

    # Update databases synchronously so the portal finds them immediately
    try:
        subprocess.run(
            ["update-desktop-database", str(desktop_dir)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if need_update_icon:
        try:
            subprocess.run(
                ["gtk-update-icon-cache", "-f", str(data_dir / "icons" / "hicolor")],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass


def _set_autostart(enable, minimized=False):
    """Create or remove the XDG autostart desktop entry."""
    AUTOSTART_DIR.mkdir(parents=True, exist_ok=True)
    if enable:
        # Resolve the binary path
        # 1. Check if the deb-installed launcher exists
        launcher = Path("/usr/bin/autobahn-defender")
        if launcher.exists():
            exec_path = str(launcher)
        # 2. Check PyInstaller frozen mode
        elif getattr(sys, "frozen", False):
            exec_path = sys.executable
        # 3. Fall back to this script (source run)
        else:
            exec_path = str(Path(__file__).resolve())

        # Add --minimized flag if start minimized is enabled
        exec_line = exec_path
        if minimized:
            exec_line = f"{exec_path} --minimized"

        autostart_entry = (
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=Autobahn Defender\n"
            "Comment=Linux antivirus application by Digital Autobahn\n"
            f"Exec={exec_line}\n"
            "Icon=autobahn-defender\n"
            "Categories=System;Security;\n"
            "StartupNotify=false\n"
            "Terminal=false\n"
            "X-GNOME-Autostart-enabled=true\n"
            "X-KDE-autostart-after=panel\n"
        )
        try:
            AUTOSTART_FILE.write_text(autostart_entry)
            os.chmod(str(AUTOSTART_FILE), 0o644)
        except OSError:
            pass
    else:
        try:
            AUTOSTART_FILE.unlink(missing_ok=True)
        except OSError:
            pass


class FileMonitorWorker(QThread):
    """Background worker that polls folders for new/modified files and auto-scans them."""
    new_file = pyqtSignal(str)

    def __init__(self, watch_folders, scanner, poll_interval=5):
        super().__init__()
        self.watch_folders = watch_folders or []
        self.scanner = scanner
        self.poll_interval = poll_interval
        self._running = True
        self._known_files = {}  # folder -> set of known files

    def run(self):
        # Build initial snapshot
        for folder in self.watch_folders:
            self._known_files[folder] = self._snapshot(folder)

        while self._running:
            self.msleep(self.poll_interval * 1000)
            if not self._running:
                break
            for folder in self.watch_folders:
                if not os.path.isdir(folder):
                    continue
                current = self._snapshot(folder)
                known = self._known_files.get(folder, set())
                new_files = current - known
                for fpath in new_files:
                    if self._running:
                        self.new_file.emit(fpath)
                self._known_files[folder] = current

    def stop(self):
        self._running = False

    def _snapshot(self, folder):
        """Build a set of file paths in the given folder (shallow)."""
        files = set()
        try:
            for entry in os.scandir(folder):
                if entry.is_file(follow_symlinks=False):
                    files.add(os.path.normpath(entry.path))
        except (PermissionError, OSError):
            pass
        return files


class SidebarButton(QPushButton):
    """A button styled for the sidebar navigation."""

    def __init__(self, text, icon_char="", parent=None):
        super().__init__(f"  {icon_char}  {text}" if icon_char else f"  {text}", parent)
        self._active = False
        self.setCheckable(True)
        self.setMinimumHeight(48)
        self.setFont(QFont("Segoe UI", 12))
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: #B0B0B0;
                border: none;
                text-align: left;
                padding: 12px 20px;
                border-radius: 8px;
                margin: 2px 8px;
            }}
            QPushButton:hover {{
                background-color: {SIDEBAR_HOVER};
                color: white;
            }}
            QPushButton:checked {{
                background-color: {SIDEBAR_ACTIVE};
                color: white;
                font-weight: bold;
            }}
        """)

    def set_active(self, active):
        self._active = active
        self.setChecked(active)


class MainWindow(QMainWindow):
    """Main application window with sidebar navigation."""

    # Queued from the feed-worker thread (audit B-3 fix)
    _feeds_polled = pyqtSignal(str)

    def __init__(self, app_icon=None):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        # 9 nav buttons + logo + version need ~700px of sidebar height;
        # below that Qt compressed the buttons into each other (6px overlaps).
        self.setMinimumSize(1000, 720)
        self.resize(1100, 700)
        self.settings_mgr = SettingsManager()
        self.scanner = Scanner(settings_mgr=self.settings_mgr)
        self.quarantine_mgr = QuarantineManager()

        # v2.0 Security Center — deterministic engine (no AI model)
        self._security_engine = None
        self._ai_rss_timer = None

        # System tray (may not be available on all desktops)
        self.tray_icon = None  # initialized in _setup_tray if available

        # Initialize history database
        init_db()

        # Ensure app directories exist
        ensure_dirs()
        # v2.0: ensure engine intel DB dirs exist
        try:
            from engine import ensure_dirs as _engine_dirs
            _engine_dirs()
        except Exception as e:
            import logging as _log
            _log.getLogger(__name__).warning("Failed to create engine dirs: %s", e)

        # Set window icon from the multi-size QIcon
        self._app_icon = app_icon or _get_app_icon()
        if not self._app_icon.isNull():
            self.setWindowIcon(self._app_icon)

        self._setup_ui()
        self._setup_tray()
        # Route feed-worker completions through the GUI thread (B-3 fix)
        self._feeds_polled.connect(self._on_feeds_polled)

        # v2.0: Start background feed polling (does NOT require AI to be enabled)
        # Polls RSS feeds daily and stores articles for the Security News tab
        self._start_background_feed_polling()

        # Start updater and first-run checks after window is shown
        self.updater = AppUpdater(self)
        self.yara_updater = YaraRuleUpdater(self)
        QTimer.singleShot(500, self._first_run_checks)

        # USB monitor (enabled via settings)
        self._usb_monitor = None
        if self.settings_mgr.is_auto_scan_usb():
            self._start_usb_monitor()

        # File monitor (enabled via settings)
        self._file_monitor = None
        if self.settings_mgr.is_realtime_enabled():
            self._start_file_monitor()

        # Scheduled scan timer
        self._scheduled_scan_timer = None
        if self.settings_mgr.is_schedule_enabled():
            self._start_scheduled_scans()

        # Autostart — sync on launch
        _set_autostart(
            self.settings_mgr.is_autostart_enabled(),
            self.settings_mgr.is_start_minimized()
        )

        # Wire settings changes after tabs are created (they're created in _setup_ui)
        self.settings_tab.autostart_check.stateChanged.connect(self._on_autostart_changed)
        self.settings_tab.minimized_check.stateChanged.connect(self._on_minimized_changed)
        self.settings_tab.rt_check.stateChanged.connect(self._on_realtime_changed)
        self.settings_tab.usb_check.stateChanged.connect(self._on_usb_scan_changed)
        self.settings_tab.sched_check.stateChanged.connect(self._on_schedule_changed)

    def _first_run_checks(self):
        """Check for missing dependencies and outdated definitions on first run.
        On first-run setup, these are handled by _run_first_run_setup before
        the window is shown, so only run checks for subsequent launches.
        """
        from scanner import DEFS_DIR
        cvd_files = list(DEFS_DIR.glob("*.cvd")) + list(DEFS_DIR.glob("*.cld"))
        if not cvd_files:
            # First-run setup already handled this — skip duplicate checks
            self.updater.start_periodic_checks()
            self._start_periodic_defs_check()
            self._start_yara_updater()
            return
        self._check_dependencies()
        self._check_definitions_on_launch()
        self.updater.start_periodic_checks()
        self._start_periodic_defs_check()
        self._start_yara_updater()

    def _check_dependencies(self):
        """Check for required tools and offer to install missing ones."""
        from scanner import find_clamscan, find_yara, find_freshclam
        missing = []
        if not find_clamscan():
            missing.append("clamav (clamscan)")
        if not find_yara():
            missing.append("yara")
        if not find_freshclam():
            missing.append("clamav (freshclam)")

        if not missing:
            return

        missing_str = "\n  \u2022 ".join(missing)
        reply = QMessageBox.warning(
            self, "Missing Dependencies",
            f"Required dependencies are missing:\n  \u2022 {missing_str}\n\n"
            f"The app will be limited without them.\n\n"
            f"Would you like to install them now?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._install_deps_standalone()

    def _install_deps_standalone(self):
        """Install missing dependencies directly without relying on About tab UI."""
        from scanner import find_clamscan, find_yara, find_freshclam
        distro_id = ""
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("ID="):
                        distro_id = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("ID_LIKE="):
                        distro_id = distro_id or line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass

        commands = []
        if distro_id in ("arch", "cachyos", "manjaro", "endeavouros") or "arch" in distro_id:
            cmds = []
            if not find_clamscan():
                cmds.append("clamav")
            if not find_yara():
                cmds.append("yara")
            cmds.append("python-psutil")
            if cmds:
                commands = ["sudo", "pacman", "-S", "--needed", "--noconfirm"] + cmds
        elif distro_id in ("debian", "ubuntu", "linuxmint", "pop", "zorin") or "debian" in distro_id:
            cmds = []
            if not find_clamscan() or not find_freshclam():
                if not find_clamscan():
                    cmds.append("clamav")
                if not find_freshclam():
                    cmds.append("clamav-freshclam")
            if not find_yara():
                cmds.append("yara")
            cmds.append("python3-psutil")
            if cmds:
                # Create /var/log/clamav/ before installing clamav-daemon
                # to prevent its post-install script from failing
                # (known Ubuntu/Mint bug: the directory doesn't exist)
                commands = [
                    "sudo", "bash", "-c",
                    "dpkg --configure -a; "
                    "apt-get --fix-broken install -y; "
                    "mkdir -p /var/log/clamav && chown clamav:clamav /var/log/clamav 2>/dev/null || true; "
                    "apt-get update && apt-get install -y " + " ".join(cmds) + " && apt-get install -f -y"
                ]
        elif distro_id in ("fedora", "rhel", "centos", "rocky", "almalinux") or "fedora" in distro_id:
            cmds = []
            if not find_clamscan() or not find_freshclam():
                if not find_clamscan():
                    cmds.append("clamav")
                if not find_freshclam():
                    cmds.append("clamav-update")
            if not find_yara():
                cmds.append("yara")
            cmds.append("python3-psutil")
            if cmds:
                commands = ["sudo", "dnf", "install", "-y"] + cmds

        if not commands:
            QMessageBox.information(
                self, "Install Dependencies",
                "Could not detect your package manager.\n\n"
                "Please install manually: sudo apt-get install clamav clamav-freshclam yara python3-psutil",
            )
            return

        pkexec = shutil.which("pkexec")
        if pkexec:
            install_cmd = commands[1:]  # Strip sudo; pkexec runs as root
            from updater import InstallProgressDialog
            dialog = InstallProgressDialog(
                "Installing Dependencies",
                install_cmd,
                self,
            )
            dialog.exec()

            # On Debian-based systems, clamav-freshclam auto-starts a systemd
            # service after install. That service conflicts with our freshclam
            # usage. Stop and disable it so the app's definition updates work.
            if ("debian" in distro_id or distro_id in ("ubuntu", "linuxmint", "pop", "zorin")):
                try:
                    subprocess.run(
                        [pkexec, "systemctl", "stop", "clamav-freshclam"],
                        capture_output=True, timeout=15,
                    )
                    subprocess.run(
                        [pkexec, "systemctl", "disable", "clamav-freshclam"],
                        capture_output=True, timeout=15,
                    )
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass
        else:
            cmd_str = " ".join(commands)
            # Fallback: try terminal emulators
            terminal = shutil.which("konsole") or shutil.which("gnome-terminal") or shutil.which("xterm")
            if terminal:
                try:
                    if "konsole" in terminal:
                        subprocess.Popen([terminal, "-e", *commands])
                    elif "gnome-terminal" in terminal:
                        shell_cmd = cmd_str + "; echo; read -p 'Press Enter to close...'"
                        subprocess.Popen([terminal, "--", "bash", "-c", shell_cmd])
                    else:
                        subprocess.Popen([terminal, "-e", *commands])
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Failed to open terminal: {e}")
            else:
                QMessageBox.information(
                    self, "Install Dependencies",
                    f"No terminal emulator found.\n\nPlease run manually:\n  {cmd_str}",
                )

    def _check_definitions_on_launch(self):
        """Check if definitions exist or are stale, and show update dialog if needed."""
        cvd_files = list(DEFS_DIR.glob("*.cvd")) + list(DEFS_DIR.glob("*.cld"))
        last = get_defs_last_updated()

        should_update = False
        reason = ""

        if not cvd_files and last == "Never":
            # First run: no definitions at all
            should_update = True
            reason = "No virus definitions found. Definitions are required for ClamAV scanning."
        elif last != "Never":
            # Check if stale (>24 hours)
            try:
                last_dt = datetime.fromisoformat(
                    Path(DEFS_DIR.parent / "defs_last_updated.txt").read_text().strip()
                )
                if datetime.now() - last_dt > timedelta(hours=24):
                    should_update = True
                    reason = "Virus definitions are more than 24 hours old."
            except (ValueError, OSError):
                should_update = True
                reason = "Checking virus definitions..."

        if should_update:
            if not cvd_files and last == "Never":
                reply = QMessageBox.information(
                    self, "Virus Definitions",
                    reason + "\n\nWould you like to download them now?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes,
                )
                if reply == QMessageBox.StandardButton.No:
                    return

            self._show_defs_update_dialog()
            self.scanner.update_definitions()

    def _show_defs_update_dialog(self):
        """Create and show the definition update progress dialog."""
        self._defs_dialog = DefsUpdateDialog(self.scanner, self)
        self._defs_dialog.setStyleSheet(STYLESHEET)
        self._defs_dialog.show()

    def _start_periodic_defs_check(self):
        """Check for definition updates every 24 hours."""
        self._defs_check_timer = QTimer()
        self._defs_check_timer.timeout.connect(self._on_periodic_defs_check)
        self._defs_check_timer.start(24 * 60 * 60 * 1000)  # 24 hours

    def _on_periodic_defs_check(self):
        """Timer callback: show dialog and check for definition updates."""
        # Don't stack if a manual update is already in progress
        if self.scanner._defs_worker and self.scanner._defs_worker.isRunning():
            return
        self._show_defs_update_dialog()
        self.scanner.update_definitions()

    def _start_yara_updater(self):
        """Start periodic YARA rule update checks."""
        if self.settings_mgr.is_yara_auto_update():
            self.yara_updater.start_periodic_checks()

    # ── Autostart ──────────────────────────────────────────────
    def _on_autostart_changed(self, state):
        """Create or remove the XDG autostart entry when the checkbox toggles."""
        enabled = (state == Qt.CheckState.Checked.value)
        self.settings_mgr.settings.sync()
        _set_autostart(enabled, self.settings_mgr.is_start_minimized())

    def _on_minimized_changed(self, state):
        """Update the autostart entry when the minimized checkbox toggles."""
        minimized = (state == Qt.CheckState.Checked.value)
        # Force sync settings to disk before reading (in case the lambda
        # that saves the setting hasn't flushed yet)
        self.settings_mgr.settings.sync()
        if self.settings_mgr.is_autostart_enabled():
            _set_autostart(True, minimized)

    # ── Real-time file monitoring ─────────────────────────────
    def _on_realtime_changed(self, state):
        """Start or stop the file monitor when the checkbox toggles."""
        enabled = (state == Qt.CheckState.Checked.value)
        if enabled:
            self._start_file_monitor()
        else:
            self._stop_file_monitor()

    def _start_file_monitor(self):
        """Start polling watch folders for new/modified files."""
        if self._file_monitor and self._file_monitor.isRunning():
            return
        folders = self.settings_mgr.get_watch_folders()
        if not folders:
            folders = [str(Path.home() / "Downloads")]
        self._file_monitor = FileMonitorWorker(folders, self.scanner)
        self._file_monitor.new_file.connect(self._on_new_file_detected)
        self._file_monitor.start()

    def _stop_file_monitor(self):
        if self._file_monitor:
            self._file_monitor.stop()
            self._file_monitor.wait(3000)
            self._file_monitor = None

    def _on_new_file_detected(self, filepath):
        """Auto-scan a newly detected file from real-time monitoring."""
        silent = self.settings_mgr.is_silent_mode()
        if not silent:
            reply = QMessageBox.question(
                self, "File Detected",
                f"A new file was detected in a monitored folder:\n{filepath}\n\n"
                f"Would you like to scan it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.scanner.start_scan("custom", custom_paths=[filepath])
        else:
            self.scanner.start_scan("custom", custom_paths=[filepath])

    # ── USB auto-scan ─────────────────────────────────────────
    def _on_usb_scan_changed(self, state):
        """Start or stop the USB monitor when the checkbox toggles."""
        enabled = (state == Qt.CheckState.Checked.value)
        if enabled:
            self._start_usb_monitor()
        else:
            self._stop_usb_monitor()

    # ── Scheduled scans ───────────────────────────────────────
    def _on_schedule_changed(self, state):
        """Start or stop the scheduled scan timer when the checkbox toggles."""
        enabled = (state == Qt.CheckState.Checked.value)
        if enabled:
            self._start_scheduled_scans()
        else:
            self._stop_scheduled_scans()

    def _start_scheduled_scans(self):
        """Start a timer that fires scans at the configured interval."""
        if self._scheduled_scan_timer and self._scheduled_scan_timer.isActive():
            return
        hours = self.settings_mgr.get_scan_interval()
        if hours <= 0:
            hours = 24

        self._scheduled_scan_timer = QTimer()
        self._scheduled_scan_timer.timeout.connect(self._run_scheduled_scan)
        self._scheduled_scan_timer.start(hours * 60 * 60 * 1000)

    def _stop_scheduled_scans(self):
        if self._scheduled_scan_timer:
            self._scheduled_scan_timer.stop()
            self._scheduled_scan_timer = None

    def _run_scheduled_scan(self):
        """Fire the scheduled scan without a confirmation dialog."""
        if self.scanner._worker and self.scanner._worker.isRunning():
            return  # Already scanning

        scan_type = self.settings_mgr.get_schedule_scan_type()
        if not scan_type:
            scan_type = "quick_home"

        self.scanner.start_scan(scan_type)
        self._notify_scheduled_scan_started(scan_type)

    def _notify_scheduled_scan_started(self, scan_type):
        """Show a tray notification that a scheduled scan has started."""
        names = {"quick_home": "Home Directory", "full_system": "Full System", "custom": "Custom"}
        if hasattr(self, "tray_icon") and self.tray_icon:
            self.tray_icon.showMessage(
                APP_NAME,
                f"Scheduled scan started ({names.get(scan_type, scan_type)})",
                QSystemTrayIcon.MessageIcon.Information,
                5000,
            )

    # ------------------------------------------------------------------
    # v2.0 AI Security lifecycle
    # ------------------------------------------------------------------

    def _create_security_tab(self):
        """Create the Security Center tab (deterministic — no AI model).

        Replaces the old _create_ai_tab. Falls back to a placeholder if
        the engine module imports failed.
        """
        if not _SECURITY_TAB_OK:
            placeholder = QWidget()
            lay = QVBoxLayout(placeholder)
            msg = QLabel(
                "Security Center module could not be loaded.\n\n"
                f"Error: {_SECURITY_TAB_ERROR}\n\n"
                "Make sure all dependencies are installed and restart the app."
            )
            msg.setWordWrap(True)
            msg.setStyleSheet("color: #E0E0E0; padding: 24px;")
            lay.addWidget(msg)
            lay.addStretch()
            return placeholder

        tab = SecurityTab()
        return tab

    def _stop_rss_polling(self):
        if self._ai_rss_timer:
            self._ai_rss_timer.stop()
            self._ai_rss_timer = None

    def _poll_feeds_background(self):
        """Poll RSS feeds in background (called by Security News tab refresh).
        Does NOT require AI — this is application-layer polling.

        Audit 2026-08-31 B-3 fix: the worker thread previously called
        security_news_tab.set_last_updated()/refresh_articles() DIRECTLY from
        a plain threading.Thread — Qt widgets are only touchable from the GUI
        thread (instant-crash risk). The worker now emits a queued signal.
        """
        def _do_poll():
            try:
                from ai.rss_feeds import poll_all_feeds
                summary = poll_all_feeds()
                import time as _time
                self._feeds_polled.emit(_time.strftime("%Y-%m-%d %H:%M:%S"))
            except Exception as e:
                print(f"[Security News] RSS poll error: {e}", flush=True)
        t = threading.Thread(target=_do_poll, daemon=True)
        t.start()

    def _on_feeds_polled(self, timestamp: str):
        """GUI-thread slot for the feeds_polled signal."""
        if hasattr(self, "security_news_tab") and _NEWS_TAB_OK:
            self.security_news_tab.set_last_updated(timestamp)
            self.security_news_tab.refresh_articles()

    def _start_background_feed_polling(self):
        """Start the daily RSS feed poll timer (does NOT require AI).

        The feed poller runs independently. It polls feeds on startup
        (if > 24h since last poll) and every 24 hours.
        """
        if self._ai_rss_timer:
            return
        try:
            from ai.rss_feeds import poll_all_feeds, POLL_INTERVAL_SECONDS
            last_poll = self.settings_mgr.get_ai_last_poll()
            import time as _time
            if not last_poll or (_time.time() - last_poll) > POLL_INTERVAL_SECONDS:
                QTimer.singleShot(30000, self._poll_feeds_background)
        except Exception:
            QTimer.singleShot(30000, self._poll_feeds_background)
        # Then every 24 hours
        try:
            from ai.rss_feeds import POLL_INTERVAL_SECONDS
            self._ai_rss_timer = QTimer(self)
            self._ai_rss_timer.timeout.connect(self._poll_feeds_background)
            self._ai_rss_timer.start(POLL_INTERVAL_SECONDS * 1000)
        except Exception:
            pass

    def _setup_ui(self):
        """Build the sidebar + stacked widget layout."""
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Sidebar
        sidebar = QWidget()
        sidebar.setFixedWidth(220)
        sidebar.setStyleSheet(f"background-color: {SIDEBAR_BG};")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 16, 0, 16)
        sidebar_layout.setSpacing(4)

        # App icon in sidebar
        icon_pixmap = self._app_icon.pixmap(64, 64)
        if icon_pixmap.isNull():
            icon_path = Path(__file__).parent / "512.png"
            if icon_path.exists():
                icon_pixmap = QPixmap(str(icon_path)).scaled(
                    64, 64, Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
        if not icon_pixmap.isNull():
            app_icon_label = QLabel()
            app_icon_label.setPixmap(icon_pixmap)
            app_icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            app_icon_label.setStyleSheet("background: transparent; padding: 8px 0;")
            sidebar_layout.addWidget(app_icon_label)
        else:
            app_label = QLabel("  Autobahn\n  Defender")
            app_label.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
            app_label.setStyleSheet("color: #FFFFFF; background: transparent; padding: 8px;")
            sidebar_layout.addWidget(app_label)

        # Separator
        sep = QWidget()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: #333; margin: 8px 16px;")
        sidebar_layout.addWidget(sep)

        # Navigation buttons
        self.nav_buttons = []
        tabs = [
            ("Dashboard", ""),
            ("Scan", ""),
            ("Quarantine", ""),
            ("History", ""),
            ("Security News", ""),
            ("Security Center", ""),
            ("AI Agent", ""),
            ("Settings", ""),
            ("About", ""),
        ]

        for label, icon in tabs:
            btn = SidebarButton(label, icon)
            btn.clicked.connect(lambda checked, idx=len(self.nav_buttons): self.switch_tab(idx))
            self.nav_buttons.append(btn)
            sidebar_layout.addWidget(btn)

        sidebar_layout.addStretch()

        # Version label at bottom
        ver_label = QLabel(f"  v{APP_VERSION}")
        ver_label.setFont(QFont("Segoe UI", 9))
        ver_label.setStyleSheet("color: #555; background: transparent; padding: 8px;")
        sidebar_layout.addWidget(ver_label)

        main_layout.addWidget(sidebar)

        # Content stack
        self.stack = QStackedWidget()
        self.stack.setStyleSheet(f"background-color: #121212;")

        self.dashboard_tab = DashboardTab(self.scanner)
        self.scan_tab = ScanTab(self.scanner, self.quarantine_mgr, self.settings_mgr)
        self.quarantine_tab = QuarantineTab(self.quarantine_mgr)
        self.history_tab = HistoryTab()
        # v2.0 Security News tab (does NOT require AI to be enabled)
        if _NEWS_TAB_OK:
            self.security_news_tab = SecurityNewsTab()
            self.security_news_tab.refresh_requested.connect(self._poll_feeds_background)
        else:
            self.security_news_tab = QWidget()
            lay = QVBoxLayout(self.security_news_tab)
            msg = QLabel(f"Security News tab could not be loaded.\nError: {_NEWS_TAB_ERROR}")
            msg.setWordWrap(True)
            msg.setStyleSheet("color: #E0E0E0; padding: 24px;")
            lay.addWidget(msg)
            lay.addStretch()
        # v2.0 Security Center tab (deterministic engine — no AI model)
        self.ai_tab = self._create_security_tab()
        # v2.0 AI Agent tab (MCP integration for external AI assistants)
        if _AGENT_TAB_OK:
            self.agent_tab = AIAgentTab()
        else:
            self.agent_tab = QWidget()
            _lay = QVBoxLayout(self.agent_tab)
            _msg = QLabel(f"AI Agent tab could not be loaded.\nError: {_AGENT_TAB_ERROR}")
            _msg.setWordWrap(True)
            _msg.setStyleSheet("color: #E0E0E0; padding: 24px;")
            _lay.addWidget(_msg)
            _lay.addStretch()
        self.settings_tab = SettingsTab(self.scanner, self.settings_mgr)
        self.about_tab = AboutTab()

        self.stack.addWidget(self.dashboard_tab)       # 0
        self.stack.addWidget(self.scan_tab)             # 1
        self.stack.addWidget(self.quarantine_tab)       # 2
        self.stack.addWidget(self.history_tab)          # 3
        self.stack.addWidget(self.security_news_tab)    # 4
        self.stack.addWidget(self.ai_tab)               # 5
        self.stack.addWidget(self.agent_tab)            # 6  AI Agent (MCP)
        self.stack.addWidget(self.settings_tab)         # 7
        self.stack.addWidget(self.about_tab)            # 8

        main_layout.addWidget(self.stack, 1)

        # Default to Dashboard
        self.switch_tab(0)

    def switch_tab(self, index):
        """Switch the visible tab and update sidebar highlighting.

        Instant switch (no fade animation) for performance.
        QGraphicsOpacityEffect forces Qt to render the entire tab to an
        offscreen pixmap, which is extremely slow for complex pages like
        the AI Security tab (100+ widgets).
        """
        for i, btn in enumerate(self.nav_buttons):
            btn.set_active(i == index)

        self.stack.setCurrentIndex(index)

        # Refresh data-driven tabs when switching to them
        if index == 2:
            self.quarantine_tab.refresh()
        elif index == 3:
            self.history_tab.refresh()
        elif index == 4 and _NEWS_TAB_OK:
            self.security_news_tab.refresh_articles()

    def _setup_tray(self):
        """Set up the system tray icon."""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        tray_icon = self._app_icon if not self._app_icon.isNull() else None
        if tray_icon is None:
            icon_path = Path(__file__).parent / "256.png"
            if not icon_path.exists():
                icon_path = Path(__file__).parent / "icons" / "256.png"
            if not icon_path.exists():
                return
            tray_icon = QIcon(str(icon_path))
            if tray_icon.isNull():
                return

        self.tray_icon = QSystemTrayIcon(tray_icon, self)
        self.tray_icon.setToolTip(APP_NAME)

        # Tray menu
        tray_menu = QMenu(self)
        show_action = tray_menu.addAction("Show Autobahn Defender")
        show_action.triggered.connect(self._show_window)

        scan_action = tray_menu.addAction("Home Scan")
        scan_action.triggered.connect(lambda: self.scanner.start_scan("quick_home"))

        tray_menu.addSeparator()

        quit_action = tray_menu.addAction("Quit")
        quit_action.triggered.connect(QApplication.quit)

        self.tray_icon.setContextMenu(tray_menu)

        # Double-click and single-click show window
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()

    def _on_tray_activated(self, reason):
        if reason in (QSystemTrayIcon.ActivationReason.DoubleClick,
                      QSystemTrayIcon.ActivationReason.Trigger):
            self._show_window()

    def _show_window(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def _start_usb_monitor(self):
        """Start monitoring for USB device connections."""
        try:
            from usb_monitor import USBMonitorWorker
            self._usb_monitor = USBMonitorWorker()
            self._usb_monitor.new_device.connect(self._on_new_usb_device)
            self._usb_monitor.start()
        except Exception:
            self._usb_monitor = None

    def _stop_usb_monitor(self):
        """Stop the USB monitor."""
        if self._usb_monitor:
            self._usb_monitor.stop()
            self._usb_monitor.wait(3000)
            self._usb_monitor = None

    def _on_new_usb_device(self, mount_point):
        """Handle a newly connected USB device by auto-scanning it."""
        silent = self.settings_mgr.is_silent_mode()
        if not silent:
            reply = QMessageBox.question(
                self, "USB Device Detected",
                f"A new device was mounted at:\n{mount_point}\n\n"
                f"Would you like to scan it now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.scanner.start_scan("custom", custom_paths=[mount_point])
        else:
            # Silent mode: auto-scan without dialog
            self.scanner.start_scan("custom", custom_paths=[mount_point])

    def closeEvent(self, event):
        """Ask user whether to exit or minimize to tray. Also clean up daemons."""
        reply = QMessageBox.question(
            self,
            APP_NAME,
            "Would you like to minimize to the system tray?",
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.No
            | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Yes,
        )
        if reply == QMessageBox.StandardButton.Yes:
            event.ignore()
            self.hide()
        elif reply == QMessageBox.StandardButton.No:
            # Stop ALL background threads to prevent "QThread: Destroyed
            # while thread is still running" crash
            self._stop_usb_monitor()
            self._stop_file_monitor()
            self._stop_scheduled_scans()
            # Stop the updater and YARA updater threads
            try:
                self.updater.stop_periodic_checks()
            except Exception:
                pass
            try:
                self.yara_updater.stop_periodic_checks()
            except Exception:
                pass
            # v2.0: stop RSS polling cleanly on app exit
            self._stop_rss_polling()
            # Security Center thread cleanup
            if hasattr(self, "ai_tab") and self.ai_tab:
                if hasattr(self.ai_tab, "cleanup"):
                    self.ai_tab.cleanup()
            event.accept()
            QApplication.quit()
        else:
            event.ignore()


def _run_first_run_setup(window, app, splash):
    """Run the first-launch setup flow before showing the main window.

    1. Install missing dependencies
    2. Download virus definitions
    3. Show guidance dialog
    4. Show the main window
    """
    from PyQt6.QtCore import QTimer
    from scanner import find_clamscan, find_yara, find_freshclam, DEFS_DIR
    from ui_tabs import STYLESHEET

    # ── Step 1: Install missing dependencies ────────────────────────
    missing = []
    if not find_clamscan():
        missing.append("clamav")
    if not find_yara():
        missing.append("yara")
    if not find_freshclam():
        missing.append("clamav-freshclam")

    if splash:
        splash.showMessage(
            f"  {APP_NAME} v{APP_VERSION}\\n  Installing dependencies...",
            Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignLeft,
            QColor("#E0E0E0"),
        )
        app.processEvents()

    if missing:
        window._install_deps_standalone()
        # Re-check what's still missing
        for _ in range(15):
            app.processEvents()
            app.processEvents()
        # Give a brief moment for installations to finish
        import time
        time.sleep(0.5)

    # ── Step 2: Download virus definitions ──────────────────────────
    if splash:
        splash.showMessage(
            f"  {APP_NAME} v{APP_VERSION}\\n  Downloading virus definitions...",
            Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignLeft,
            QColor("#E0E0E0"),
        )
        app.processEvents()

    # Use the scanner's definition update mechanism
    cvd_files = list(DEFS_DIR.glob("*.cvd")) + list(DEFS_DIR.glob("*.cld"))
    if not cvd_files:
        # Show the definitions update dialog (blocks via exec)
        from ui_tabs import DefsUpdateDialog
        dialog = DefsUpdateDialog(window.scanner, window)
        dialog.setStyleSheet(STYLESHEET)
        dialog.setWindowTitle("Downloading Virus Definitions")
        dialog.show()
        app.processEvents()
        window.scanner.update_definitions()
        # Wait a bit for the download to start, then close dialog
        # The dialog manages its own lifecycle via signals

    # ── Step 3: Show guidance dialog ────────────────────────────────
    if splash:
        splash.close()

    window.setWindowTitle(APP_NAME)
    window.show()
    window.raise_()
    window.activateWindow()
    app.processEvents()

    # Show first-run guidance
    guidance_dialog = FirstRunGuidanceDialog(window)
    guidance_dialog.exec()


class FirstRunGuidanceDialog(QDialog):
    """Guidance dialog for new users on their first launch."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Welcome to Autobahn Defender")
        self.setMinimumSize(600, 500)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: #121212;
                color: #E0E0E0;
            }}
            QLabel {{
                color: #E0E0E0;
                background: transparent;
            }}
            QTextEdit {{
                background-color: #1E1E1E;
                color: #E0E0E0;
                border: 1px solid #2C2C2C;
                border-radius: 8px;
                padding: 12px;
                font-size: 13px;
            }}
            QPushButton {{
                background-color: #2962FF;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 32px;
                font-size: 14px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #1E88E5;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Title
        title = QLabel("Welcome to Autobahn Defender!")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #FFFFFF;")
        title.setWordWrap(True)
        layout.addWidget(title)

        # Subtitle
        subtitle = QLabel(
            "Your setup is complete. Here are a few tips to get the most out of Autobahn Defender:"
        )
        subtitle.setStyleSheet("font-size: 14px; color: #B0B0B0;")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        # Tips text
        tips = QTextEdit()
        tips.setReadOnly(True)
        tips.setHtml("""
<h3>1. Run a Full System Scan</h3>
<p>On a known-good system, a full scan establishes a baseline. Everything on your system
is scanned — files, documents, archives, and binaries.</p>

<h3>2. Handle False Positives</h3>
<p>If the scanner flags something you <b>know is safe</b>, you have two options:</p>
<ul>
<li><b>Ignore Forever (per file)</b> — In scan results, select "Ignore Forever" from the
Action column for any file. That file will never be flagged again.</li>
<li><b>Ignore Forever (bulk)</b> — Use the "Ignore All (Forever)" button to exempt all
current results at once.</li>
</ul>

<h3>3. Exempt YARA Rules in Results</h3>
<p>If a YARA rule triggers false positives on many files:</p>
<ul>
<li><b>Right-click</b> any flagged result in the scan results table</li>
<li>Choose <b>"Exempt YARA rule 'RuleName'"</b> from the context menu</li>
<li>The rule will be skipped in all future scans</li>
</ul>

<h3>4. Manage Exemptions</h3>
<p>Go to <b>Settings > Exemptions / Ignore List</b> to see all your exemptions.
Click any entry to remove it. You can also add folders to the ignore list manually.</p>

<h3>5. Scheduled Scans</h3>
<p>Enable scheduled scans in <b>Settings</b> to run automatic scans at regular intervals
(12h, daily, 5/15/30 days).</p>

<h3>6. Real-Time Protection</h3>
<p>Turn on <b>USB Monitoring</b> and <b>File Watching</b> in Settings for automatic
scanning of new files and external drives.</p>

<h3>7. Virus Definitions</h3>
<p>Definitions are checked every 24 hours in the background. You can also manually
update from the <b>Dashboard</b> or <b>Settings</b> tabs.</p>
        """)
        layout.addWidget(tips, 1)

        # Launch button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        launch_btn = QPushButton("Get Started")
        launch_btn.setMinimumWidth(200)
        launch_btn.clicked.connect(self.accept)
        btn_layout.addWidget(launch_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)


def main():
    # ── CLI dispatch (Phase 2): a recognized verb runs headless and exits ──
    # `autobahn-defender scan ...` etc. never touches Qt; `--minimized` and
    # bare launches go to the GUI below.
    try:
        from cli.main import _COMMANDS as _CLI_COMMANDS, main as _cli_main
    except ImportError:
        _CLI_COMMANDS, _cli_main = {}, None
    _argv = sys.argv[1:]
    if _argv and _argv[0] in _CLI_COMMANDS:
        sys.exit(_cli_main(_argv))

    # Version/help flags must not initialize Qt (VM/CI-safe; VM test caught
    # this: --version crashed with qt.qpa.xcb on headless boxes).
    if _argv and _argv[0] in ("--version", "-V", "--help", "-h"):
        print(f"Autobahn Defender {APP_VERSION}")
        if _argv[0] in ("--help", "-h"):
            print(__doc__ if "__doc__" in globals() else
                  "Run 'autobahn-defender --help' for the full CLI, "
                  "or launch without arguments for the GUI.")
            print("\nCLI verbs: scan scan-processes cve patches audit checks "
                  "alerts quarantine network intel watch remediate defs rules "
                  "apply doctor mcp")
        return 0

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName(ORG_NAME)

    # Check for --minimized CLI flag
    start_minimized = "--minimized" in sys.argv

    # Set desktop file name for Wayland/portal support
    app.setDesktopFileName("com.digitalautobahn.AutobahnDefender")
    _ensure_desktop_file()

    # Build and set the application icon BEFORE creating windows.
    app_icon = _get_app_icon()
    if not app_icon.isNull():
        app.setWindowIcon(app_icon)

    # Apply dark theme stylesheet
    app.setStyleSheet(STYLESHEET)

    # Splash screen
    splash = None
    banner_path = Path(__file__).parent / "banner.png"
    if banner_path.exists():
        splash_pixmap = QPixmap(str(banner_path))
        scaled = splash_pixmap.scaled(
            600, 400, Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        splash = QSplashScreen(scaled)
        splash.setStyleSheet(f"background-color: {SIDEBAR_BG};")
        splash.show()
        splash.showMessage(
            f"  {APP_NAME} v{APP_VERSION}\\n  Loading...",
            Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignLeft,
            QColor("#E0E0E0"),
        )
        app.processEvents()

    # Check if this is a first run (no definitions, no prior settings)
    from scanner import DEFS_DIR
    cvd_files = list(DEFS_DIR.glob("*.cvd")) + list(DEFS_DIR.glob("*.cld"))
    has_defs = len(cvd_files) > 0
    is_first_run = not has_defs

    # Create the main window (hidden initially)
    window = MainWindow(app_icon=app_icon)
    window.hide()  # Keep hidden until setup is done

    if splash:
        splash.showMessage(
            f"  {APP_NAME} v{APP_VERSION}\\n  Checking dependencies...",
            Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignLeft,
            QColor("#E0E0E0"),
        )
        app.processEvents()

    # On first run, run setup blocking dialog before showing the main window
    if is_first_run:
        _run_first_run_setup(window, app, splash)
    else:
        # Not first run: splash finishes, window shows normally
        if splash:
            splash.close()  # Close splash explicitly (not finish() — window may stay hidden)
        # Check if we should start minimized
        if start_minimized or window.settings_mgr.is_start_minimized():
            # Start minimized to system tray — don't show the window
            if window.tray_icon:
                window.tray_icon.show()
                window.tray_icon.showMessage(
                    APP_NAME,
                    "Autobahn Defender is running in the system tray.",
                    QSystemTrayIcon.MessageIcon.Information,
                    3000,
                )
            else:
                # No tray available — show window as fallback
                window.show()
        else:
            window.show()

    # Run the event loop. When the user closes the app, app.exec()
    # returns and we clean up all background threads before exiting.
    exit_code = app.exec()

    # Ensure all background threads are stopped before the Python
    # process exits, to prevent "QThread: Destroyed while thread is
    # still running" crash.
    try:
        window._stop_usb_monitor()
        window._stop_file_monitor()
        window._stop_scheduled_scans()
        window.updater.stop_periodic_checks()
        window.yara_updater.stop_periodic_checks()
        window._stop_rss_polling()
    except Exception:
        pass

    sys.exit(exit_code)


if __name__ == "__main__":
    main()