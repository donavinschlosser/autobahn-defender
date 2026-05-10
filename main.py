#!/usr/bin/env python3
"""
Autobahn Defender v1.0 - Main Application Entry Point
A modern Linux antivirus application by Digital Autobahn.
"""

import os
import shutil
import sys
import subprocess
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStackedWidget, QSystemTrayIcon, QMessageBox,
    QSplashScreen, QMenu,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap, QIcon, QFont, QColor

from scanner import Scanner, ensure_dirs, get_defs_last_updated, DEFS_DIR
from settings import SettingsManager
from quarantine import QuarantineManager
from ui_tabs import DashboardTab, ScanTab, QuarantineTab, SettingsTab, AboutTab, HistoryTab, STYLESHEET
from updater import AppUpdater
from history_db import init_db

APP_NAME = "Autobahn Defender"
APP_VERSION = "1.0"
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

    # Always rewrite if missing or Exec line is stale (binary moved)
    need_write = True
    if desktop_file.exists():
        try:
            existing = desktop_file.read_text()
            if f"Exec={exec_path}" in existing:
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

    def __init__(self, app_icon=None):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(1000, 650)
        self.resize(1100, 700)

        # Core modules
        self.settings_mgr = SettingsManager()
        self.scanner = Scanner(settings_mgr=self.settings_mgr)
        self.quarantine_mgr = QuarantineManager()

        # Initialize history database
        init_db()

        # Ensure app directories exist
        ensure_dirs()

        # Set window icon from the multi-size QIcon
        self._app_icon = app_icon or _get_app_icon()
        if not self._app_icon.isNull():
            self.setWindowIcon(self._app_icon)

        self._setup_ui()
        self._setup_tray()

        # Start updater and first-run checks after window is shown
        self.updater = AppUpdater(self)
        QTimer.singleShot(500, self._first_run_checks)

        # USB monitor (enabled via settings)
        self._usb_monitor = None
        if self.settings_mgr.is_auto_scan_usb():
            self._start_usb_monitor()

    def _first_run_checks(self):
        """Check for missing dependencies and outdated definitions on first run."""
        self._check_dependencies()
        self._check_definitions_on_launch()
        self.updater.start_periodic_checks()

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

        missing_str = "\n  • ".join(missing)
        reply = QMessageBox.warning(
            self, "Missing Dependencies",
            f"Required dependencies are missing:\n  • {missing_str}\n\n"
            f"The app will be limited without them.\n\n"
            f"Would you like to install them now?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.about_tab._install_deps()

    def _check_definitions_on_launch(self):
        """Check if definitions exist and prompt to update if missing."""
        from scanner import find_freshclam
        cvd_files = list(DEFS_DIR.glob("*.cvd")) + list(DEFS_DIR.glob("*.cld"))
        last = get_defs_last_updated()

        if not cvd_files and last == "Never":
            reply = QMessageBox.information(
                self, "Virus Definitions",
                "No virus definitions found.\n\n"
                "Definitions are required for ClamAV scanning.\n"
                "Would you like to download them now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.scanner.defs_update_finished.connect(
                    lambda ok, msg: self.dashboard_tab._refresh_defs_status()
                )
                self.scanner.update_definitions()

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
        self.scan_tab = ScanTab(self.scanner, self.quarantine_mgr)
        self.quarantine_tab = QuarantineTab(self.quarantine_mgr)
        self.history_tab = HistoryTab()
        self.settings_tab = SettingsTab(self.scanner, self.settings_mgr)
        self.about_tab = AboutTab()

        self.stack.addWidget(self.dashboard_tab)    # 0
        self.stack.addWidget(self.scan_tab)          # 1
        self.stack.addWidget(self.quarantine_tab)    # 2
        self.stack.addWidget(self.history_tab)       # 3
        self.stack.addWidget(self.settings_tab)      # 4
        self.stack.addWidget(self.about_tab)         # 5

        main_layout.addWidget(self.stack, 1)

        # Default to Dashboard
        self.switch_tab(0)

    def switch_tab(self, index):
        """Switch the visible tab and update sidebar highlighting."""
        for i, btn in enumerate(self.nav_buttons):
            btn.set_active(i == index)
        self.stack.setCurrentIndex(index)

        # Refresh quarantine tab when switching to it
        if index == 2:
            self.quarantine_tab.refresh()
        # Refresh history tab when switching to it
        elif index == 3:
            self.history_tab.refresh()

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
        """Ask user whether to exit or minimize to tray."""
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
            self._stop_usb_monitor()
            event.accept()
            QApplication.quit()
        else:
            event.ignore()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName(ORG_NAME)

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
            f"  {APP_NAME} v{APP_VERSION}\n  Loading...",
            Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignLeft,
            QColor("#E0E0E0"),
        )
        app.processEvents()
    else:
        splash = None

    # Create main window, passing the shared app icon
    window = MainWindow(app_icon=app_icon)

    if splash:
        splash.finish(window)

    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()