"""
Autobahn Defender - Settings Manager
Persistent settings using QSettings.
"""

import sys
from PyQt6.QtCore import QSettings
from pathlib import Path

APP_DIR = Path.home() / ".autobahn"
RULES_DIR = APP_DIR / "rules"


class SettingsManager:
    """Manages application settings with QSettings persistence."""

    def __init__(self):
        self.settings = QSettings("Digital Autobahn", "Autobahn Defender")

    # --- Real-time monitoring ---

    def is_realtime_enabled(self):
        return self.settings.value("realtime/enabled", False, type=bool)

    def set_realtime_enabled(self, enabled):
        self.settings.setValue("realtime/enabled", enabled)

    def get_watch_path(self):
        default = str(Path.home() / "Downloads")
        return self.settings.value("realtime/watch_path", default, type=str)

    def set_watch_path(self, path):
        self.settings.setValue("realtime/watch_path", path)

    def get_watch_folders(self):
        """Return list of up to 3 custom watch folder paths."""
        default = str(Path.home() / "Downloads")
        folders = self.settings.value("realtime/folders", [default])
        if not isinstance(folders, list) or not folders:
            folders = [default]
        return folders[:3]

    def set_watch_folders(self, folders):
        self.settings.setValue("realtime/folders", folders[:3])

    def is_auto_scan_external(self):
        return self.settings.value("realtime/auto_scan_external", False, type=bool)

    def set_auto_scan_external(self, enabled):
        self.settings.setValue("realtime/auto_scan_external", enabled)

    def is_auto_scan_usb(self):
        return self.settings.value("realtime/auto_scan_usb", False, type=bool)

    def set_auto_scan_usb(self, enabled):
        self.settings.setValue("realtime/auto_scan_usb", enabled)

    # --- Scheduled scans ---

    def get_scan_interval(self):
        """Return scan interval in hours. 0 = disabled."""
        return self.settings.value("schedule/interval_hours", 0, type=int)

    def set_scan_interval(self, hours):
        self.settings.setValue("schedule/interval_hours", hours)

    def get_scan_time(self):
        """Return scheduled scan time as 'HH:MM' string."""
        return self.settings.value("schedule/time", "02:00", type=str)

    def set_scan_time(self, time_str):
        self.settings.setValue("schedule/time", time_str)

    def get_schedule_scan_type(self):
        """Return the scan type for scheduled scans."""
        return self.settings.value("schedule/scan_type", "quick_home", type=str)

    def set_schedule_scan_type(self, scan_type):
        self.settings.setValue("schedule/scan_type", scan_type)

    def is_schedule_enabled(self):
        return self.settings.value("schedule/enabled", False, type=bool)

    def set_schedule_enabled(self, enabled):
        self.settings.setValue("schedule/enabled", enabled)

    # --- YARA rules ---

    def get_custom_yara_rules(self):
        """Return custom YARA rules text."""
        return self.settings.value("yara/custom_rules", "", type=str)

    def set_custom_yara_rules(self, text):
        self.settings.setValue("yara/custom_rules", text)
        self._save_yara_rules(text)

    def is_scan_windows_malware(self):
        """Whether to scan for Windows malware (PE files). Default: False."""
        return self.settings.value("yara/scan_windows_malware", False, type=bool)

    def set_scan_windows_malware(self, enabled):
        self.settings.setValue("yara/scan_windows_malware", enabled)

    def _save_yara_rules(self, text):
        """Save custom YARA rules to a .yar file."""
        RULES_DIR.mkdir(parents=True, exist_ok=True)
        rule_file = RULES_DIR / "custom.yar"
        if text.strip():
            rule_file.write_text(text)
        else:
            if rule_file.exists():
                rule_file.unlink()

    # --- Whitelist ---

    def get_whitelist(self):
        """Return list of whitelisted paths."""
        from scanner import get_whitelist
        return get_whitelist()

    def set_whitelist(self, paths):
        """Save whitelist paths."""
        from scanner import save_whitelist
        save_whitelist(paths)

    # --- Performance mode ---

    def is_performance_mode(self):
        return self.settings.value("performance/mode", False, type=bool)

    def set_performance_mode(self, enabled):
        self.settings.setValue("performance/mode", enabled)

    # --- Silent mode ---

    def is_silent_mode(self):
        return self.settings.value("notifications/silent", False, type=bool)

    def set_silent_mode(self, enabled):
        self.settings.setValue("notifications/silent", enabled)

    # --- Auto-start ---

    def is_autostart_enabled(self):
        return self.settings.value("autostart/enabled", False, type=bool)

    def set_autostart_enabled(self, enabled):
        self.settings.setValue("autostart/enabled", enabled)
        self.settings.sync()  # Force write to disk immediately
        self._update_autostart(enabled)

    def is_start_minimized(self):
        """Whether to start minimized to system tray. Default: False."""
        return self.settings.value("autostart/start_minimized", False, type=bool)

    def set_start_minimized(self, enabled):
        self.settings.setValue("autostart/start_minimized", enabled)
        self.settings.sync()  # Force write to disk immediately
        # Rewrite the .desktop file to include/remove the --minimized flag.
        # Use main.py's _set_autostart for consistency (it knows the correct
        # exec path — the launcher script /usr/bin/autobahn-defender, not
        # settings.py's own path).
        # We delegate to _update_autostart which reads is_start_minimized().

    def _update_autostart(self, enabled):
        """Create or remove desktop entry for autostart.

        Includes --minimized flag if the start_minimized setting is enabled.
        Uses the correct executable path — the launcher script if installed
        via deb, or main.py if running from source.
        """
        autostart_dir = Path.home() / ".config" / "autostart"
        autostart_dir.mkdir(parents=True, exist_ok=True)
        desktop_file = autostart_dir / "com.digitalautobahn.AutobahnDefender.desktop"

        if enabled:
            # Resolve the binary path
            # 1. Check if the deb-installed launcher exists
            launcher = Path("/usr/bin/autobahn-defender")
            if launcher.exists():
                exec_path = str(launcher)
            # 2. Check PyInstaller frozen mode
            elif getattr(sys, "frozen", False):
                exec_path = sys.executable
            # 3. Fall back to main.py in the same directory as this file
            else:
                exec_path = str(Path(__file__).resolve().parent / "main.py")

            # Add --minimized flag if start minimized is enabled
            exec_line = exec_path
            if self.is_start_minimized():
                exec_line = f"{exec_path} --minimized"

            desktop_file.write_text(
                "[Desktop Entry]\n"
                "Type=Application\n"
                "Name=Autobahn Defender\n"
                "Comment=Antivirus protection\n"
                f"Exec={exec_line}\n"
                "Icon=autobahn-defender\n"
                "Categories=System;Security;\n"
                "StartupNotify=false\n"
                "Terminal=false\n"
                "X-GNOME-Autostart-enabled=true\n"
                "X-KDE-autostart-after=panel\n"
            )
        else:
            if desktop_file.exists():
                desktop_file.unlink()

    # --- General ---

    def get_last_scan_type(self):
        return self.settings.value("general/last_scan_type", "", type=str)

    def set_last_scan_type(self, scan_type):
        self.settings.setValue("general/last_scan_type", scan_type)

    # --- Scan options ---

    def is_scan_archives(self):
        """Whether to scan inside compressed/archive files. Default: True."""
        return self.settings.value("scan/archives", True, type=bool)

    def set_scan_archives(self, enabled):
        self.settings.setValue("scan/archives", enabled)

    def is_scan_hidden(self):
        """Whether to scan hidden files/directories. Default: True."""
        return self.settings.value("scan/hidden", True, type=bool)

    def set_scan_hidden(self, enabled):
        self.settings.setValue("scan/hidden", enabled)

    # --- Scan threads ---

    @staticmethod
    def default_thread_count():
        """Return the default thread count based on CPU cores.
        25% of cores, minimum 1. Below 4 cores defaults to 1.
        """
        import os
        cores = os.cpu_count() or 1
        if cores < 4:
            return 1
        return max(1, cores // 4)

    def get_scan_threads(self):
        """Return number of threads for scanning. Default: 1-2 based on CPU."""
        default = self.default_thread_count()
        return self.settings.value("scan/threads", default, type=int)

    def set_scan_threads(self, count):
        self.settings.setValue("scan/threads", count)