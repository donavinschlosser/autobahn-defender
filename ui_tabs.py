"""
Autobahn Defender - UI Tab Widgets
Dashboard, Scan, Quarantine, Settings, About, and History tabs.
"""

import os
import html
import shutil
import subprocess
import urllib.request
import json
from pathlib import Path
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton,
    QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QSpinBox, QTimeEdit, QTextEdit, QCheckBox,
    QGroupBox, QScrollArea, QSizePolicy, QMessageBox, QComboBox,
    QListWidget, QListWidgetItem, QTabWidget, QLineEdit, QDialog,
    QDialogButtonBox, QPlainTextEdit, QMenu, QStyledItemDelegate,
    QFrame,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap, QFont, QColor

from scanner import Scanner, find_clamscan, find_yara, DEFS_DIR, RULES_DIR, get_whitelist, save_whitelist, is_whitelisted
from quarantine import QuarantineManager
from settings import SettingsManager
from updater import AppUpdater, CURRENT_VERSION, InstallProgressDialog
from yara_updater import YaraRuleUpdater, get_yara_last_updated
from history_db import init_db, log_scan, log_quarantine_action, log_audit, get_scan_history, get_quarantine_history, get_audit_history
from kernel_checker import KernelCheckWorker
from firewall import detect_firewall, get_firewall_status, FirewallApplyWorker
from hardening import HardeningCheckWorker
from usb_monitor import USBMonitorWorker


# --- Helper: larger, resizable message boxes ---
def _make_message_box(parent, title, text, icon=QMessageBox.Icon.Information, detail=None, buttons=QMessageBox.StandardButton.Ok):
    """Create a QMessageBox that is larger and resizable."""
    box = QMessageBox(icon, title, text, buttons, parent)
    box.setTextFormat(Qt.TextFormat.PlainText)
    # Make the dialog wider and allow text to wrap
    box.setMinimumWidth(520)
    box.setMinimumHeight(300)
    # Force resizable by setting the size grip
    spacer = QWidget()
    spacer.setMinimumSize(500, 0)
    box.layout().addWidget(spacer, box.layout().rowCount(), 0, 1, box.layout().columnCount())
    if detail:
        box.setDetailedText(detail)
        # Auto-show the detail area so text is visible
        # Use contains() instead of exact match for better locale support
        for btn in box.findChildren(QPushButton):
            if "show details" in btn.text().lower() or "show" in btn.text().lower():
                btn.click()
                break
    return box


# --- Theme colors ---
BG_DARK = "#121212"
BG_CARD = "#1E1E1E"
BORDER = "#2C2C2C"
ACCENT = "#2962FF"
ACCENT_HOVER = "#1E53E0"
BTN_BLUE = "#0D47A1"
BTN_BLUE_HOVER = "#0A3D8F"
TEXT_PRIMARY = "#E0E0E0"
TEXT_SECONDARY = "#A0A0A0"
DANGER = "#CF6679"
SUCCESS = "#4CAF50"
SIDEBAR_HOVER = "#1A1A2E"

STYLESHEET = f"""
    QWidget {{ background-color: {BG_DARK}; color: {TEXT_PRIMARY}; }}
    QLabel {{ color: {TEXT_PRIMARY}; background: transparent; }}
    QPushButton {{
        background-color: {BTN_BLUE};
        color: white;
        border: 1px solid #093680;
        border-radius: 8px;
        padding: 8px 18px;
        font-size: 13px;
        font-weight: bold;
        min-width: 90px;
        min-height: 36px;
    }}
    QPushButton:hover {{ background-color: {BTN_BLUE_HOVER}; border-color: #072d6b; }}
    QPushButton:pressed {{ background-color: #0A3D8F; border-color: #062659; }}
    QPushButton:disabled {{ background-color: #455A64; color: #888; border-color: #37474F; }}
    QGroupBox {{

        background-color: {BG_CARD};
        border: 1px solid {BORDER};
        border-radius: 10px;
        margin-top: 20px;
        padding: 20px;
        padding-top: 28px;
        font-weight: bold;
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 16px;
        padding: 0 8px;
        color: {TEXT_PRIMARY};
        background-color: transparent;
        font-size: 14px;
    }}
    QTableWidget {{
        background-color: {BG_CARD};
        border: 1px solid {BORDER};
        border-radius: 10px;
        gridline-color: #333;
        color: {TEXT_PRIMARY};
    }}
    QTableWidget::item {{
        padding: 8px;
    }}
    QHeaderView::section {{
        background-color: #262626;
        color: {TEXT_PRIMARY};
        border: none;
        border-bottom: 1px solid {BORDER};
        padding: 8px;
        font-weight: bold;
    }}
    QProgressBar {{
        background-color: {BG_CARD};
        border: 1px solid {BORDER};
        border-radius: 4px;
        text-align: center;
        color: white;
        height: 24px;
    }}
    QProgressBar::chunk {{
        background-color: {ACCENT};
        border-radius: 3px;
    }}
    QTextEdit {{
        background-color: {BG_CARD};
        border: 1px solid {BORDER};
        border-radius: 6px;
        color: {TEXT_PRIMARY};
        padding: 8px;
        font-family: monospace;
    }}
    QCheckBox {{
        color: {TEXT_PRIMARY};
        spacing: 8px;
        background: transparent;
    }}
    QCheckBox::indicator {{
        width: 20px;
        height: 20px;
        border-radius: 4px;
        border: 2px solid {BORDER};
        background-color: {BG_CARD};
    }}
    QCheckBox::indicator:checked {{
        background-color: {ACCENT};
        border-color: {ACCENT};
    }}
    QSpinBox, QTimeEdit {{
        background-color: {BG_CARD};
        border: 1px solid {BORDER};
        border-radius: 6px;
        padding: 6px;
        color: {TEXT_PRIMARY};
        selection-background-color: {ACCENT};
    }}
    QSpinBox::up-button, QSpinBox::down-button,
    QTimeEdit::up-button, QTimeEdit::down-button {{
        background-color: {BORDER};
        border: none;
        width: 20px;
    }}
    QSpinBox::up-button:hover, QSpinBox::down-button:hover,
    QTimeEdit::up-button:hover, QTimeEdit::down-button:hover {{
        background-color: {ACCENT};
    }}
    QComboBox {{
        background-color: {BG_CARD};
        border: 1px solid {BORDER};
        border-radius: 4px;
        padding: 4px 8px;
        color: {TEXT_PRIMARY};
        min-height: 24px;
    }}
    QComboBox:hover {{
        border-color: {ACCENT};
    }}
    QComboBox::drop-down {{
        border: none;
        width: 20px;
    }}
    QComboBox::down-arrow {{
        image: none;
        border-left: 4px solid transparent;
        border-right: 4px solid transparent;
        border-top: 5px solid {TEXT_SECONDARY};
        margin-right: 4px;
    }}
    QComboBox QAbstractItemView {{
        background-color: {BG_CARD};
        border: 1px solid {BORDER};
        border-radius: 4px;
        color: {TEXT_PRIMARY};
        selection-background-color: {ACCENT};
        selection-color: white;
        outline: none;
        padding: 2px;
    }}
    QComboBox QAbstractItemView::item {{
        height: 28px;
        padding: 2px 8px;
    }}
    QLineEdit {{
        background-color: {BG_CARD};
        border: 1px solid {BORDER};
        border-radius: 6px;
        padding: 6px 12px;
        color: {TEXT_PRIMARY};
    }}
    QLineEdit:focus {{
        border-color: {ACCENT};
    }}
    QScrollArea {{ border: none; background: transparent; }}
    QScrollBar:vertical {{
        background: {BG_DARK};
        width: 10px;
    }}
    QScrollBar::handle:vertical {{
        background: {BORDER};
        border-radius: 5px;
        min-height: 20px;
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
    QScrollBar:horizontal {{
        background: {BG_DARK};
        height: 10px;
    }}
    QScrollBar::handle:horizontal {{
        background: {BORDER};
        border-radius: 5px;
        min-width: 20px;
    }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
    QMessageBox {{ min-width: 520px; }}
    QMessageBox QLabel {{ min-width: 480px; min-height: 60px; }}
    QTabWidget::pane {{
        border: 1px solid {BORDER};
        background: {BG_DARK};
    }}
    QTabBar::tab {{
        background: {BG_CARD};
        color: {TEXT_SECONDARY};
        padding: 8px 16px;
        border: 1px solid {BORDER};
        border-bottom: none;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
    }}
    QTabBar::tab:selected {{
        background: {ACCENT};
        color: white;
    }}
    QTabBar::tab:hover {{
        background: {SIDEBAR_HOVER};
        color: white;
    }}
"""


class CardWidget(QGroupBox):
    """A styled card widget for the dashboard."""

    def __init__(self, title="", parent=None):
        super().__init__(title, parent)


def _make_combo(items, default_index=0):
    """Create a QComboBox for use in a table cell."""
    combo = QComboBox()
    combo.addItems(items)
    combo.setCurrentIndex(default_index)
    return combo


class DefsUpdateDialog(QDialog):
    """Progress dialog showing virus definition AND YARA rule update status.

    Runs both updates in sequence: definitions first, then YARA rules.
    Shows combined progress across both phases.
    """

    def __init__(self, scanner: Scanner, parent=None):
        super().__init__(parent)
        self.scanner = scanner
        self.setWindowTitle("Updating Definitions & YARA Rules")
        self.setModal(True)
        self.setMinimumWidth(500)
        self._worker_ref = None  # Keep reference to worker
        self._yara_updater = YaraRuleUpdater()
        self._yara_phase = False  # True when we're in the YARA phase
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Title
        self.title = QLabel("Downloading Virus Definitions")
        self.title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self.title.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent;")
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.title)

        # Status label
        self.status_label = QLabel("Initializing...")
        self.status_label.setFont(QFont("Segoe UI", 10))
        self.status_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)

        # Progress bar
        progress_card = CardWidget("Progress")
        progress_layout = QVBoxLayout(progress_card)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        progress_layout.addWidget(self.progress_bar)

        # Speed/bytes info
        self.speed_label = QLabel("")
        self.speed_label.setFont(QFont("Segoe UI", 9))
        self.speed_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        self.speed_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        progress_layout.addWidget(self.speed_label)

        layout.addWidget(progress_card)

        # Cancel button
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setMinimumHeight(36)
        self.cancel_btn.clicked.connect(self._on_cancel)
        layout.addWidget(self.cancel_btn)

    def _connect_signals(self):
        """Connect scanner signals to dialog update handlers."""
        self._start_time = None
        self._phase_start = None

        self.scanner.defs_update_status.connect(self._on_status)
        self.scanner.defs_update_progress.connect(self._on_progress)
        self.scanner.defs_update_finished.connect(self._on_defs_finished)
        # Track the worker so we can cancel it
        self.scanner.defs_started.connect(self._on_worker_started)

    def _on_worker_started(self):
        """Enable cancel button when update starts."""
        self.cancel_btn.setEnabled(True)
        self._start_time = datetime.now()
        self._phase_start = datetime.now()

    def _on_status(self, status: str):
        """Update status label with current operation."""
        self.status_label.setText(status)

        # Show elapsed time for active operations
        is_download = "downloading" in status.lower() or "updated" in status.lower()
        if is_download and self._start_time is not None:
            elapsed = (datetime.now() - self._start_time).total_seconds()
            if elapsed >= 1:
                self.speed_label.setText(f"Elapsed: {self._format_elapsed(int(elapsed))}")

    def _format_elapsed(self, seconds: int) -> str:
        """Format elapsed seconds as human-readable string."""
        if seconds >= 60:
            mins = seconds // 60
            secs = seconds % 60
            return f"{mins}m {secs}s"
        return f"{seconds}s"

    def _on_progress(self, pct: int):
        """Update progress bar."""
        self.progress_bar.setValue(pct)

    def _on_defs_finished(self, ok: bool, msg: str):
        """Handle definition update completion, then start YARA update."""
        if not ok:
            # Definitions failed -- still try YARA rules
            self.status_label.setText(f"Definitions: {msg}")
            self._start_yara_phase()
            return

        self.status_label.setText(f"Definitions: {msg}")
        self._start_yara_phase()

    def _start_yara_phase(self):
        """Start the YARA rule update phase."""
        self._yara_phase = True
        self.title.setText("Updating YARA Rules")
        self.status_label.setText("Checking for YARA rule updates...")
        self.progress_bar.setValue(50)
        self.cancel_btn.setText("Close")
        self.cancel_btn.setEnabled(True)

        # Run YARA update check in a background thread
        self._yara_check_worker = YaraUpdateCheckWorker()
        self._yara_check_worker.finished.connect(self._on_yara_check_result)
        self._yara_check_worker.start()

    def _on_yara_check_result(self, result):
        """Handle YARA update check result."""
        if result.get("available"):
            self.status_label.setText("Downloading YARA rules...")
            self.progress_bar.setValue(60)
            self._yara_download_worker = YaraRuleDownloadWorker(result.get("version", "unknown"))
            self._yara_download_worker.progress.connect(self._on_yara_progress)
            self._yara_download_worker.status.connect(self._on_yara_status)
            self._yara_download_worker.finished.connect(self._on_yara_download_finished)
            self._yara_download_worker.start()
        else:
            self._finish_yara_phase("YARA rules are up to date")

    def _on_yara_progress(self, pct):
        """Update progress during YARA download."""
        self.progress_bar.setValue(50 + int(pct * 0.4))  # Scale 0-100 to 50-90

    def _on_yara_status(self, msg):
        """Update status during YARA download."""
        self.status_label.setText(msg)

    def _on_yara_download_finished(self, success, message):
        """Handle YARA download completion."""
        if success:
            self._finish_yara_phase(f"YARA rules updated: {message}")
        else:
            self._finish_yara_phase(f"YARA rules: {message}")

    def _finish_yara_phase(self, msg):
        """Finish the YARA phase and close the dialog."""
        self.status_label.setText(msg)
        self.progress_bar.setValue(100)
        self.cancel_btn.setEnabled(False)

        if self._start_time is not None:
            elapsed = (datetime.now() - self._start_time).total_seconds()
            if elapsed >= 1:
                self.speed_label.setText(f"Completed in {self._format_elapsed(int(elapsed))}")
            else:
                self.speed_label.setText("")

        QTimer.singleShot(1500, self.accept)

    def _on_cancel(self):
        """Handle cancel button click."""
        if not self._yara_phase:
            # Cancel definitions phase
            if self.scanner._defs_worker and self.scanner._defs_worker.isRunning():
                self.scanner._defs_worker.terminate()
        self.accept()

    def closeEvent(self, event):
        """Cancel the running worker and disconnect signals when dialog is closed."""
        try:
            self.scanner.defs_update_status.disconnect(self._on_status)
        except TypeError:
            pass
        try:
            self.scanner.defs_update_progress.disconnect(self._on_progress)
        except TypeError:
            pass
        try:
            self.scanner.defs_update_finished.disconnect(self._on_defs_finished)
        except TypeError:
            pass
        try:
            self.scanner.defs_started.disconnect(self._on_worker_started)
        except TypeError:
            pass
        if self.scanner._defs_worker and self.scanner._defs_worker.isRunning():
            self.scanner._defs_worker.terminate()
        super().closeEvent(event)


class DashboardTab(QWidget):
    """Dashboard tab with status overview and quick actions."""

    def __init__(self, scanner: Scanner, parent=None):
        super().__init__(parent)
        self.scanner = scanner
        self.setup_ui()

    def setup_ui(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        content = QWidget()
        content.setStyleSheet(f"background-color: {BG_DARK};")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Status header
        header = QLabel("Dashboard")
        header.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        header.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent;")
        layout.addWidget(header)

        version_label = QLabel(f"Autobahn Defender v{CURRENT_VERSION}")
        version_label.setFont(QFont("Segoe UI", 11))
        version_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        layout.addWidget(version_label)

        # Status card
        status_card = CardWidget("Scan Status")
        status_layout = QVBoxLayout(status_card)
        status_layout.setSpacing(12)

        self.status_label = QLabel("No scan running")
        self.status_label.setFont(QFont("Segoe UI", 13))
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        status_layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        status_layout.addWidget(self.progress_bar)

        self.current_file_label = QLabel("")
        self.current_file_label.setFont(QFont("Segoe UI", 10))
        self.current_file_label.setStyleSheet(
            f"color: {TEXT_SECONDARY}; background: transparent;"
        )
        self.current_file_label.setWordWrap(True)
        status_layout.addWidget(self.current_file_label)

        # ETA label (elapsed / estimated time)
        self.eta_label = QLabel("")
        self.eta_label.setFont(QFont("Segoe UI", 10))
        self.eta_label.setStyleSheet(
            f"color: {TEXT_SECONDARY}; background: transparent;"
        )
        self.eta_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        status_layout.addWidget(self.eta_label)

        self.defs_last_updated_label = QLabel("")
        self.defs_last_updated_label.setFont(QFont("Segoe UI", 9))
        self.defs_last_updated_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        self.defs_last_updated_label.setWordWrap(True)
        status_layout.addWidget(self.defs_last_updated_label)

        # Update buttons row
        update_row = QHBoxLayout()
        self.update_defs_btn = QPushButton("Update Definitions")
        self.update_defs_btn.setMinimumHeight(36)
        self.update_defs_btn.clicked.connect(self._update_definitions)
        update_row.addWidget(self.update_defs_btn)

        self.check_app_update_btn = QPushButton("Check for App Updates")
        self.check_app_update_btn.setMinimumHeight(36)
        self.check_app_update_btn.clicked.connect(self._check_app_updates)
        update_row.addWidget(self.check_app_update_btn)
        status_layout.addLayout(update_row)

        self._refresh_defs_status()
        layout.addWidget(status_card)

        # Quick actions card
        actions_card = CardWidget("Quick Actions")
        actions_layout = QVBoxLayout(actions_card)
        actions_layout.setSpacing(10)

        actions_row = QHBoxLayout()
        actions_row.setSpacing(10)

        self.home_scan_btn = QPushButton("Home Scan")
        self.home_scan_btn.setMinimumHeight(44)
        self.home_scan_btn.setMinimumWidth(140)
        self.home_scan_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.home_scan_btn.clicked.connect(lambda: self.start_scan("quick_home"))
        actions_row.addWidget(self.home_scan_btn)

        self.kernel_btn = QPushButton("Kernel Modules")
        self.kernel_btn.setMinimumHeight(44)
        self.kernel_btn.setMinimumWidth(140)
        self.kernel_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.kernel_btn.clicked.connect(self._run_kernel_check)
        actions_row.addWidget(self.kernel_btn)

        self.hardening_btn = QPushButton("System Audit")
        self.hardening_btn.setMinimumHeight(44)
        self.hardening_btn.setMinimumWidth(140)
        self.hardening_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.hardening_btn.clicked.connect(self._run_hardening_audit)
        actions_row.addWidget(self.hardening_btn)

        actions_layout.addLayout(actions_row)
        layout.addWidget(actions_card)

        self._action_btns = [self.home_scan_btn, self.kernel_btn, self.hardening_btn]

        # Stats card — enhanced with color-coded threat display
        stats_card = CardWidget("Last Scan Results")
        stats_layout = QVBoxLayout(stats_card)

        stats_row = QHBoxLayout()
        self.stats_label = QLabel("No scan data available")
        self.stats_label.setFont(QFont("Segoe UI", 11))
        self.stats_label.setWordWrap(True)
        self.stats_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        stats_row.addWidget(self.stats_label, 1)

        self.dashboard_results_btn = QPushButton("Scan Results")
        self.dashboard_results_btn.setEnabled(False)
        self.dashboard_results_btn.setMinimumHeight(36)
        self.dashboard_results_btn.clicked.connect(self._open_results)
        stats_row.addWidget(self.dashboard_results_btn)

        stats_layout.addLayout(stats_row)

        # Visual threat summary bar
        self.threat_summary_label = QLabel("")
        self.threat_summary_label.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        self.threat_summary_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.threat_summary_label.setStyleSheet(
            f"background-color: {BG_DARK}; color: {SUCCESS}; "
            f"border: 1px solid {BORDER}; border-radius: 8px; padding: 12px; margin: 4px;"
        )
        self.threat_summary_label.setText("  System Protected  ")
        stats_layout.addWidget(self.threat_summary_label)

        layout.addWidget(stats_card)

        # Export button
        self.export_btn = QPushButton("Export Scan Report")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._export_report)
        layout.addWidget(self.export_btn)

        layout.addStretch()
        scroll.setWidget(content)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        # Connect scanner signals
        self.scanner.scan_progress.connect(self.on_progress)
        self.scanner.scan_file.connect(self.on_file)
        self.scanner.scan_finished.connect(self.on_scan_finished)
        self.scanner.scan_started.connect(self.on_scan_started)
        self.scanner.scan_error.connect(lambda msg: QMessageBox.warning(self, "Scan Error", msg))

        self._last_scan_results = None

        # Scan phase tracking
        self._scan_phase = "idle"  # idle, yara, clamav

    def on_scan_started(self):
        self.status_label.setText("Scanning...")
        self.progress_bar.setValue(0)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setFormat("%p%")
        for btn in self._action_btns:
            btn.setEnabled(False)

    def on_progress(self, pct):
        self.progress_bar.setValue(pct)

    def start_scan(self, scan_type):
        if scan_type == "full_system" and os.geteuid() != 0:
            reply = QMessageBox.warning(
                self, "Limited Scan",
                "Full system scan works best with root privileges.\n"
                "Some files will be skipped.\n\nContinue anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.No:
                return
        if scan_type == "custom":
            path = QFileDialog.getExistingDirectory(
                self, "Select Directory to Scan", "",
                QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontUseNativeDialog,
            )
            if not path:
                return
            self.scanner.start_scan(scan_type, custom_paths=[path])
        else:
            self.scanner.start_scan(scan_type)

    def on_file(self, filename):
        # ClamAV phase starting
        if filename == "CLAM_START":
            self._scan_phase = "clamav"
            self.current_file_label.setText("ClamAV: Scanning...")
            return
        # Just show whatever the scanner sends — YARA progress or ClamAV file paths
        self.current_file_label.setText(filename)

    def on_scan_finished(self, results):
        self._scan_phase = "idle"
        self.status_label.setText("Scan complete")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.current_file_label.setText("")
        self.eta_label.setText("")
        for btn in self._action_btns:
            btn.setEnabled(True)
        files = results.get("files_scanned", 0)
        threats = results.get("threats_found", 0)
        self.stats_label.setText(
            f"Files scanned: {files}  |  Threats found: {threats}"
        )
        self._last_scan_results = results
        self.export_btn.setEnabled(True)
        self.dashboard_results_btn.setEnabled(bool(results.get("details")))

        # Update visual threat summary with color coding
        if threats == 0:
            self.threat_summary_label.setText(f"  No threats found — {files} files scanned  ")
            self.threat_summary_label.setStyleSheet(
                f"background-color: {BG_DARK}; color: {SUCCESS}; "
                f"border: 1px solid {SUCCESS}; border-radius: 8px; padding: 12px; margin: 4px;"
            )
        elif threats <= 5:
            self.threat_summary_label.setText(f"  {threats} threat(s) found — review recommended  ")
            self.threat_summary_label.setStyleSheet(
                f"background-color: {BG_DARK}; color: #FFB74D; "
                f"border: 1px solid #FFB74D; border-radius: 8px; padding: 12px; margin: 4px;"
            )
        else:
            self.threat_summary_label.setText(f"  {threats} threats found — immediate action required  ")
            self.threat_summary_label.setStyleSheet(
                f"background-color: {BG_DARK}; color: {DANGER}; "
                f"border: 1px solid {DANGER}; border-radius: 8px; padding: 12px; margin: 4px;"
            )

        # Log to history
        scan_type = getattr(self.scanner._worker, 'scan_type', 'unknown') if self.scanner._worker else 'unknown'
        log_scan(scan_type, files, threats, results.get("details", []))

    def _open_results(self):
        """Open the scan results dialog from the Dashboard."""
        if not self._last_scan_results or not self._last_scan_results.get("details"):
            QMessageBox.information(self, "Scan Results", "No scan results available.")
            return
        main_window = self.window()
        quarantine_mgr = getattr(main_window, 'quarantine_mgr', None)
        settings_mgr = getattr(main_window, 'settings_mgr', None)
        dialog = ScanResultsDialog(self._last_scan_results, quarantine_mgr, settings_mgr, self)
        dialog.setStyleSheet(STYLESHEET)
        dialog.exec()
        dialog_results = dialog.get_results()
        details = self._last_scan_results.get("details", [])
        for i, d in enumerate(dialog_results):
            if i < len(details) and "_user_action" in d:
                details[i]["_user_action"] = d["_user_action"]
        if any("_user_action" in d and d["_user_action"] != "skipped" for d in details if isinstance(d, dict)):
            if hasattr(main_window, 'quarantine_tab'):
                main_window.quarantine_tab.refresh()

    def _refresh_defs_status(self):
        from scanner import get_defs_last_updated
        last = get_defs_last_updated()
        self.defs_last_updated_label.setText(f"Definitions last updated: {last}")

    def _update_definitions(self):
        self.update_defs_btn.setEnabled(False)
        self.status_label.setText("Updating definitions...")
        # Create and show the definition update dialog
        self._defs_dialog = DefsUpdateDialog(self.scanner, self)
        self._defs_dialog.setStyleSheet(STYLESHEET)
        self._defs_dialog.show()
        self.scanner.update_definitions()
        # Re-enable the button when the dialog closes
        self._defs_dialog.finished.connect(
            lambda: self.update_defs_btn.setEnabled(True)
        )
        self._defs_dialog.finished.connect(self._refresh_defs_status)

    def _check_app_updates(self):
        self.check_app_update_btn.setEnabled(False)
        self.check_app_update_btn.setText("Checking...")
        self._app_updater = AppUpdater(self)
        self._app_updater.check_for_updates(silent=False)
        # Re-enable button after a short delay (the check is async)
        QTimer.singleShot(5000, lambda: self.check_app_update_btn.setEnabled(True))
        QTimer.singleShot(5000, lambda: self.check_app_update_btn.setText("Check for App Updates"))

    def _run_kernel_check(self):
        self.kernel_btn.setEnabled(False)
        self.status_label.setText("Checking kernel modules...")
        self._kernel_worker = KernelCheckWorker()
        self._kernel_worker.finished.connect(self._on_kernel_check_finished)
        self._kernel_worker.start()

    def _on_kernel_check_finished(self, results):
        self.kernel_btn.setEnabled(True)
        self.status_label.setText("Kernel check complete")

        if "error" in results:
            QMessageBox.warning(self, "Kernel Check", f"Error: {results['error']}")
            return

        total = results.get("total", 0)
        suspicious = results.get("suspicious", [])
        unsigned = results.get("unsigned", [])
        unknown_source = results.get("unknown_source", [])

        log_audit("kernel_modules", suspicious + unsigned + unknown_source)

        msg = f"Total modules loaded: {total}\n\n"
        if suspicious:
            msg += f"Suspicious names ({len(suspicious)}):\n"
            for m in suspicious[:10]:
                msg += f"  • {m['name']}\n"
            msg += "\n"
        if unsigned:
            msg += f"Unsigned modules ({len(unsigned)}):\n"
            for m in unsigned[:10]:
                msg += f"  • {m['name']} — {m.get('filename', 'unknown')}\n"
            msg += "\n"
        if unknown_source:
            msg += f"Unknown source modules ({len(unknown_source)}):\n"
            for m in unknown_source[:10]:
                msg += f"  • {m['name']} — {m.get('filename', 'unknown')}\n"
            msg += "\n"

        if not suspicious and not unsigned and not unknown_source:
            msg += "No suspicious modules detected."
        else:
            msg += "\nReview these modules for potential security risks."

        box = _make_message_box(self, "Kernel Module Check", msg, icon=QMessageBox.Icon.Information)
        box.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        box.exec()

    def _run_hardening_audit(self):
        self.hardening_btn.setEnabled(False)
        self.status_label.setText("Running system audit...")
        self._hardening_worker = HardeningCheckWorker()
        self._hardening_worker.finished.connect(self._on_hardening_finished)
        self._hardening_worker.start()

    def _on_hardening_finished(self, findings):
        self.hardening_btn.setEnabled(True)
        self.status_label.setText("System audit complete")

        checks = findings.get("checks", [])
        distro = findings.get("distro", {})

        log_audit("hardening", checks)

        pass_count = sum(1 for c in checks if c.get("status") == "pass")
        warn_count = sum(1 for c in checks if c.get("status") == "warn")
        total = len(checks)

        msg = f"System Hardening Audit Results\n"
        msg += f"Distribution: {distro.get('name', 'Unknown')}\n\n"
        msg += f"Passed: {pass_count}/{total}  |  Warnings: {warn_count}\n\n"

        for check in checks:
            icon = "+" if check.get("status") == "pass" else "!"
            severity = check.get("severity", "info").upper()
            name = check.get("name", "Unknown")
            desc = check.get("description", "")
            rec = check.get("recommendation", "")
            msg += f"[{icon}] {name} ({severity})\n    {desc}\n"
            if check.get("status") == "warn":
                msg += f"    → {rec}\n"
            msg += "\n"

        # Show in a custom resizable dialog
        dlg = QDialog(self)
        dlg.setWindowTitle("System Hardening Audit")
        dlg.setMinimumSize(650, 500)
        dlg.setStyleSheet(f"background-color: {BG_DARK}; color: {TEXT_PRIMARY};")
        dlg_layout = QVBoxLayout(dlg)

        summary = QLabel(f"Audit complete: {pass_count}/{total} passed, {warn_count} warnings")
        summary.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        summary.setWordWrap(True)
        summary.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent;")
        dlg_layout.addWidget(summary)

        detail = QPlainTextEdit()
        detail.setPlainText(msg)
        detail.setReadOnly(True)
        detail.setFont(QFont("Segoe UI", 10))
        detail.setStyleSheet(
            f"background-color: {BG_CARD}; color: {TEXT_PRIMARY}; "
            f"border: 1px solid {BORDER}; border-radius: 6px; padding: 8px;"
        )
        dlg_layout.addWidget(detail, 1)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        dlg_layout.addWidget(close_btn)
        dlg.exec()

    def _export_report(self):
        if not self._last_scan_results:
            QMessageBox.information(self, "Export", "No scan results to export.")
            return

        results = self._last_scan_results
        dest = QFileDialog.getSaveFileName(
            self, "Export Scan Report", "scan_report.html", "HTML Files (*.html)",
            options=QFileDialog.Option.DontUseNativeDialog,
        )[0]
        if not dest:
            return

        report = f"""<!DOCTYPE html>
<html><head><title>Autobahn Defender Scan Report</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #121212; color: #E0E0E0; margin: 40px; }}
h1 {{ color: #2962FF; }} h2 {{ color: #4CAF50; }}
table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
th, td {{ border: 1px solid #2C2C2C; padding: 10px; text-align: left; }}
th {{ background: #1E1E1E; color: #E0E0E0; }}
tr:nth-child(even) {{ background: #1A1A1A; }}
.pass {{ color: #4CAF50; }} .warn {{ color: #CF6679; }} .info {{ color: #A0A0A0; }}
</style></head><body>
<h1>Autobahn Defender Scan Report</h1>
<p><b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<p><b>Files scanned:</b> {results.get('files_scanned', 0)}</p>
<p><b>Threats found:</b> {results.get('threats_found', 0)}</p>
"""
        details = results.get("details", [])
        if details:
            report += "<h2>Details</h2><table><tr><th>File</th><th>Threat</th><th>Action</th></tr>\n"
            for d in details:
                action = d.get("_user_action", d.get("action", ""))
                cls = "warn" if action in ("quarantine", "flag", "Quarantined") else "info"
                report += f"<tr><td>{html.escape(str(d.get('file', 'N/A')))}</td><td>{html.escape(str(d.get('threat', '')))}</td><td class='{cls}'>{html.escape(str(action))}</td></tr>\n"
            report += "</table>\n"

        report += "</body></html>"

        try:
            Path(dest).write_text(report)
            QMessageBox.information(self, "Export", f"Report saved to:\n{dest}")
        except OSError as e:
            QMessageBox.warning(self, "Export Failed", f"Could not save report: {e}")


class ScanResultsDialog(QDialog):
    """Dialog showing scan results with per-row and bulk actions."""

    def __init__(self, results, quarantine_mgr, settings_mgr, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scan Results")
        self.setMinimumSize(800, 500)
        self.quarantine_mgr = quarantine_mgr
        self.settings_mgr = settings_mgr
        self.details = [d.copy() for d in results.get("details", [])]
        self._setup_ui(results)

    def _setup_ui(self, results):
        layout = QVBoxLayout(self)

        # Summary
        summary = QLabel(
            f"<b>Files scanned:</b> {results.get('files_scanned', 0)} &nbsp;&nbsp; "
            f"<b>Threats found:</b> {results.get('threats_found', 0)}"
        )
        summary.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent; font-size: 14px;")
        summary.setWordWrap(True)
        layout.addWidget(summary)

        # Bulk action buttons
        bulk_layout = QHBoxLayout()
        for label, action in [("Quarantine All", "quarantine"), ("Delete All", "delete")]:
            btn = QPushButton(label)
            btn.setMinimumHeight(36)
            btn.clicked.connect(lambda checked, a=action: self._apply_bulk(a))
            bulk_layout.addWidget(btn)

        ignore_once_btn = QPushButton("Ignore All (Once)")
        ignore_once_btn.setMinimumHeight(36)
        ignore_once_btn.clicked.connect(lambda: self._apply_bulk("ignore_once"))
        bulk_layout.addWidget(ignore_once_btn)

        ignore_forever_btn = QPushButton("Ignore All (Forever)")
        ignore_forever_btn.setMinimumHeight(36)
        ignore_forever_btn.setObjectName("dangerBtn")
        ignore_forever_btn.clicked.connect(lambda: self._apply_bulk("ignore_forever"))
        bulk_layout.addWidget(ignore_forever_btn)

        bulk_layout.addStretch()
        layout.addLayout(bulk_layout)

        # Results table
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["File", "Threat", "Action"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(1, 250)
        self.table.setColumnWidth(2, 150)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._table_context_menu)
        self.table.setStyleSheet("""
            QTableWidget {
                gridline-color: #333;
            }
            QTableWidget::item {
                padding: 8px;
            }
        """)
        self.table.setItemDelegate(QStyledItemDelegate())
        layout.addWidget(self.table)

        # Populate rows
        self.combos = []
        for row, item in enumerate(self.details):
            self.table.setRowCount(row + 1)
            file_item = QTableWidgetItem(item.get("file", ""))
            file_item.setToolTip(item.get("file", ""))
            self.table.setItem(row, 0, file_item)

            # Color-code threat by severity
            threat_text = item.get("threat", "")
            threat_item = QTableWidgetItem(threat_text)
            action = item.get("action", "")
            if action == "error":
                threat_item.setForeground(QColor("#FFB74D"))  # Orange — errors
            elif "ransom" in threat_text.lower():
                threat_item.setForeground(QColor(DANGER))    # Red — ransomware
            elif "rootkit" in threat_text.lower() or "backdoor" in threat_text.lower():
                threat_item.setForeground(QColor(DANGER))    # Red — rootkits/backdoors
            elif "miner" in threat_text.lower() or "xmrig" in threat_text.lower():
                threat_item.setForeground(QColor("#CE93D8")) # Purple — cryptominers
            elif "trojan" in threat_text.lower():
                threat_item.setForeground(QColor("#FFAB91")) # Light red — trojans
            elif "suspicious" in threat_text.lower():
                threat_item.setForeground(QColor("#FFF59D")) # Yellow — suspicious
            self.table.setItem(row, 1, threat_item)

            idx = 2 if item.get("action") == "error" else 0
            combo = _make_combo(["Quarantine", "Delete File", "Ignore Once", "Ignore Forever"], idx)
            self.table.setCellWidget(row, 2, combo)
            self.table.setRowHeight(row, 48)
            self.combos.append(combo)

        # Apply button
        self.apply_btn = QPushButton("Apply Actions")
        self.apply_btn.setMinimumHeight(40)
        self.apply_btn.clicked.connect(self._apply_actions)
        layout.addWidget(self.apply_btn)

    def _table_context_menu(self, pos):
        item = self.table.itemAt(pos)
        if not item:
            return
        menu = QMenu(self)
        copy_action = menu.addAction("Copy cell")
        copy_row_action = menu.addAction("Copy full row")
        # Add rule exemption option for YARA threats
        selected = self.table.currentRow()
        exempt_rule_action = None
        if selected >= 0 and selected < len(self.details):
            threat = self.details[selected].get("threat", "")
            if threat.startswith("YARA:"):
                rule_name = threat.replace("YARA:", "").strip()
                if rule_name:
                    exempt_rule_action = menu.addAction(f"Exempt YARA rule '{rule_name}'")
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if not chosen:
            return
        clipboard_text = ""
        if chosen == copy_action:
            clipboard_text = item.text()
        elif chosen == copy_row_action:
            vals = []
            for col in range(self.table.columnCount()):
                widget = self.table.cellWidget(selected, col)
                if isinstance(widget, QComboBox):
                    vals.append(widget.currentText())
                elif self.table.item(selected, col):
                    vals.append(self.table.item(selected, col).text())
                else:
                    vals.append("")
            clipboard_text = "  |  ".join(vals)
        elif exempt_rule_action and chosen == exempt_rule_action:
            from scanner import get_whitelist, save_whitelist
            whitelist = get_whitelist()
            if not any(isinstance(e, dict) and e.get("__type__") == "yara_rule"
                       and e.get("pattern") == rule_name for e in whitelist):
                whitelist.append({"__type__": "yara_rule", "pattern": rule_name})
                save_whitelist(whitelist)
            QMessageBox.information(
                self, "Rule Exempted",
                f"YARA rule '{rule_name}' will be ignored in all future scans.",
            )
            return
        if clipboard_text:
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText(clipboard_text)

    def _apply_bulk(self, action):
        mapping = {"quarantine": 0, "delete": 1, "ignore_once": 2, "ignore_forever": 3}
        idx = mapping.get(action, 2)
        for combo in self.combos:
            combo.setCurrentIndex(idx)

    def _apply_actions(self):
        applied = 0
        from scanner import _realpath
        whitelist = self.settings_mgr.get_whitelist() if self.settings_mgr else []
        for row, item in enumerate(self.details):
            combo = self.combos[row]
            choice = combo.currentText()
            filepath = item.get("file", "")
            threat = item.get("threat", "")

            if filepath == "N/A" or not filepath:
                item["_user_action"] = "skipped"
                continue

            if choice == "Quarantine":
                ok = self.quarantine_mgr.quarantine_file(filepath, threat)
                if ok:
                    log_quarantine_action("quarantine", filepath, "", threat)
                    item["_user_action"] = "Quarantined"
                    applied += 1
                else:
                    item["_user_action"] = "Quarantine failed"

            elif choice == "Delete File":
                # Path safety check: ensure the file path looks reasonable
                # (starts with /, contains no null bytes, isn't a system-critical path)
                if not filepath or not filepath.startswith("/"):
                    item["_user_action"] = "Delete skipped (invalid path)"
                    continue
                if filepath in ("/", "/etc", "/usr", "/bin", "/sbin", "/lib",
                                "/boot", "/dev", "/proc", "/sys", "/tmp"):
                    item["_user_action"] = "Delete skipped (system path)"
                    continue
                try:
                    os.remove(filepath)
                    item["_user_action"] = "Deleted"
                    applied += 1
                except OSError:
                    item["_user_action"] = "Delete failed"

            elif choice == "Ignore Once":
                item["_user_action"] = "Ignored (once)"

            elif choice == "Ignore Forever":
                # Check if this is a process scan result (format: "PID 1234: processname")
                import re as _re
                pid_match = _re.match(r"^PID\s+\d+:\s+(.+)$", filepath)
                if pid_match:
                    # Process result: exempt by process name (not PID)
                    process_name = pid_match.group(1).strip()
                    if not any(isinstance(e, dict) and e.get("__type__") == "process_name"
                               and e.get("name", "").lower() == process_name.lower() for e in whitelist):
                        whitelist.append({"__type__": "process_name", "name": process_name})
                    item["_user_action"] = "Ignored (forever)"
                else:
                    # File path exemption with realpath normalization
                    rp = _realpath(filepath)
                    exempt_path = rp if rp else filepath
                    if not any(isinstance(e, dict) and e.get("__type__") == "path"
                               and e.get("path") == exempt_path for e in whitelist):
                        whitelist.append({"__type__": "path", "path": exempt_path})
                    item["_user_action"] = "Ignored (forever)"

            combo.setEnabled(False)

        if whitelist:
            self.settings_mgr.set_whitelist(whitelist)

        QMessageBox.information(self, "Actions Applied", f"Applied actions to {applied} file(s).")
        self.apply_btn.setEnabled(False)
        self.done(1)

    def get_results(self):
        return self.details


class ScanTab(QWidget):
    """Detailed scan tab with progress and results table."""

    def __init__(self, scanner: Scanner, quarantine_mgr: QuarantineManager, settings_mgr: SettingsManager, parent=None):
        super().__init__(parent)
        self.scanner = scanner
        self.quarantine_mgr = quarantine_mgr
        self.settings_mgr = settings_mgr
        self.results = []
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header = QLabel("Scan")
        header.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        header.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent;")
        layout.addWidget(header)

        # Quick actions
        btn_layout = QGridLayout()
        btn_layout.setSpacing(8)
        scan_buttons = [
            ("Home Scan", "quick_home"),
            ("Full System", "full_system"),
            ("External", "external"),
            ("Custom", "custom"),
            ("Rootkit", "rootkit"),
            ("Processes", "processes"),
        ]
        self.scan_buttons = {}
        for idx, (label, scan_type) in enumerate(scan_buttons):
            btn = QPushButton(label)
            btn.setMinimumHeight(40)
            btn.clicked.connect(lambda checked, st=scan_type: self.start_scan(st))
            self.scan_buttons[scan_type] = btn
            row, col = divmod(idx, 3)
            btn_layout.addWidget(btn, row, col)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("dangerBtn")
        cancel_btn.setMinimumHeight(40)
        cancel_btn.clicked.connect(self.scanner.cancel_scan)
        btn_layout.addWidget(cancel_btn, 2, 0, 1, 3)
        layout.addLayout(btn_layout)

        # Progress
        progress_card = CardWidget("Progress")
        progress_layout = QVBoxLayout(progress_card)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_bar)
        self.file_label = QLabel("Ready")
        self.file_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        self.file_label.setWordWrap(True)
        progress_layout.addWidget(self.file_label)

        # ETA label (elapsed / estimated time)
        self.eta_label = QLabel("")
        self.eta_label.setFont(QFont("Segoe UI", 10))
        self.eta_label.setStyleSheet(
            f"color: {TEXT_SECONDARY}; background: transparent;"
        )
        self.eta_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        progress_layout.addWidget(self.eta_label)

        layout.addWidget(progress_card)

        # Results section
        results_row = QHBoxLayout()

        self.export_btn = QPushButton("Export Report as HTML")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._export_report)
        results_row.addWidget(self.export_btn)

        self.view_results_btn = QPushButton("Scan Results")
        self.view_results_btn.setEnabled(False)
        self.view_results_btn.setMinimumHeight(40)
        self.view_results_btn.clicked.connect(self._open_results)
        results_row.addWidget(self.view_results_btn)

        layout.addLayout(results_row)

        # Connect signals
        self.scanner.scan_progress.connect(self.on_progress)
        self.scanner.scan_file.connect(self.on_file)
        self.scanner.scan_finished.connect(self.on_scan_finished)
        self.scanner.scan_started.connect(self.on_scan_started)
        self.scanner.scan_error.connect(lambda msg: QMessageBox.warning(self, "Scan Error", msg))

        self._last_scan_results = None

        # Scan phase tracking
        self._scan_phase = "idle"  # idle, yara, clamav

    def start_scan(self, scan_type):
        if scan_type == "full_system" and os.geteuid() != 0:
            reply = QMessageBox.warning(
                self, "Limited Scan",
                "Full system scan works best with root privileges.\n"
                "Some files will be skipped.\n\nContinue anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.No:
                return
        self.results = []
        if scan_type == "custom":
            path = QFileDialog.getExistingDirectory(
                self, "Select Directory to Scan", "",
                QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontUseNativeDialog,
            )
            if not path:
                return
            self.scanner.start_scan(scan_type, custom_paths=[path])
        else:
            self.scanner.start_scan(scan_type)

    def on_scan_started(self):
        self.file_label.setText("Scanning...")
        self.progress_bar.setValue(0)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setFormat("%p%")
        for btn in self.scan_buttons.values():
            btn.setEnabled(False)

    def on_progress(self, pct):
        self.progress_bar.setValue(pct)

    def on_file(self, filename):
        # ClamAV phase starting
        if filename == "CLAM_START":
            self._scan_phase = "clamav"
            self.file_label.setText("ClamAV: Scanning...")
            return
        # Just show whatever the scanner sends — YARA progress or ClamAV file paths
        self.file_label.setText(filename)

    def on_scan_finished(self, results):
        self._scan_phase = "idle"
        self.file_label.setText("Scan complete")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.eta_label.setText("")
        for btn in self.scan_buttons.values():
            btn.setEnabled(True)
        self.results = results.get("details", [])
        self._last_scan_results = results
        self.export_btn.setEnabled(True)
        # Enable the results button if there are any details or any threats found
        has_content = bool(self.results) or results.get("threats_found", 0) > 0 or results.get("files_scanned", 0) > 0
        self.view_results_btn.setEnabled(has_content)

        # Log to history
        scan_type = getattr(self.scanner._worker, 'scan_type', 'unknown') if self.scanner._worker else 'unknown'
        log_scan(scan_type, results.get("files_scanned", 0), results.get("threats_found", 0), self.results)

        # Always open results dialog after a scan (even if no threats)
        dialog = ScanResultsDialog(results, self.quarantine_mgr, self.settings_mgr, self)
        dialog.setStyleSheet(STYLESHEET)
        dialog.exec()
        # Merge user actions back into results
        dialog_results = dialog.get_results()
        for i, d in enumerate(dialog_results):
            if "_user_action" in d:
                self.results[i]["_user_action"] = d["_user_action"]
        self._last_scan_results["details"] = self.results

        # Refresh quarantine tab if actions were applied
        if any("_user_action" in d and d["_user_action"] != "skipped" for d in self.results if isinstance(d, dict)):
            main_window = self.window()
            if hasattr(main_window, 'quarantine_tab'):
                main_window.quarantine_tab.refresh()

    def _open_results(self):
        """Open the scan results dialog."""
        if not self._last_scan_results or not self.results:
            QMessageBox.information(self, "Scan Results", "No scan results available.")
            return
        dialog = ScanResultsDialog(self._last_scan_results, self.quarantine_mgr, self.settings_mgr, self)
        dialog.setStyleSheet(STYLESHEET)
        dialog.exec()
        dialog_results = dialog.get_results()
        for i, d in enumerate(dialog_results):
            if "_user_action" in d:
                self.results[i]["_user_action"] = d["_user_action"]
        self._last_scan_results["details"] = self.results

        # Refresh quarantine tab if actions were applied
        if any("_user_action" in d and d["_user_action"] != "skipped" for d in self.results if isinstance(d, dict)):
            main_window = self.window()
            if hasattr(main_window, 'quarantine_tab'):
                main_window.quarantine_tab.refresh()

    def _export_report(self):
        if not self._last_scan_results:
            QMessageBox.information(self, "Export", "No scan results to export.")
            return
        results = self._last_scan_results
        dest = QFileDialog.getSaveFileName(
            self, "Export Scan Report", "scan_report.html", "HTML Files (*.html)",
            options=QFileDialog.Option.DontUseNativeDialog,
        )[0]
        if not dest:
            return

        report = f"""<!DOCTYPE html>
<html><head><title>Autobahn Defender Scan Report</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #121212; color: #E0E0E0; margin: 40px; }}
h1 {{ color: #2962FF; }} h2 {{ color: #4CAF50; }}
table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
th, td {{ border: 1px solid #2C2C2C; padding: 10px; text-align: left; }}
th {{ background: #1E1E1E; color: #E0E0E0; }}
tr:nth-child(even) {{ background: #1A1A1A; }}
</style></head><body>
<h1>Autobahn Defender Scan Report</h1>
<p><b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<p><b>Files scanned:</b> {results.get('files_scanned', 0)}</p>
<p><b>Threats found:</b> {results.get('threats_found', 0)}</p>
"""
        details = results.get("details", [])
        if details:
            report += "<h2>Details</h2><table><tr><th>File</th><th>Threat</th><th>Action Taken</th></tr>\n"
            for row_idx, d in enumerate(details):
                action_taken = d.get("_user_action", d.get("action", ""))
                report += f"<tr><td>{html.escape(str(d.get('file', 'N/A')))}</td><td>{html.escape(str(d.get('threat', '')))}</td><td>{html.escape(str(action_taken))}</td></tr>\n"
            report += "</table>\n"
        report += "</body></html>"
        try:
            Path(dest).write_text(report)
            QMessageBox.information(self, "Export", f"Report saved to:\n{dest}")
        except OSError as e:
            QMessageBox.warning(self, "Export Failed", f"Could not save report: {e}")


class QuarantineTab(QWidget):
    """Quarantine tab for managing quarantined files."""

    def __init__(self, quarantine_mgr: QuarantineManager, parent=None):
        super().__init__(parent)
        self.quarantine_mgr = quarantine_mgr
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header = QLabel("Quarantine")
        header.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        header.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent;")
        layout.addWidget(header)

        # Bulk actions
        bulk_layout = QHBoxLayout()
        restore_all_btn = QPushButton("Restore All")
        restore_all_btn.setObjectName("successBtn")
        restore_all_btn.clicked.connect(self.restore_all)
        bulk_layout.addWidget(restore_all_btn)

        delete_all_btn = QPushButton("Delete All")
        delete_all_btn.setObjectName("dangerBtn")
        delete_all_btn.clicked.connect(self.delete_all)
        bulk_layout.addWidget(delete_all_btn)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        bulk_layout.addWidget(refresh_btn)
        bulk_layout.addStretch()
        layout.addLayout(bulk_layout)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(
            ["Original Path", "Threat", "Date", "Action"]
        )
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(1, 250)
        self.table.setColumnWidth(2, 140)
        self.table.setColumnWidth(3, 150)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._table_context_menu)
        self.table.setStyleSheet("""
            QTableWidget {
                gridline-color: #333;
            }
            QTableWidget::item {
                padding: 8px;
            }
        """)
        self.table.setItemDelegate(QStyledItemDelegate())
        layout.addWidget(self.table)

        # Apply actions button
        self.apply_btn = QPushButton("Apply Actions")
        self.apply_btn.setMinimumHeight(36)
        self.apply_btn.setEnabled(False)
        self.apply_btn.clicked.connect(self._apply_actions)
        layout.addWidget(self.apply_btn)

        self.refresh()

    def refresh(self):
        items = self.quarantine_mgr.get_quarantined()
        self.table.setRowCount(len(items))
        self._quarantine_combos = []
        self._quarantine_items = items
        for row, entry in enumerate(items):
            path_item = QTableWidgetItem(entry.get("original_path", ""))
            path_item.setToolTip(entry.get("original_path", ""))
            self.table.setItem(row, 0, path_item)
            self.table.setItem(row, 1, QTableWidgetItem(entry.get("threat", "")))
            self.table.setItem(row, 2, QTableWidgetItem(entry.get("date", "")))

            combo = _make_combo(["Restore", "Delete", "Keep"], 0)
            self.table.setCellWidget(row, 3, combo)
            self.table.setRowHeight(row, 48)
            self._quarantine_combos.append(combo)

        if items:
            self.apply_btn.setEnabled(True)
        else:
            self.apply_btn.setEnabled(False)

    def restore_file(self, quarantine_name):
        ok, msg = self.quarantine_mgr.restore_file(quarantine_name)
        if not ok:
            QMessageBox.warning(self, "Restore Failed", msg)
        else:
            log_quarantine_action("restore", "", quarantine_name, "")
        self.refresh()

    def delete_file(self, quarantine_name):
        reply = QMessageBox.question(
            self, "Confirm Delete",
            "Permanently delete this file?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.quarantine_mgr.delete_file(quarantine_name)
            log_quarantine_action("delete", "", quarantine_name, "")
            self.refresh()

    def restore_all(self):
        self.quarantine_mgr.restore_all()
        log_quarantine_action("restore_all", "", "", "")
        self.refresh()

    def delete_all(self):
        reply = QMessageBox.question(
            self, "Confirm Delete All",
            "Permanently delete ALL quarantined files?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.quarantine_mgr.delete_all()
            log_quarantine_action("delete_all", "", "", "")
            self.refresh()

    def _apply_actions(self):
        if not self._quarantine_items:
            return
        restored = deleted = 0
        for row, entry in enumerate(self._quarantine_items):
            combo = self._quarantine_combos[row] if row < len(self._quarantine_combos) else None
            if not combo or not combo.isEnabled():
                continue
            choice = combo.currentText()
            qname = entry.get("quarantine_name", "")

            if choice == "Restore":
                ok, msg = self.quarantine_mgr.restore_file(qname)
                if ok:
                    restored += 1
                    log_quarantine_action("restore", "", qname, "")
                else:
                    QMessageBox.warning(self, "Restore Failed", msg)
            elif choice == "Delete":
                ok = self.quarantine_mgr.delete_file(qname)
                if ok:
                    deleted += 1
                    log_quarantine_action("delete", "", qname, "")
            # "Keep" does nothing

            combo.setEnabled(False)

        if restored or deleted:
            QMessageBox.information(self, "Actions Applied", f"Restored {restored}, Deleted {deleted}.")
        self.refresh()

    def _table_context_menu(self, pos):
        item = self.table.itemAt(pos)
        if not item:
            return
        menu = QMenu(self)
        copy_action = menu.addAction("Copy cell")
        copy_row_action = menu.addAction("Copy full row")
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if not chosen:
            return
        selected = self.table.currentRow()
        clipboard_text = ""
        if chosen == copy_action:
            clipboard_text = item.text()
        elif chosen == copy_row_action:
            vals = []
            for col in range(self.table.columnCount()):
                widget = self.table.cellWidget(selected, col)
                if isinstance(widget, QComboBox):
                    vals.append(widget.currentText())
                elif self.table.item(selected, col):
                    vals.append(self.table.item(selected, col).text())
                else:
                    vals.append("")
            clipboard_text = "  |  ".join(vals)
        if clipboard_text:
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText(clipboard_text)


class HistoryTab(QWidget):
    """History tab showing scan, quarantine, and audit logs."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header = QLabel("History")
        header.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        header.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent;")
        layout.addWidget(header)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        layout.addWidget(refresh_btn)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"background-color: {BG_DARK};")

        # Scan history
        self.scan_table = QTableWidget()
        self.scan_table.setColumnCount(4)
        self.scan_table.setHorizontalHeaderLabels(["Date", "Type", "Files", "Threats"])
        self.scan_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.scan_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.scan_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.scan_table.setItemDelegate(QStyledItemDelegate())
        self.tabs.addTab(self.scan_table, "Scan History")

        # Quarantine history
        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(4)
        self.quarantine_table.setHorizontalHeaderLabels(["Date", "Action", "Path", "Threat"])
        self.quarantine_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.quarantine_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.quarantine_table.setItemDelegate(QStyledItemDelegate())
        self.tabs.addTab(self.quarantine_table, "Quarantine History")

        # Audit history
        self.audit_table = QTableWidget()
        self.audit_table.setColumnCount(3)
        self.audit_table.setHorizontalHeaderLabels(["Date", "Type", "Findings"])
        self.audit_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.audit_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.audit_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.audit_table.setItemDelegate(QStyledItemDelegate())
        self.audit_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tabs.addTab(self.audit_table, "Audit History")

        layout.addWidget(self.tabs)
        self.refresh()

    def refresh(self):
        # Scan history
        scans = get_scan_history()
        self.scan_table.setRowCount(len(scans))
        for row, s in enumerate(scans):
            self.scan_table.setItem(row, 0, QTableWidgetItem(s.get("timestamp", "")[:16]))
            self.scan_table.setItem(row, 1, QTableWidgetItem(s.get("scan_type", "")))
            self.scan_table.setItem(row, 2, QTableWidgetItem(str(s.get("files_scanned", 0))))
            self.scan_table.setItem(row, 3, QTableWidgetItem(str(s.get("threats_found", 0))))

        # Quarantine history
        qh = get_quarantine_history()
        self.quarantine_table.setRowCount(len(qh))
        for row, q in enumerate(qh):
            self.quarantine_table.setItem(row, 0, QTableWidgetItem(q.get("timestamp", "")[:16]))
            self.quarantine_table.setItem(row, 1, QTableWidgetItem(q.get("action", "")))
            self.quarantine_table.setItem(row, 2, QTableWidgetItem(q.get("original_path", "")))
            self.quarantine_table.setItem(row, 3, QTableWidgetItem(q.get("threat", "")))

        # Audit history
        ah = get_audit_history()
        self.audit_table.setRowCount(len(ah))
        for row, a in enumerate(ah):
            self.audit_table.setItem(row, 0, QTableWidgetItem(a.get("timestamp", "")[:16]))
            self.audit_table.setItem(row, 1, QTableWidgetItem(a.get("audit_type", "")))
            findings = a.get("findings_json", "[]")
            try:
                count = len(json.loads(findings)) if findings else 0
            except (json.JSONDecodeError, TypeError):
                count = 0
            self.audit_table.setItem(row, 2, QTableWidgetItem(f"{count} finding(s)"))


class SettingsTab(QWidget):
    """Settings tab with monitoring, scheduling, YARA rules, and definitions."""

    def __init__(self, scanner: Scanner, settings_mgr: SettingsManager, parent=None):
        super().__init__(parent)
        self.scanner = scanner
        self.settings_mgr = settings_mgr
        self.updater = AppUpdater(self)
        self.setup_ui()

    def setup_ui(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget()
        content.setStyleSheet(f"background-color: {BG_DARK};")
        content.setSizePolicy(QSizePolicy.Policy.MinimumExpanding, QSizePolicy.Policy.Preferred)
        main_layout = QVBoxLayout(content)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(20)

        header = QLabel("Settings")
        header.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        header.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent;")
        main_layout.addWidget(header)

        # --- Real-time monitoring ---
        rt_card = CardWidget("Real-Time Monitoring")
        rt_layout = QVBoxLayout(rt_card)

        self.rt_check = QCheckBox("Enable real-time file monitoring")
        self.rt_check.setChecked(self.settings_mgr.is_realtime_enabled())
        self.rt_check.stateChanged.connect(
            lambda s: self.settings_mgr.set_realtime_enabled(s == Qt.CheckState.Checked.value)
        )
        rt_layout.addWidget(self.rt_check)

        rt_layout.addWidget(QLabel("Watch folders (up to 3):"))
        self.folder_edits = []
        folders = self.settings_mgr.get_watch_folders()
        for i in range(3):
            row = QHBoxLayout()
            edit = QLineEdit(folders[i] if i < len(folders) else "")
            edit.setPlaceholderText("Folder path...")
            edit.setMinimumWidth(120)
            btn = QPushButton("Browse")
            btn.clicked.connect(lambda checked, idx=i: self.browse_watch_folder(idx))
            row.addWidget(edit, 1)
            row.addWidget(btn)
            rt_layout.addLayout(row)
            self.folder_edits.append(edit)

        self.usb_check = QCheckBox("Auto-scan newly connected USB/removable drives")
        self.usb_check.setChecked(self.settings_mgr.is_auto_scan_usb())
        self.usb_check.stateChanged.connect(
            lambda s: self.settings_mgr.set_auto_scan_usb(s == Qt.CheckState.Checked.value)
        )
        rt_layout.addWidget(self.usb_check)
        main_layout.addWidget(rt_card)

        # --- Scheduled scans ---
        sched_card = CardWidget("Scheduled Scans")
        sched_layout = QVBoxLayout(sched_card)

        self.sched_check = QCheckBox("Enable scheduled scans")
        self.sched_check.setChecked(self.settings_mgr.is_schedule_enabled())
        self.sched_check.stateChanged.connect(
            lambda s: self.settings_mgr.set_schedule_enabled(s == Qt.CheckState.Checked.value)
        )
        sched_layout.addWidget(self.sched_check)

        interval_layout = QHBoxLayout()
        interval_layout.addWidget(QLabel("Frequency:"))
        self.interval_combo = QComboBox()
        self.interval_combo.addItems(["Every 12 hours", "Daily (24h)", "Every 5 days", "Every 15 days", "Every 30 days"])
        interval_map = {12: 0, 24: 1, 120: 2, 360: 3, 720: 4}
        saved = self.settings_mgr.get_scan_interval()
        self.interval_combo.setCurrentIndex(interval_map.get(saved, 1))
        self.interval_combo.currentIndexChanged.connect(self._on_interval_changed)
        interval_layout.addWidget(self.interval_combo, 1)
        sched_layout.addLayout(interval_layout)

        scan_type_layout = QHBoxLayout()
        scan_type_layout.addWidget(QLabel("Scan type:"))
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Home Directory", "Full System", "Custom Path"])
        type_map = {"quick_home": 0, "full_system": 1, "custom": 2}
        saved_type = self.settings_mgr.get_schedule_scan_type()
        self.scan_type_combo.setCurrentIndex(type_map.get(saved_type, 0))
        self.scan_type_combo.currentIndexChanged.connect(self._on_scan_type_changed)
        scan_type_layout.addWidget(self.scan_type_combo, 1)
        sched_layout.addLayout(scan_type_layout)

        sched_layout.addWidget(QLabel("Scan time (HH:MM):"))
        self.time_edit = QTimeEdit()
        self.time_edit.setDisplayFormat("HH:mm")
        from PyQt6.QtCore import QTime
        time_str = self.settings_mgr.get_scan_time()
        try:
            parts = time_str.split(":")
            self.time_edit.setTime(QTime(int(parts[0]), int(parts[1])))
        except (ValueError, IndexError):
            self.time_edit.setTime(QTime(2, 0))
        self.time_edit.timeChanged.connect(
            lambda t: self.settings_mgr.set_scan_time(t.toString("HH:mm"))
        )
        sched_layout.addWidget(self.time_edit)
        main_layout.addWidget(sched_card)

        # --- YARA rules ---
        yara_card = CardWidget("YARA Rules")
        yara_layout = QVBoxLayout(yara_card)

        yara_layout.addWidget(QLabel("Custom YARA rules (saved as custom.yar):"))
        self.yara_edit = QTextEdit()
        self.yara_edit.setMaximumHeight(200)
        self.yara_edit.setPlainText(self.settings_mgr.get_custom_yara_rules())
        self.yara_save_timer = QTimer()
        self.yara_save_timer.setSingleShot(True)
        self.yara_save_timer.setInterval(1000)
        self.yara_save_timer.timeout.connect(
            lambda: self.settings_mgr.set_custom_yara_rules(self.yara_edit.toPlainText())
        )
        self.yara_edit.textChanged.connect(self.yara_save_timer.start)
        yara_layout.addWidget(self.yara_edit)

        yara_btn_row = QHBoxLayout()
        yara_save_btn = QPushButton("Save Rules")
        yara_save_btn.clicked.connect(self._save_yara_rules)
        yara_btn_row.addWidget(yara_save_btn)

        yara_open_btn = QPushButton("Open Rules Folder")
        yara_open_btn.clicked.connect(self._open_yara_folder)
        yara_btn_row.addWidget(yara_open_btn)
        yara_layout.addLayout(yara_btn_row)

        self.yara_status = QLabel("")
        self.yara_status.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent; font-size: 11px;")
        yara_layout.addWidget(self.yara_status)

        # Separator
        yara_layout.addSpacing(8)
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {BORDER};")
        yara_layout.addWidget(sep)
        yara_layout.addSpacing(8)

        # Platform-specific rule toggles
        yara_layout.addWidget(QLabel("Platform-specific rule sets:"))
        yara_layout.addWidget(QLabel(
            "Linux rules are always enabled. Windows and macOS rules are opt-in "
            "for scanning files from those platforms (Wine/Proton, SMB mounts, external drives)."
        ))

        self.windows_malware_check = QCheckBox("Scan for Windows malware (PE files from Wine/Proton/SMB mounts)")
        self.windows_malware_check.setChecked(self.settings_mgr.is_scan_windows_malware())
        self.windows_malware_check.stateChanged.connect(
            lambda s: self.settings_mgr.set_scan_windows_malware(s == Qt.CheckState.Checked.value)
        )
        yara_layout.addWidget(self.windows_malware_check)

        self.macos_malware_check = QCheckBox("Scan for macOS malware (Mach-O files from external drives/SMB)")
        self.macos_malware_check.setChecked(self.settings_mgr.is_scan_macos_malware())
        self.macos_malware_check.stateChanged.connect(
            lambda s: self.settings_mgr.set_scan_macos_malware(s == Qt.CheckState.Checked.value)
        )
        yara_layout.addWidget(self.macos_malware_check)

        self.pup_check = QCheckBox("Scan for PUPs (Potentially Unwanted Programs — adware, bloatware, unwanted AV, etc.)")
        self.pup_check.setChecked(self.settings_mgr.is_scan_pup())
        self.pup_check.stateChanged.connect(
            lambda s: self.settings_mgr.set_scan_pup(s == Qt.CheckState.Checked.value)
        )
        yara_layout.addWidget(self.pup_check)

        # Separator
        yara_layout.addSpacing(8)
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setStyleSheet(f"color: {BORDER};")
        yara_layout.addWidget(sep2)
        yara_layout.addSpacing(8)

        # Auto-update toggle
        self.yara_auto_update_check = QCheckBox("Auto-update YARA rules from Codeberg")
        self.yara_auto_update_check.setChecked(self.settings_mgr.is_yara_auto_update())
        self.yara_auto_update_check.stateChanged.connect(
            lambda s: self.settings_mgr.set_yara_auto_update(s == Qt.CheckState.Checked.value)
        )
        yara_layout.addWidget(self.yara_auto_update_check)

        # YARA rules last updated
        from yara_updater import get_yara_last_updated
        self.yara_last_updated_label = QLabel(f"YARA rules last updated: {get_yara_last_updated()}")
        self.yara_last_updated_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent; font-size: 11px;")
        yara_layout.addWidget(self.yara_last_updated_label)

        main_layout.addWidget(yara_card)

        # --- Definitions ---
        defs_card = CardWidget("Virus Definitions")
        defs_layout = QVBoxLayout(defs_card)

        self.defs_status = QLabel("Checking definitions...")
        self.defs_status.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        defs_layout.addWidget(self.defs_status)

        self.defs_progress = QProgressBar()
        self.defs_progress.setRange(0, 100)
        self.defs_progress.setValue(0)
        self.defs_progress.setVisible(False)
        defs_layout.addWidget(self.defs_progress)

        self.defs_last_updated = QLabel("")
        self.defs_last_updated.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent; font-size: 11px;")
        defs_layout.addWidget(self.defs_last_updated)

        self.update_btn = QPushButton("Update Definitions Now")
        self.update_btn.clicked.connect(self.update_definitions)
        defs_layout.addWidget(self.update_btn)
        main_layout.addWidget(defs_card)

        # --- Ignore List (Whitelist) ---
        wl_card = CardWidget("Exemptions / Ignore List")
        wl_layout = QVBoxLayout(wl_card)

        wl_layout.addWidget(QLabel("Paths excluded from scans (click to remove):"))

        self.whitelist_list = QListWidget()
        self.whitelist_list.setMaximumHeight(180)
        self.whitelist_list.setStyleSheet(f"""
            QListWidget {{
                background-color: {BG_CARD};
                color: {TEXT_PRIMARY};
                border: 1px solid {BORDER};
                border-radius: 6px;
                padding: 4px;
                font-size: 12px;
            }}
            QListWidget::item {{
                padding: 6px 8px;
                border-bottom: 1px solid {BORDER};
            }}
            QListWidget::item:hover {{
                background-color: #2A2A2A;
            }}
        """)
        self.whitelist_list.itemClicked.connect(self._remove_whitelist_item)
        self._refresh_whitelist_list()
        wl_layout.addWidget(self.whitelist_list)

        wl_btn_row = QHBoxLayout()
        add_folder_btn = QPushButton("Add Folder")
        add_folder_btn.clicked.connect(self._add_whitelist_folder)
        wl_btn_row.addWidget(add_folder_btn)

        clear_exempt_btn = QPushButton("Clear All")
        clear_exempt_btn.setObjectName("dangerBtn")
        clear_exempt_btn.clicked.connect(self._clear_whitelist)
        wl_btn_row.addWidget(clear_exempt_btn)

        wl_btn_row.addStretch()
        wl_layout.addLayout(wl_btn_row)

        wl_hint = QLabel(
            "Tip: Use 'Ignore Forever' from scan results to add items here.\n"
            "YARA rule exemptions and file paths are shown with icons."
        )
        wl_hint.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent; font-size: 10px;")
        wl_layout.addWidget(wl_hint)
        main_layout.addWidget(wl_card)

        # --- Scan Options ---
        scan_card = CardWidget("Scan Options")
        scan_layout = QVBoxLayout(scan_card)

        # Scan engine selection
        engine_row = QHBoxLayout()
        engine_label = QLabel("Scan engine:")
        engine_label.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent;")
        engine_row.addWidget(engine_label)
        self.engine_combo = QComboBox()
        self.engine_combo.addItem("Both (ClamAV + YARA)", "both")
        self.engine_combo.addItem("ClamAV only", "clamav")
        self.engine_combo.addItem("YARA only", "yara")
        current_engine = self.settings_mgr.get_scan_engine()
        for i in range(self.engine_combo.count()):
            if self.engine_combo.itemData(i) == current_engine:
                self.engine_combo.setCurrentIndex(i)
                break
        self.engine_combo.currentIndexChanged.connect(
            lambda idx: self.settings_mgr.set_scan_engine(self.engine_combo.itemData(idx))
        )
        engine_row.addWidget(self.engine_combo)
        engine_row.addStretch()
        scan_layout.addLayout(engine_row)

        engine_hint = QLabel("Choose which scanning engine(s) to use. 'Both' gives maximum coverage.")
        engine_hint.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent; font-size: 11px;")
        engine_hint.setWordWrap(True)
        scan_layout.addWidget(engine_hint)

        self.archive_check = QCheckBox("Scan inside compressed/archived files (zip, tar, rar, 7z, etc.)")
        self.archive_check.setChecked(self.settings_mgr.is_scan_archives())
        self.archive_check.stateChanged.connect(
            lambda s: self.settings_mgr.set_scan_archives(s == Qt.CheckState.Checked.value)
        )
        scan_layout.addWidget(self.archive_check)

        self.hidden_check = QCheckBox("Scan hidden files and directories (dotfiles)")
        self.hidden_check.setChecked(self.settings_mgr.is_scan_hidden())
        self.hidden_check.stateChanged.connect(
            lambda s: self.settings_mgr.set_scan_hidden(s == Qt.CheckState.Checked.value)
        )
        scan_layout.addWidget(self.hidden_check)

        thread_row = QHBoxLayout()
        import os as _os
        max_cores = _os.cpu_count() or 1
        default_threads = max(1, max_cores // 2)
        thread_row.addWidget(QLabel("Parallel scan threads:"))
        self.thread_spin = QSpinBox()
        self.thread_spin.setMinimum(1)
        self.thread_spin.setMaximum(max_cores)
        self.thread_spin.setValue(self.settings_mgr.get_scan_threads())
        self.thread_spin.valueChanged.connect(self.settings_mgr.set_scan_threads)
        thread_row.addWidget(self.thread_spin)
        thread_hint = QLabel(f"({max_cores} thread{'s' if max_cores != 1 else ''} available — default: {default_threads} (half of CPU threads) — affects YARA + ClamAV parallel scanning)")
        thread_hint.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent; font-size: 11px;")
        thread_hint.setWordWrap(True)
        thread_row.addWidget(thread_hint)
        scan_layout.addLayout(thread_row)

        self.parallel_clamav_check = QCheckBox("Parallel ClamAV scanning (multiple clamscan processes on separate CPU cores)")
        self.parallel_clamav_check.setChecked(self.settings_mgr.is_parallel_clamav())
        self.parallel_clamav_check.stateChanged.connect(
            lambda s: self.settings_mgr.set_parallel_clamav(s == Qt.CheckState.Checked.value)
        )
        scan_layout.addWidget(self.parallel_clamav_check)

        parallel_hint = QLabel("When enabled, ClamAV runs multiple clamscan processes simultaneously — each on its own CPU core. This roughly doubles scan speed on multi-core systems. Uses more RAM (~500MB per process).")
        parallel_hint.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent; font-size: 11px;")
        parallel_hint.setWordWrap(True)
        scan_layout.addWidget(parallel_hint)

        main_layout.addWidget(scan_card)

        # --- Firewall ---
        fw_card = CardWidget("Firewall")
        fw_layout = QVBoxLayout(fw_card)

        fw_status = get_firewall_status()
        fw_type = fw_status.get("type")
        if fw_type:
            active = fw_status.get("active", False)
            status_text = f"Firewall: {fw_type} ({'Active' if active else 'Inactive'})"
            self.fw_status_label = QLabel(status_text)
        else:
            self.fw_status_label = QLabel("No firewall tool found (install ufw or firewalld)")

        self.fw_status_label.setWordWrap(True)
        self.fw_status_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        fw_layout.addWidget(self.fw_status_label)

        apply_fw_btn = QPushButton("Apply Recommended Secure Rules")
        apply_fw_btn.setObjectName("dangerBtn")
        apply_fw_btn.clicked.connect(self._apply_firewall_rules)
        fw_layout.addWidget(apply_fw_btn)

        self.fw_result_label = QLabel("")
        self.fw_result_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent; font-size: 11px;")
        self.fw_result_label.setWordWrap(True)
        fw_layout.addWidget(self.fw_result_label)
        main_layout.addWidget(fw_card)

        # --- Performance & Notifications ---
        perf_card = CardWidget("Performance & Notifications")
        perf_layout = QVBoxLayout(perf_card)

        self.perf_check = QCheckBox("Performance Mode (reduce CPU usage during scans)")
        self.perf_check.setChecked(self.settings_mgr.is_performance_mode())
        self.perf_check.stateChanged.connect(
            lambda s: self.settings_mgr.set_performance_mode(s == Qt.CheckState.Checked.value)
        )
        perf_layout.addWidget(self.perf_check)

        self.silent_check = QCheckBox("Silent Mode (only tray notifications for scheduled/auto scans)")
        self.silent_check.setChecked(self.settings_mgr.is_silent_mode())
        self.silent_check.stateChanged.connect(
            lambda s: self.settings_mgr.set_silent_mode(s == Qt.CheckState.Checked.value)
        )
        perf_layout.addWidget(self.silent_check)
        main_layout.addWidget(perf_card)

        # --- Auto-start ---
        auto_card = CardWidget("Auto-Start")
        auto_layout = QVBoxLayout(auto_card)

        self.autostart_check = QCheckBox("Start Autobahn Defender at login")
        self.autostart_check.setChecked(self.settings_mgr.is_autostart_enabled())
        self.autostart_check.stateChanged.connect(
            lambda s: self.settings_mgr.set_autostart_enabled(s == Qt.CheckState.Checked.value)
        )
        auto_layout.addWidget(self.autostart_check)

        self.minimized_check = QCheckBox("Start minimized to system tray")
        self.minimized_check.setChecked(self.settings_mgr.is_start_minimized())
        self.minimized_check.stateChanged.connect(
            lambda s: self.settings_mgr.set_start_minimized(s == Qt.CheckState.Checked.value)
        )
        auto_layout.addWidget(self.minimized_check)
        main_layout.addWidget(auto_card)

        # --- Updates ---
        update_card = CardWidget("Application Updates")
        update_layout = QVBoxLayout(update_card)

        self.update_status_label = QLabel(f"Current version: v{CURRENT_VERSION}")
        self.update_status_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        update_layout.addWidget(self.update_status_label)

        self.check_update_btn = QPushButton("Check for Updates")
        self.check_update_btn.clicked.connect(self._check_for_updates)
        update_layout.addWidget(self.check_update_btn)

        main_layout.addWidget(update_card)

        main_layout.addStretch()
        scroll.setWidget(content)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        self._check_definitions()

    def browse_watch_folder(self, index):
        path = QFileDialog.getExistingDirectory(
            self, "Select Watch Folder", "",
            QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontUseNativeDialog,
        )
        if path:
            if index < len(self.folder_edits):
                self.folder_edits[index].setText(path)
                self._save_watch_folders()

    def _save_watch_folders(self):
        folders = [edit.text() for edit in self.folder_edits if edit.text()]
        if not folders:
            folders = [str(Path.home() / "Downloads")]
        self.settings_mgr.set_watch_folders(folders)
        self.settings_mgr.set_watch_path(folders[0])

    def _on_interval_changed(self, index):
        hours_map = {0: 12, 1: 24, 2: 120, 3: 360, 4: 720}
        self.settings_mgr.set_scan_interval(hours_map.get(index, 24))

    def _on_scan_type_changed(self, index):
        type_map = {0: "quick_home", 1: "full_system", 2: "custom"}
        self.settings_mgr.set_schedule_scan_type(type_map.get(index, "quick_home"))

    def _check_definitions(self):
        from scanner import get_defs_last_updated
        cvd_files = list(DEFS_DIR.glob("*.cvd")) + list(DEFS_DIR.glob("*.cld"))
        system_defs = Path("/var/lib/clamav")
        sys_cvd = list(system_defs.glob("*.cvd")) + list(system_defs.glob("*.cld")) if system_defs.exists() else []
        if cvd_files:
            self.defs_status.setText(
                f"Local definitions: {len(cvd_files)} file(s)\n"
                f"Location: {DEFS_DIR}"
            )
        elif sys_cvd:
            self.defs_status.setText(
                f"No local definitions, but {len(sys_cvd)} system definition(s) found.\n"
                f"Click Update to copy them, or install clamav for freshclam."
            )
        else:
            self.defs_status.setText("No definitions found. Click Update to download or install ClamAV.")
        last = get_defs_last_updated()
        self.defs_last_updated.setText(f"Last updated: {last}")

    def update_definitions(self):
        # Disable button and create/show progress dialog
        self.update_btn.setEnabled(False)
        self._defs_dialog = DefsUpdateDialog(self.scanner, self)
        self._defs_dialog.setStyleSheet(STYLESHEET)
        self._defs_dialog.show()
        self.scanner.update_definitions()
        # Re-enable the button when the dialog finishes
        self._defs_dialog.finished.connect(
            lambda: self.update_btn.setEnabled(True)
        )
        self._defs_dialog.finished.connect(self._check_definitions)

    def _check_for_updates(self):
        """Manually check for updates."""
        self.check_update_btn.setEnabled(False)
        self.update_status_label.setText("Checking for updates...")
        self.update_status_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        from updater import UpdateCheckWorker
        self._update_worker = UpdateCheckWorker()
        self._update_worker.finished.connect(self._on_update_check_result)
        self._update_worker.start()

    def _on_update_check_result(self, result):
        """Handle update check result from Settings tab."""
        self.check_update_btn.setEnabled(True)
        if result.get("available"):
            version = result.get("version", "unknown")
            self.update_status_label.setText(f"Update available: v{version}")
            self.update_status_label.setStyleSheet(f"color: {SUCCESS}; background: transparent;")
            self.updater._on_check_result(result)
        else:
            self.update_status_label.setText(f"v{CURRENT_VERSION} — Up to date")
            self.update_status_label.setStyleSheet(f"color: {SUCCESS}; background: transparent;")
            QMessageBox.information(
                self, "No Updates Available",
                f"You are running the latest version (v{CURRENT_VERSION}).",
            )

    def _save_yara_rules(self):
        """Save the custom YARA rules text to custom.yar file."""
        content = self.yara_edit.toPlainText()
        RULES_DIR.mkdir(parents=True, exist_ok=True)
        custom_path = RULES_DIR / "custom.yar"
        try:
            custom_path.write_text(content)
            self.yara_status.setText(f"Rules saved to {custom_path}")
            self.yara_status.setStyleSheet(f"color: {SUCCESS}; background: transparent; font-size: 11px;")
        except OSError as e:
            self.yara_status.setText(f"Failed to save: {e}")
            self.yara_status.setStyleSheet(f"color: {DANGER}; background: transparent; font-size: 11px;")

    def _open_yara_folder(self):
        """Open the YARA rules directory in the system file manager."""
        RULES_DIR.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.Popen(["xdg-open", str(RULES_DIR)])
        except Exception:
            QMessageBox.information(self, "Rules Folder", f"YARA rules are stored at:\n{RULES_DIR}")

    def _add_whitelist_folder(self):
        path = QFileDialog.getExistingDirectory(
            self, "Select Folder to Whitelist", "",
            QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontUseNativeDialog,
        )
        if path:
            from scanner import get_whitelist, save_whitelist, _realpath
            rp = _realpath(path)
            exempt_path = rp if rp else path
            entries = get_whitelist()
            if not any(isinstance(e, dict) and e.get("__type__") == "path"
                       and e.get("path") == exempt_path for e in entries):
                entries.append({"__type__": "path", "path": exempt_path})
                save_whitelist(entries)
            self._refresh_whitelist_list()

    def _refresh_whitelist_list(self):
        """Refresh the whitelist list widget from saved data."""
        from scanner import get_whitelist
        self.whitelist_list.clear()
        entries = get_whitelist()
        if not entries:
            self.whitelist_list.addItem("(no exemptions set)")
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            t = entry.get("__type__", "unknown")
            if t == "path":
                icon = "  "  # folder icon
                text = entry.get("path", "")
            elif t == "yara_rule":
                icon = "  "  # rule icon
                text = f"YARA rule: {entry.get('pattern', '')}"
            elif t == "process_name":
                icon = "  "  # process icon
                text = f"Process: {entry.get('name', '')}"
            else:
                icon = "  "
                text = f"Unknown entry: {str(entry)[:60]}"
            self.whitelist_list.addItem(f"{icon} {text}")
            item = self.whitelist_list.item(self.whitelist_list.count() - 1)
            item.setData(256, repr(entry))  # store entry as serialized data

    def _remove_whitelist_item(self, item):
        """Remove a whitelist entry when clicked."""
        from scanner import get_whitelist, save_whitelist
        raw = item.data(256)
        if not raw:
            return
        try:
            import ast
            target = ast.literal_eval(raw)
        except (ValueError, SyntaxError):
            return
        entries = get_whitelist()
        filtered = [e for e in entries if e != target]
        if len(filtered) != len(entries):
            save_whitelist(filtered)
            self._refresh_whitelist_list()

    def _clear_whitelist(self):
        """Clear all whitelist entries."""
        from scanner import save_whitelist
        reply = QMessageBox.warning(
            self, "Clear Exemptions",
            "Remove ALL items from the ignore list? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            save_whitelist([])
            self._refresh_whitelist_list()

    def _apply_firewall_rules(self):
        fw_type = detect_firewall()
        if not fw_type:
            QMessageBox.warning(self, "Firewall", "No firewall tool found.\nInstall ufw or firewalld first.")
            return
        reply = QMessageBox.warning(
            self, "Apply Firewall Rules",
            f"This will apply recommended security rules using {fw_type}:\n\n"
            f"• Deny all incoming traffic\n"
            f"• Allow SSH (port 22)\n"
            f"• Allow loopback traffic\n"
            f"• Allow all outgoing traffic\n\n"
            f"Requires sudo privileges. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.fw_result_label.setText("Applying firewall rules...")
            self._fw_worker = FirewallApplyWorker(fw_type)
            self._fw_worker.finished.connect(self._on_fw_apply_finished)
            self._fw_worker.start()

    def _on_fw_apply_finished(self, ok, msg):
        if ok:
            self.fw_result_label.setStyleSheet(f"color: {SUCCESS}; background: transparent;")
            self.fw_result_label.setText("Firewall rules applied successfully.")
            # Refresh status
            status = get_firewall_status()
            fw_type = status.get("type", "")
            active = status.get("active", False)
            self.fw_status_label.setText(f"Firewall: {fw_type} ({'Active' if active else 'Inactive'})")
        else:
            self.fw_result_label.setStyleSheet(f"color: {DANGER}; background: transparent;")
            self.fw_result_label.setText(f"Failed to apply rules:\n{msg}")


class AboutTab(QWidget):
    """About tab showing banner, developer info, and system details."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def _get_private_ip(self):
        """Get the local/private IP address."""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return "Unavailable"

    def _fetch_public_ip(self):
        """Fetch public IP on demand and update the label."""
        ip = self._get_public_ip()
        current_text = self.info_label.text()
        new_text = current_text.replace("Click to fetch", ip)
        self.info_label.setText(new_text)

    def _get_public_ip(self):
        """Get the public IP address."""
        try:
            req = urllib.request.Request(
                "https://api.ipify.org?format=json",
                headers={"User-Agent": "AutobahnDefender/1.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                return data.get("ip", "Unavailable")
        except Exception:
            return "Unavailable"

    def setup_ui(self):
        # Wrap About tab in a scroll area so content is never cut off
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        content = QWidget()
        content.setStyleSheet(f"background-color: {BG_DARK};")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # App icon (instead of banner)
        icon_paths = [
            Path(__file__).parent / "icons" / "512.png",
            Path(__file__).parent / "512.png",
            Path(__file__).parent / "icons" / "256.png",
            Path(__file__).parent / "256.png",
        ]
        for icon_path in icon_paths:
            if icon_path.exists():
                pixmap = QPixmap(str(icon_path))
                if not pixmap.isNull():
                    scaled = pixmap.scaled(
                        128, 128,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                    icon_label = QLabel()
                    icon_label.setPixmap(scaled)
                    icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                    icon_label.setStyleSheet("background: transparent;")
                    layout.addWidget(icon_label)
                    break

        # App info
        title = QLabel("Autobahn Defender")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setWordWrap(True)
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent;")
        layout.addWidget(title)

        version = QLabel(f"v{CURRENT_VERSION}")
        version.setFont(QFont("Segoe UI", 13))
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version.setWordWrap(True)
        version.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        layout.addWidget(version)

        dev = QLabel("Developed by Donavin K. Schlosser\nDigital Autobahn")
        dev.setFont(QFont("Segoe UI", 12))
        dev.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dev.setWordWrap(True)
        dev.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        layout.addWidget(dev)

        license_label = QLabel("Licensed under the MIT License")
        license_label.setFont(QFont("Segoe UI", 10))
        license_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        license_label.setWordWrap(True)
        license_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        layout.addWidget(license_label)

        website_label = QLabel(
            '<a href="https://codeberg.org/donavinschlosser/autobahn-defender" '
            f'style="color: {ACCENT};">codeberg.org/donavinschlosser/autobahn-defender</a>'
        )
        website_label.setFont(QFont("Segoe UI", 10))
        website_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        website_label.setStyleSheet(f"background: transparent;")
        website_label.setOpenExternalLinks(False)
        website_label.linkActivated.connect(self._open_link)
        layout.addWidget(website_label)

        # Check for updates button
        self.about_updater = AppUpdater(self)
        self.about_update_btn = QPushButton("Check for Updates")
        self.about_update_btn.setFixedWidth(200)
        self.about_update_btn.clicked.connect(self._check_updates_about)
        layout.addWidget(self.about_update_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        # System details card
        sys_card = CardWidget("System Information")
        sys_layout = QVBoxLayout(sys_card)

        import platform
        try:
            distro_name = "Unknown"
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("NAME="):
                        distro_name = line.split("=", 1)[1].strip('"')
                        break
        except OSError:
            distro_name = "Unknown"

        kernel = platform.release()
        arch = platform.machine()
        import socket
        hostname = socket.gethostname()
        private_ip = self._get_private_ip()

        info_text = (
            f"Distribution: {distro_name}\n"
            f"Kernel: {kernel}\n"
            f"Architecture: {arch}\n"
            f"Hostname: {hostname}\n"
            f"Private IP: {private_ip}\n"
            f"Public IP: Click to fetch"
        )
        self.info_label = QLabel(info_text)
        self.info_label.setFont(QFont("Segoe UI", 11))
        self.info_label.setWordWrap(True)
        self.info_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.info_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        sys_layout.addWidget(self.info_label)

        public_ip_btn = QPushButton("Show Public IP")
        public_ip_btn.setFixedWidth(160)
        public_ip_btn.clicked.connect(self._fetch_public_ip)
        sys_layout.addWidget(public_ip_btn)
        layout.addWidget(sys_card)

        # Dependencies card
        deps_card = CardWidget("Dependencies")
        deps_layout = QVBoxLayout(deps_card)

        clamscan = find_clamscan()
        yara_bin = find_yara()
        freshclam_path = shutil.which("freshclam")

        deps = []
        if clamscan:
            try:
                ver = subprocess.run(
                    [clamscan, "--version"], capture_output=True, text=True, timeout=5
                )
                ver_str = ver.stdout.strip().split("\n")[0] if ver.stdout else "installed"
                deps.append(f"ClamAV: {ver_str}")
            except Exception:
                deps.append(f"ClamAV: installed ({clamscan})")
        else:
            deps.append("ClamAV: Not installed")

        if yara_bin:
            try:
                ver = subprocess.run(
                    [yara_bin, "--version"], capture_output=True, text=True, timeout=5
                )
                ver_str = ver.stdout.strip().split("\n")[0] if ver.stdout else "installed"
                deps.append(f"YARA: {ver_str}")
            except Exception:
                deps.append(f"YARA: installed ({yara_bin})")
        else:
            deps.append("YARA: Not installed")

        if freshclam_path:
            deps.append(f"freshclam: installed ({freshclam_path})")
        else:
            deps.append("freshclam: Not installed")

        try:
            import psutil
            deps.append(f"psutil: installed ({psutil.__version__})")
        except ImportError:
            deps.append("psutil: Not installed (for process scanning)")

        deps_text = "\n".join(deps)
        deps_label = QLabel(deps_text)
        deps_label.setFont(QFont("Segoe UI", 11))
        deps_label.setWordWrap(True)
        deps_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        deps_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        deps_layout.addWidget(deps_label)

        # Install button for missing dependencies
        if not clamscan or not yara_bin:
            install_btn = QPushButton("Install Missing Dependencies")
            install_btn.clicked.connect(self._install_deps)
            deps_layout.addWidget(install_btn)
        else:
            all_good = QLabel("All core dependencies are installed.")
            all_good.setWordWrap(True)
            all_good.setStyleSheet(f"color: {SUCCESS}; background: transparent; font-weight: bold;")
            deps_layout.addWidget(all_good)

        layout.addWidget(deps_card)

        # ── Uninstall button ──
        uninstall_btn = QPushButton("Uninstall Autobahn Defender")
        uninstall_btn.setFixedWidth(280)
        uninstall_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {DANGER};
                color: white;
                border: 1px solid #B5535D;
                border-radius: 6px;
                padding: 8px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #D55E6A;
            }}
        """)
        uninstall_btn.clicked.connect(self._uninstall_app)
        layout.addWidget(uninstall_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addStretch()

        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    def _check_updates_about(self):
        """Check for updates from the About tab."""
        self.about_update_btn.setEnabled(False)
        from updater import UpdateCheckWorker
        self._about_update_worker = UpdateCheckWorker()
        self._about_update_worker.finished.connect(self._on_about_update_result)
        self._about_update_worker.start()

    def _on_about_update_result(self, result):
        """Handle update check result from About tab."""
        self.about_update_btn.setEnabled(True)
        if result.get("available"):
            self.about_updater._on_check_result(result)
        else:
            QMessageBox.information(
                self, "No Updates Available",
                f"You are running the latest version (v{CURRENT_VERSION}).",
            )

    @staticmethod
    def _open_link(url):
        """Open a URL in the system's default browser using webbrowser."""
        import webbrowser
        webbrowser.open(url)

    def _install_deps(self):
        """Detect the distro and offer to install missing dependencies."""
        from scanner import find_freshclam
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
        has_sudo = True
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
                # Add clamav if missing, or clamav-freshclam specifically if only freshclam is missing
                if not find_clamscan():
                    cmds.append("clamav")
                if not find_freshclam():
                    cmds.append("clamav-freshclam")
            if not find_yara():
                cmds.append("yara")
            cmds.append("python3-psutil")
            if cmds:
                # Clean up any broken dpkg state first, then update package cache
                # and install. The dpkg --configure -a + apt-get --fix-broken
                # handles the "unmet dependencies / try apt --fix-broken install"
                # error that happens on fresh systems or after interrupted installs.
                commands = ["sudo", "bash", "-c",
                    "dpkg --configure -a; apt-get --fix-broken install -y; apt-get update && apt-get install -y " + " ".join(cmds) + " && apt-get install -f -y"]
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
        else:
            cmds = []
            if not find_clamscan():
                cmds.append("clamav")
            if not find_yara():
                cmds.append("yara")
            cmds.append("python3-psutil")
            QMessageBox.information(
                self, "Install Dependencies",
                f"Could not detect your package manager.\\n\\n"
                f"Please install manually: sudo apt-get install {' '.join(cmds)}",
            )
            return

        if not commands:
            return

        # pkexec is the preferred way to elevate on most modern distros
        cmd_str = " ".join(commands)
        has_sudo = commands[0] == "sudo"
        reply = QMessageBox.question(
            self, "Install Dependencies",
            f"Install the following packages?\n\n  {cmd_str}\n\n"
            f"This will require sudo privileges.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            # Prefer pkexec with real-time progress dialog
            pkexec = shutil.which("pkexec")
            if pkexec:
                # Strip sudo from install command (pkexec already runs as root)
                install_cmd = commands[1:] if has_sudo else commands
                dialog = InstallProgressDialog(
                    "Installing Dependencies",
                    install_cmd,
                    self,
                )
                dialog.exec()
                # Refresh the About tab to reflect new dependency state
                self._refresh_about_tab()
                return
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
                    QMessageBox.information(
                        self, "Installing",
                        f"Installing in terminal...\n\nCommand: {cmd_str}\n\n"
                        f"Please complete the installation in the terminal window.",
                    )
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Failed to open terminal: {e}")
            else:
                QMessageBox.information(
                    self, "Install Dependencies",
                    f"No terminal emulator found.\n\nPlease run manually:\n  {cmd_str}",
                )

    def _uninstall_app(self):
        """Completely uninstall Autobahn Defender and all its data."""
        import sys

        # Build list of everything that will be removed
        app_dir = Path.home() / ".autobahn"
        autostart_file = Path.home() / ".config" / "autostart" / "com.digitalautobahn.AutobahnDefender.desktop"

        items = []
        if app_dir.exists():
            items.append(f"  \u2022 Application data: {app_dir}")
        if autostart_file.exists():
            items.append(f"  \u2022 Autostart entry: {autostart_file}")

        # Detect what was installed via package manager
        pkgs_found = []
        try:
            result = subprocess.run(
                ["dpkg", "-s", "autobahn-defender"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                pkgs_found.append(f"  \u2022 DEB package: autobahn-defender")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        try:
            result = subprocess.run(
                ["pacman", "-Q", "autobahn-defender"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                pkgs_found.append(f"  \u2022 Arch package: autobahn-defender")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check if running as AppImage
        is_appimage = "APPIMAGE" in os.environ
        if is_appimage:
            items.append(f"  \u2022 AppImage: {os.environ.get('APPIMAGE', 'unknown')}")

        if not items and not pkgs_found:
            QMessageBox.information(
                self, "Nothing to Uninstall",
                "No Autobahn Defender installation or data was found on this system.",
            )
            return

        summary = "\n".join(items) if items else "No app data found."
        pkg_summary = "\n".join(pkgs_found) if pkgs_found else ""

        msg = "This will completely remove Autobahn Defender from your system:\n\n"

        if pkg_summary:
            msg += "Installed packages:\n" + pkg_summary + "\n\n"
        msg += "To be removed:\n" + summary + "\n\n"
        msg += "This action CANNOT be undone. Continue?"

        reply = QMessageBox.question(
            self, "Uninstall Autobahn Defender",
            msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        errors = []

        # Step 1: Remove autostart entry
        try:
            autostart_file.unlink(missing_ok=True)
        except OSError as e:
            errors.append(f"Failed to remove autostart entry: {e}")

        # Step 2: Remove ALL application data (~/.autobahn/ — definitions, quarantine, history, settings)
        if app_dir.exists():
            try:
                shutil.rmtree(str(app_dir), ignore_errors=False)
            except OSError as e:
                errors.append(f"Failed to remove app data: {e}")

        # Step 3: Remove package if installed
        removed_pkg = False
        for pkg_text in pkgs_found:
            try:
                if "DEB package" in pkg_text:
                    subprocess.run(
                        ["pkexec", "apt-get", "remove", "--purge", "-y", "autobahn-defender"],
                        timeout=60,
                    )
                    removed_pkg = True
                elif "Arch package" in pkg_text:
                    subprocess.run(
                        ["pkexec", "pacman", "-R", "--noconfirm", "autobahn-defender"],
                        timeout=60,
                    )
                    removed_pkg = True
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                errors.append(f"Failed to remove package: {e}")

        # Step 4: AppImage — just note that the file must be deleted manually
        appimage_notice = ""
        if is_appimage:
            appimage_path = os.environ.get("APPIMAGE", "")
            appimage_notice = (
                f"\n\nThe AppImage file must be deleted manually:\n"
                f"  rm \"{appimage_path}\"\n"
                f"The application will now exit."
            )

        if errors:
            QMessageBox.warning(
                self, "Uninstall - Warnings",
                f"Uninstall completed with some issues:\n\n" + "\n".join(errors) + appimage_notice,
            )
        else:
            QMessageBox.information(
                self, "Uninstall Complete",
                f"Autobahn Defender has been fully removed from your system.{appimage_notice}",
            )

        # Force quit the app after uninstall
        QTimer.singleShot(500, sys.exit)

    def _refresh_about_tab(self):
        """Rebuild the About tab UI to reflect current dependency state."""
        scroll = self.findChild(QScrollArea)
        if scroll:
            old_content = scroll.widget()
            scroll.takeWidget()
            if old_content:
                old_content.deleteLater()
        old_layout = self.layout()
        if old_layout:
            for i in range(old_layout.count()):
                w = old_layout.itemAt(i).widget()
                if w:
                    w.deleteLater()
        self.setup_ui()
