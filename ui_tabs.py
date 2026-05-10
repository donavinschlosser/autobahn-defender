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
    QDialogButtonBox, QPlainTextEdit,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap, QFont, QColor

from scanner import Scanner, find_clamscan, find_yara, DEFS_DIR, get_whitelist, save_whitelist
from quarantine import QuarantineManager
from settings import SettingsManager
from updater import AppUpdater, CURRENT_VERSION, YARA_RULES_SOURCES, YaraRulesDownloadWorker
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
        for btn in box.findChildren(QPushButton):
            if btn.text() == "Show Details":
                btn.click()
                break
    return box


# --- Theme colors ---
BG_DARK = "#121212"
BG_CARD = "#1E1E1E"
BORDER = "#2C2C2C"
ACCENT = "#2962FF"
ACCENT_HOVER = "#1E53E0"
TEXT_PRIMARY = "#E0E0E0"
TEXT_SECONDARY = "#A0A0A0"
DANGER = "#CF6679"
SUCCESS = "#4CAF50"
SIDEBAR_HOVER = "#1A1A2E"

STYLESHEET = f"""
    QWidget {{ background-color: {BG_DARK}; color: {TEXT_PRIMARY}; }}
    QLabel {{ color: {TEXT_PRIMARY}; background: transparent; }}
    QPushButton {{
        background-color: {ACCENT};
        color: white;
        border: none;
        border-radius: 6px;
        padding: 10px 20px;
        font-size: 13px;
        font-weight: bold;
    }}
    QPushButton:hover {{ background-color: {ACCENT_HOVER}; }}
    QPushButton:pressed {{ background-color: #0D47A1; }}
    QPushButton:disabled {{ background-color: #455A64; color: #888; }}
    QPushButton#dangerBtn {{
        background-color: {DANGER};
    }}
    QPushButton#dangerBtn:hover {{ background-color: #B5506A; }}
    QPushButton#successBtn {{
        background-color: {SUCCESS};
    }}
    QPushButton#successBtn:hover {{ background-color: #3D8B40; }}
    QGroupBox {{
        background-color: {BG_CARD};
        border: 1px solid {BORDER};
        border-radius: 8px;
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
        border-radius: 8px;
        gridline-color: {BORDER};
        color: {TEXT_PRIMARY};
    }}
    QTableWidget::item {{ padding: 8px; }}
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
        border-radius: 6px;
        padding: 6px 12px;
        color: {TEXT_PRIMARY};
        min-height: 28px;
    }}
    QComboBox:hover {{
        border-color: {ACCENT};
    }}
    QComboBox::drop-down {{
        border: none;
        width: 24px;
    }}
    QComboBox::down-arrow {{
        image: none;
        border-left: 5px solid transparent;
        border-right: 5px solid transparent;
        border-top: 6px solid {TEXT_SECONDARY};
        margin-right: 6px;
    }}
    QComboBox QAbstractItemView {{
        background-color: {BG_CARD};
        border: 1px solid {BORDER};
        border-radius: 6px;
        color: {TEXT_PRIMARY};
        selection-background-color: {ACCENT};
        selection-color: white;
        outline: none;
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

        btn_grid = QGridLayout()
        btn_grid.setSpacing(10)

        scan_buttons = [
            ("Home Scan", "quick_home"),
            ("Full System", "full_system"),
            ("External Drives", "external"),
            ("Custom Scan", "custom"),
            ("Rootkit Scan", "rootkit"),
            ("Process Scan", "processes"),
        ]

        self.scan_buttons = {}
        for idx, (label, scan_type) in enumerate(scan_buttons):
            btn = QPushButton(label)
            btn.setMinimumHeight(44)
            btn.setMinimumWidth(140)
            btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            btn.clicked.connect(lambda checked, st=scan_type: self.start_scan(st))
            self.scan_buttons[scan_type] = btn
            row, col = divmod(idx, 3)
            btn_grid.addWidget(btn, row, col)

        actions_layout.addLayout(btn_grid)

        # System tools row
        tools_row = QHBoxLayout()
        tools_row.setSpacing(10)

        self.kernel_btn = QPushButton("Kernel Modules")
        self.kernel_btn.setMinimumWidth(140)
        self.kernel_btn.clicked.connect(self._run_kernel_check)
        tools_row.addWidget(self.kernel_btn)

        self.hardening_btn = QPushButton("System Audit")
        self.hardening_btn.setMinimumWidth(140)
        self.hardening_btn.clicked.connect(self._run_hardening_audit)
        tools_row.addWidget(self.hardening_btn)

        actions_layout.addLayout(tools_row)
        layout.addWidget(actions_card)

        # Stats card
        stats_card = CardWidget("Last Scan Results")
        stats_layout = QVBoxLayout(stats_card)
        self.stats_label = QLabel("No scan data available")
        self.stats_label.setFont(QFont("Segoe UI", 11))
        self.stats_label.setWordWrap(True)
        self.stats_label.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        stats_layout.addWidget(self.stats_label)
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

    def on_scan_started(self):
        self.status_label.setText("Scanning...")
        self.progress_bar.setValue(0)
        for btn in self.scan_buttons.values():
            btn.setEnabled(False)

    def on_progress(self, pct):
        self.progress_bar.setValue(pct)

    def on_file(self, filename):
        self.current_file_label.setText(f"Scanning: {filename}")

    def on_scan_finished(self, results):
        self.status_label.setText("Scan complete")
        self.progress_bar.setValue(100)
        self.current_file_label.setText("")
        for btn in self.scan_buttons.values():
            btn.setEnabled(True)
        files = results.get("files_scanned", 0)
        threats = results.get("threats_found", 0)
        self.stats_label.setText(
            f"Files scanned: {files}  |  Threats found: {threats}"
        )
        self._last_scan_results = results
        self.export_btn.setEnabled(True)

        # Log to history
        scan_type = getattr(self.scanner._worker, 'scan_type', 'unknown') if self.scanner._worker else 'unknown'
        log_scan(scan_type, files, threats, results.get("details", []))

    def _refresh_defs_status(self):
        from scanner import get_defs_last_updated
        last = get_defs_last_updated()
        self.defs_last_updated_label.setText(f"Definitions last updated: {last}")

    def _update_definitions(self):
        self.update_defs_btn.setEnabled(False)
        self.status_label.setText("Updating definitions...")
        self.scanner.defs_update_finished.connect(self._on_defs_update_finished)
        self.scanner.update_definitions()

    def _on_defs_update_finished(self, ok, msg):
        self.update_defs_btn.setEnabled(True)
        if ok:
            self.status_label.setText("Definitions updated successfully")
        else:
            self.status_label.setText(f"Definition update failed")
        self._refresh_defs_status()

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
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(1, 200)
        self.table.setColumnWidth(2, 200)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._table_context_menu)
        layout.addWidget(self.table)

        # Populate rows
        self.combos = []
        for row, item in enumerate(self.details):
            self.table.setRowCount(row + 1)
            file_item = QTableWidgetItem(item.get("file", ""))
            file_item.setToolTip(item.get("file", ""))
            self.table.setItem(row, 0, file_item)
            self.table.setItem(row, 1, QTableWidgetItem(item.get("threat", "")))
            combo = QComboBox()
            combo.addItems(["Quarantine", "Delete File", "Ignore Once", "Ignore Forever"])
            if item.get("action") == "error":
                combo.setCurrentIndex(2)
            self.table.setCellWidget(row, 2, combo)
            self.table.setRowHeight(row, max(self.table.rowHeight(row), 36))
            self.combos.append(combo)

    def _table_context_menu(self, pos):
        item = self.table.itemAt(pos)
        if not item:
            return
        menu = self.table.createStandardContextMenu()
        menu.clear()
        copy_action = menu.addAction("Copy cell")
        copy_row_action = menu.addAction("Copy full row")
        if menu.exec(self.table.viewport().mapToGlobal(pos)):
            selected = self.table.currentRow()
            clipboard_text = ""
            if menu.activeAction() == copy_action:
                clipboard_text = item.text()
            elif menu.activeAction() == copy_row_action:
                vals = []
                for col in range(self.table.columnCount()):
                    widget = self.table.cellWidget(selected, col)
                    vals.append(widget.currentText() if isinstance(widget, QComboBox) else self.table.item(selected, col).text() if self.table.item(selected, col) else "")
                clipboard_text = "  |  ".join(vals)
            if clipboard_text:
                from PyQt6.QtWidgets import QApplication
                QApplication.clipboard().setText(clipboard_text)

        # Apply button
        self.apply_btn = QPushButton("Apply Actions")
        self.apply_btn.setMinimumHeight(40)
        self.apply_btn.clicked.connect(self._apply_actions)
        layout.addWidget(self.apply_btn)

    def _apply_bulk(self, action):
        mapping = {"quarantine": 0, "delete": 1, "ignore_once": 2, "ignore_forever": 3}
        idx = mapping.get(action, 2)
        for combo in self.combos:
            combo.setCurrentIndex(idx)

    def _apply_actions(self):
        applied = 0
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
                try:
                    os.remove(filepath)
                    item["_user_action"] = "Deleted"
                    applied += 1
                except OSError:
                    item["_user_action"] = "Delete failed"

            elif choice == "Ignore Once":
                item["_user_action"] = "Ignored (once)"

            elif choice == "Ignore Forever":
                if filepath not in whitelist:
                    whitelist.append(filepath)
                item["_user_action"] = "Ignored (forever)"

            combo.setEnabled(False)

        if whitelist:
            self.settings_mgr.set_whitelist(whitelist)

        QMessageBox.information(self, "Actions Applied", f"Applied actions to {applied} file(s).")
        self.apply_btn.setEnabled(False)

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
        layout.addWidget(progress_card)

        # Results table
        results_card = CardWidget("Results")
        results_layout = QVBoxLayout(results_card)
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["File", "Threat", "Action"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(1, 200)
        self.table.setColumnWidth(2, 200)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._table_context_menu)
        results_layout.addWidget(self.table)

        # Export button
        self.export_btn = QPushButton("Export Report as HTML")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._export_report)
        results_layout.addWidget(self.export_btn)

        layout.addWidget(results_card)

        # Connect signals
        self.scanner.scan_progress.connect(self.progress_bar.setValue)
        self.scanner.scan_file.connect(lambda f: self.file_label.setText(f"Scanning: {f}"))
        self.scanner.scan_finished.connect(self.on_scan_finished)
        self.scanner.scan_started.connect(self.on_scan_started)
        self.scanner.scan_error.connect(lambda msg: QMessageBox.warning(self, "Scan Error", msg))

        self._last_scan_results = None

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
        self.table.setRowCount(0)
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
        for btn in self.scan_buttons.values():
            btn.setEnabled(False)

    def on_scan_finished(self, results):
        self.file_label.setText("Scan complete")
        self.progress_bar.setValue(100)
        for btn in self.scan_buttons.values():
            btn.setEnabled(True)
        self.results = results.get("details", [])
        self._last_scan_results = results
        self.export_btn.setEnabled(True)

        # Populate the embedded table with dropdowns
        self.table.setRowCount(len(self.results))
        self._combos = []
        for row, item in enumerate(self.results):
            file_item = QTableWidgetItem(item.get("file", ""))
            file_item.setToolTip(item.get("file", ""))
            self.table.setItem(row, 0, file_item)
            self.table.setItem(row, 1, QTableWidgetItem(item.get("threat", "")))
            combo = QComboBox()
            combo.addItems(["Quarantine", "Delete File", "Ignore Once", "Ignore Forever"])
            if item.get("action") == "error":
                combo.setCurrentIndex(2)
            self.table.setCellWidget(row, 2, combo)
            self.table.setRowHeight(row, max(self.table.rowHeight(row), 36))
            self._combos.append(combo)

        # Log to history
        scan_type = getattr(self.scanner._worker, 'scan_type', 'unknown') if self.scanner._worker else 'unknown'
        log_scan(scan_type, results.get("files_scanned", 0), results.get("threats_found", 0), self.results)

        # Open results dialog
        if self.results:
            dialog = ScanResultsDialog(results, self.quarantine_mgr, self.settings_mgr, self)
            dialog.setStyleSheet(STYLESHEET)
            dialog.exec()
            # Merge user actions back into results
            dialog_results = dialog.get_results()
            for i, d in enumerate(dialog_results):
                if "_user_action" in d:
                    self.results[i]["_user_action"] = d["_user_action"]
            self._last_scan_results["details"] = self.results

    def quarantine_row(self, row):
        if row < len(self.results):
            filepath = self.results[row].get("file", "")
            threat = self.results[row].get("threat", "")
            if filepath and filepath != "N/A":
                ok = self.quarantine_mgr.quarantine_file(filepath, threat)
                if ok:
                    combo = self.table.cellWidget(row, 2)
                    if combo:
                        combo.setCurrentIndex(0)
                        combo.setEnabled(False)
                    log_quarantine_action("quarantine", filepath, "", threat)

    def _table_context_menu(self, pos):
        item = self.table.itemAt(pos)
        if not item:
            return
        menu = self.table.createStandardContextMenu()
        menu.clear()
        copy_action = menu.addAction("Copy cell")
        copy_row_action = menu.addAction("Copy full row")
        if menu.exec(self.table.viewport().mapToGlobal(pos)):
            selected = self.table.currentRow()
            clipboard_text = ""
            if menu.activeAction() == copy_action:
                clipboard_text = item.text()
            elif menu.activeAction() == copy_row_action:
                vals = []
                for col in range(self.table.columnCount()):
                    widget = self.table.cellWidget(selected, col)
                    vals.append(widget.currentText() if isinstance(widget, QComboBox) else self.table.item(selected, col).text() if self.table.item(selected, col) else "")
                clipboard_text = "  |  ".join(vals)
            if clipboard_text:
                from PyQt6.QtWidgets import QApplication
                QApplication.clipboard().setText(clipboard_text)

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
            ["Original Path", "Threat", "Date", "Actions"]
        )
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(2, 140)
        self.table.setColumnWidth(3, 180)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)

        self.refresh()

    def refresh(self):
        items = self.quarantine_mgr.get_quarantined()
        self.table.setRowCount(len(items))
        for row, entry in enumerate(items):
            self.table.setItem(row, 0, QTableWidgetItem(entry.get("original_path", "")))
            self.table.setItem(row, 1, QTableWidgetItem(entry.get("threat", "")))
            self.table.setItem(row, 2, QTableWidgetItem(entry.get("date", "")))

            btn_widget = QWidget()
            btn_layout = QHBoxLayout(btn_widget)
            btn_layout.setContentsMargins(4, 2, 4, 2)

            qname = entry.get("quarantine_name", "")

            restore_btn = QPushButton("Restore")
            restore_btn.setFixedWidth(70)
            restore_btn.setObjectName("successBtn")
            restore_btn.clicked.connect(
                lambda checked, n=qname: self.restore_file(n)
            )
            btn_layout.addWidget(restore_btn)

            delete_btn = QPushButton("Delete")
            delete_btn.setFixedWidth(70)
            delete_btn.setObjectName("dangerBtn")
            delete_btn.clicked.connect(
                lambda checked, n=qname: self.delete_file(n)
            )
            btn_layout.addWidget(delete_btn)

            self.table.setCellWidget(row, 3, btn_widget)

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
        self.tabs.addTab(self.scan_table, "Scan History")

        # Quarantine history
        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(4)
        self.quarantine_table.setHorizontalHeaderLabels(["Date", "Action", "Path", "Threat"])
        self.quarantine_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.quarantine_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tabs.addTab(self.quarantine_table, "Quarantine History")

        # Audit history
        self.audit_table = QTableWidget()
        self.audit_table.setColumnCount(3)
        self.audit_table.setHorizontalHeaderLabels(["Date", "Type", "Findings"])
        self.audit_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.audit_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
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

        content = QWidget()
        content.setStyleSheet(f"background-color: {BG_DARK};")
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
            edit.setMinimumWidth(250)
            btn = QPushButton("Browse")
            btn.setFixedWidth(80)
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

        yara_dl_btn = QPushButton("Download YARA Rules")
        yara_dl_btn.clicked.connect(self._download_yara_rules)
        yara_layout.addWidget(yara_dl_btn)

        self.yara_status = QLabel("")
        self.yara_status.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent; font-size: 11px;")
        yara_layout.addWidget(self.yara_status)
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

        # --- Whitelist ---
        wl_card = CardWidget("Ignore List (Whitelist)")
        wl_layout = QVBoxLayout(wl_card)

        wl_layout.addWidget(QLabel("Paths excluded from scans (one per line):"))
        self.whitelist_edit = QTextEdit()
        self.whitelist_edit.setMaximumHeight(120)
        whitelist = get_whitelist()
        self.whitelist_edit.setPlainText("\n".join(whitelist))
        self.whitelist_save_timer = QTimer()
        self.whitelist_save_timer.setSingleShot(True)
        self.whitelist_save_timer.setInterval(1000)
        self.whitelist_save_timer.timeout.connect(self._save_whitelist)
        self.whitelist_edit.textChanged.connect(self.whitelist_save_timer.start)
        wl_layout.addWidget(self.whitelist_edit)

        add_folder_btn = QPushButton("Add Folder")
        add_folder_btn.clicked.connect(self._add_whitelist_folder)
        wl_layout.addWidget(add_folder_btn)
        main_layout.addWidget(wl_card)

        # --- Scan Options ---
        scan_card = CardWidget("Scan Options")
        scan_layout = QVBoxLayout(scan_card)

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
        thread_row.addWidget(QLabel("Parallel scan paths:"))
        self.thread_spin = QSpinBox()
        self.thread_spin.setMinimum(1)
        self.thread_spin.setMaximum(max_cores)
        self.thread_spin.setValue(self.settings_mgr.get_scan_threads())
        self.thread_spin.valueChanged.connect(self.settings_mgr.set_scan_threads)
        thread_row.addWidget(self.thread_spin)
        thread_hint = QLabel(f"({max_cores} core{'s' if max_cores != 1 else ''} available — affects YARA scanning)")
        thread_hint.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent; font-size: 11px;")
        thread_hint.setWordWrap(True)
        thread_row.addWidget(thread_hint)
        scan_layout.addLayout(thread_row)
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
        self.defs_status.setText("Updating definitions...")
        self.defs_status.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        self.defs_progress.setVisible(True)
        self.defs_progress.setValue(0)
        self.update_btn.setEnabled(False)
        try:
            self.scanner.defs_update_finished.disconnect(self._on_defs_updated)
        except (TypeError, RuntimeError):
            pass
        try:
            self.scanner.defs_update_progress.disconnect(self._on_defs_progress)
        except (TypeError, RuntimeError):
            pass
        try:
            self.scanner.defs_update_status.disconnect(self._on_defs_status)
        except (TypeError, RuntimeError):
            pass
        self.scanner.defs_update_finished.connect(self._on_defs_updated)
        self.scanner.defs_update_progress.connect(self._on_defs_progress)
        self.scanner.defs_update_status.connect(self._on_defs_status)
        self.scanner.update_definitions()

    def _on_defs_updated(self, ok, msg):
        self.update_btn.setEnabled(True)
        self.defs_progress.setVisible(False)
        if ok:
            self.defs_status.setText(msg)
            self.defs_status.setStyleSheet(
                f"color: {SUCCESS}; background: transparent;"
            )
        else:
            self.defs_status.setText(f"Update failed: {msg}")
            self.defs_status.setStyleSheet(
                f"color: {DANGER}; background: transparent;"
            )
        self._check_definitions()

    def _on_defs_progress(self, pct):
        self.defs_progress.setValue(pct)

    def _on_defs_status(self, status):
        self.defs_status.setText(status)

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

    def _download_yara_rules(self):
        """Download YARA rules from trusted sources."""
        sources = list(YARA_RULES_SOURCES.keys())
        self._yara_dl_worker = YaraRulesDownloadWorker(sources)
        self._yara_dl_worker.progress.connect(lambda pct: self.yara_status.setText(f"Downloading... {pct}%"))
        self._yara_dl_worker.status.connect(lambda s: self.yara_status.setText(s))
        self._yara_dl_worker.finished.connect(self._on_yara_download_finished)
        self._yara_dl_worker.start()

    def _on_yara_download_finished(self, ok, msg):
        if ok:
            self.yara_status.setStyleSheet(f"color: {SUCCESS}; background: transparent;")
        else:
            self.yara_status.setStyleSheet(f"color: {DANGER}; background: transparent;")
        self.yara_status.setText(msg)

    def _add_whitelist_folder(self):
        path = QFileDialog.getExistingDirectory(
            self, "Select Folder to Whitelist", "",
            QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontUseNativeDialog,
        )
        if path:
            current = self.whitelist_edit.toPlainText()
            if current.strip():
                self.whitelist_edit.setPlainText(current.strip() + "\n" + path)
            else:
                self.whitelist_edit.setPlainText(path)
            self._save_whitelist()

    def _save_whitelist(self):
        text = self.whitelist_edit.toPlainText()
        paths = [p.strip() for p in text.split("\n") if p.strip()]
        save_whitelist(paths)

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
            if cmds:
                commands = ["sudo", "pacman", "-S", "--needed", "--noconfirm"] + cmds
        elif distro_id in ("debian", "ubuntu", "linuxmint", "pop", "zorin") or "debian" in distro_id:
            cmds = []
            if not find_clamscan():
                cmds.append("clamav")
            if not find_yara():
                cmds.append("yara")
            if cmds:
                commands = ["sudo", "apt-get", "install", "-y"] + cmds
        elif distro_id in ("fedora", "rhel", "centos", "rocky", "almalinux") or "fedora" in distro_id:
            cmds = []
            if not find_clamscan():
                cmds.append("clamav")
            if not find_yara():
                cmds.append("yara")
            if cmds:
                commands = ["sudo", "dnf", "install", "-y"] + cmds
        else:
            cmds = []
            if not find_clamscan():
                cmds.append("clamav")
            if not find_yara():
                cmds.append("yara")
            install_str = " ".join(cmds)
            QMessageBox.information(
                self, "Install Dependencies",
                f"Could not detect your package manager.\n\n"
                f"Please install manually:\n  {install_str}",
            )
            return

        if not commands:
            return

        cmd_str = " ".join(commands)
        reply = QMessageBox.question(
            self, "Install Dependencies",
            f"Install the following packages?\n\n  {cmd_str}\n\n"
            f"This will require sudo privileges.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            terminal = shutil.which("konsole") or shutil.which("gnome-terminal") or shutil.which("xterm")
            if terminal:
                cmd_str = " ".join(commands)
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