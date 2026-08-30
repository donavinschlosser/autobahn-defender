"""
Autobahn Defender v2.0 — Security Center Tab.

Replaces the broken ai_tab.py. Deterministic, no AI model.
  - Alert Center: active security alerts (from scans + network watch)
  - Vulnerabilities: OSV.dev CVE scan + false-positive filter + patch tracking
  - Security Audit: 4 deterministic audit profiles with scoring
  - Hardening: AppArmor, UFW, sysctl, SSH, privacy — pkexec-gated
  - Network Watch: connection monitoring + blacklist + persistence

Contact: XMPP digitalautobahn@xmpp.brax.me
"""

from __future__ import annotations

import logging
from typing import Any

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QTabWidget, QTextEdit, QTableWidget, QTableWidgetItem,
    QProgressBar, QGroupBox, QMessageBox, QHeaderView, QSplitter,
    QCheckBox, QComboBox, QAbstractItemView,
)
from PyQt6.QtGui import QFont, QColor

from ui_tabs import (
    BG_DARK, BG_CARD, BORDER, ACCENT, TEXT_PRIMARY, TEXT_SECONDARY,
    BTN_BLUE, BTN_BLUE_HOVER, SUCCESS, DANGER, STYLESHEET,
)

from engine import advisor, alerts, cve, patches, apply as apply_mod
from engine import privacy as privacy_mod, network_watch, persistence
from engine import startup as startup_mod
from engine import CONTACT_XMPP, APP_VERSION

log = logging.getLogger(__name__)

# Task button definitions (condensed to 4 — no redundancy)
AUDIT_BUTTONS = [
    ("full_audit", "Full Security Audit"),
    ("vulnerability_scan", "Vulnerability Scan"),
    ("network_audit", "Network Audit"),
    ("hardening_audit", "Hardening Audit"),
]


class _AuditWorker(QThread):
    finished = pyqtSignal(object)
    progress = pyqtSignal(str)

    def __init__(self, task_id: str):
        super().__init__()
        self.task_id = task_id

    def run(self):
        self.progress.emit("Running security checks...")
        try:
            result = advisor.run_audit(self.task_id)
            self.finished.emit(result)
        except Exception as e:
            log.error("Audit failed: %s", e)
            self.finished.emit(None)


class _CVEWorker(QThread):
    finished = pyqtSignal(dict)
    progress = pyqtSignal(str)

    def run(self):
        self.progress.emit("Scanning for vulnerabilities (OSV.dev)...")
        try:
            result = cve.scan_cves()
            self.finished.emit(result)
        except Exception as e:
            log.error("CVE scan failed: %s", e)
            self.finished.emit({"error": str(e)})


class _PatchWorker(QThread):
    finished = pyqtSignal(dict)
    progress = pyqtSignal(str)

    def run(self):
        self.progress.emit("Checking for available patches...")
        try:
            result = patches.check_for_fixes()
            self.finished.emit(result)
        except Exception as e:
            log.error("Patch check failed: %s", e)
            self.finished.emit({"error": str(e)})


class SecurityTab(QWidget):
    """Main Security Center tab — replaces AISecurityTab."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None
        self._cve_worker = None
        self._patch_worker = None
        self._net_watch = network_watch.NetworkWatch()
        self._build_ui()
        self._refresh_alerts()

    def cleanup(self):
        """Stop any running background threads before close."""
        if self._worker and self._worker.isRunning():
            self._worker.wait(3000)
        if self._cve_worker and self._cve_worker.isRunning():
            self._cve_worker.wait(3000)
        if self._patch_worker and self._patch_worker.isRunning():
            self._patch_worker.wait(3000)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header
        header = QHBoxLayout()
        title = QLabel("Security Center")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent;")
        header.addWidget(title)
        header.addStretch()

        status_text = f"Active Security Engine v{APP_VERSION}"
        self.status_label = QLabel(status_text)
        self.status_label.setStyleSheet(
            f"color: {SUCCESS}; background: transparent; font-size: 12px;"
        )
        header.addWidget(self.status_label)
        layout.addLayout(header)

        # Sub-tabs
        sub_tabs = QTabWidget()
        sub_tabs.setStyleSheet(STYLESHEET)

        sub_tabs.addTab(self._build_alert_tab(), "Alert Center")
        sub_tabs.addTab(self._build_vuln_tab(), "Vulnerabilities")
        sub_tabs.addTab(self._build_audit_tab(), "Security Audit")
        sub_tabs.addTab(self._build_hardening_tab(), "Hardening")
        sub_tabs.addTab(self._build_network_tab(), "Network Watch")

        layout.addWidget(sub_tabs)

    # -----------------------------------------------------------------------
    # Alert Center — shows active alerts from alerts.jsonl (NOT CVE table dupe)
    # -----------------------------------------------------------------------
    def _build_alert_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(10)

        # Info label
        info = QLabel(
            "Active security alerts generated by scans and network monitoring. "
            "Resolve alerts by applying the recommended fix, or dismiss if not applicable."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
        layout.addWidget(info)

        # Toolbar
        toolbar = QHBoxLayout()
        refresh_btn = QPushButton("Refresh Alerts")
        refresh_btn.clicked.connect(self._refresh_alerts)
        toolbar.addWidget(refresh_btn)

        clear_btn = QPushButton("Clear Old Resolved")
        clear_btn.clicked.connect(self._clear_resolved)
        toolbar.addWidget(clear_btn)

        toolbar.addStretch()
        self._alert_count_label = QLabel("0 active alerts")
        self._alert_count_label.setStyleSheet(f"color: {TEXT_SECONDARY};")
        toolbar.addWidget(self._alert_count_label)
        layout.addLayout(toolbar)

        # Alert table
        self._alert_table = QTableWidget(0, 6)
        self._alert_table.setHorizontalHeaderLabels(
            ["Severity", "Title", "Package", "CVE", "Fix Command", "Timestamp"]
        )
        self._alert_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._alert_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._alert_table.setAlternatingRowColors(True)
        self._alert_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        layout.addWidget(self._alert_table)

        # Action buttons
        btn_row = QHBoxLayout()
        resolve_btn = QPushButton("Mark Resolved")
        resolve_btn.clicked.connect(self._resolve_selected_alert)
        btn_row.addWidget(resolve_btn)

        dismiss_btn = QPushButton("Dismiss")
        dismiss_btn.clicked.connect(self._dismiss_selected_alert)
        btn_row.addWidget(dismiss_btn)

        copy_btn = QPushButton("Copy Fix Command")
        copy_btn.clicked.connect(self._copy_alert_fix)
        btn_row.addWidget(copy_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        return w

    def _refresh_alerts(self):
        active = alerts.load_alerts(active_only=True)
        self._alert_table.setRowCount(0)
        for alert in active:
            row = self._alert_table.rowCount()
            self._alert_table.insertRow(row)
            sev = alert.get("severity", "medium")
            sev_item = QTableWidgetItem(sev.upper())
            color = {"critical": DANGER, "high": "#FF8800",
                     "medium": "#FFCC00", "low": SUCCESS}.get(sev, TEXT_SECONDARY)
            sev_item.setForeground(QColor(color))
            self._alert_table.setItem(row, 0, sev_item)
            self._alert_table.setItem(row, 1, QTableWidgetItem(alert.get("title", "")))
            self._alert_table.setItem(row, 2, QTableWidgetItem(alert.get("affected_package", "")))
            self._alert_table.setItem(row, 3, QTableWidgetItem(alert.get("cve_id", "")))
            self._alert_table.setItem(row, 4, QTableWidgetItem(alert.get("recommended_action", "")))
            self._alert_table.setItem(row, 5, QTableWidgetItem(alert.get("timestamp", "")[:19]))
        self._alert_count_label.setText(f"{len(active)} active alerts")

    def _clear_resolved(self):
        removed = alerts.clear_resolved()
        self._refresh_alerts()
        if removed:
            QMessageBox.information(self, "Cleanup", f"Removed {removed} old resolved alerts.")

    def _resolve_selected_alert(self):
        row = self._alert_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Resolve Alert", "Select an alert from the table first.")
            return
        active = alerts.load_alerts(active_only=True)
        if row < len(active):
            alert_id = active[row].get("id", "")
            if alerts.resolve_alert(alert_id):
                self._refresh_alerts()
                QMessageBox.information(self, "Resolved", "Alert marked as resolved.")

    def _dismiss_selected_alert(self):
        row = self._alert_table.currentRow()
        if row < 0:
            return
        active = alerts.load_alerts(active_only=True)
        if row < len(active):
            alert_id = active[row].get("id", "")
            if alerts.dismiss_alert(alert_id):
                self._refresh_alerts()

    def _copy_alert_fix(self):
        row = self._alert_table.currentRow()
        if row < 0:
            return
        item = self._alert_table.item(row, 4)
        if item:
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText(item.text())

    # -----------------------------------------------------------------------
    # Vulnerabilities — CVE scan + patch tracking + mass fix
    # -----------------------------------------------------------------------
    def _build_vuln_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(10)

        # Toolbar
        toolbar = QHBoxLayout()
        scan_btn = QPushButton("Scan for Vulnerabilities")
        scan_btn.clicked.connect(self._run_cve_scan)
        toolbar.addWidget(scan_btn)

        patch_btn = QPushButton("Check for Patches")
        patch_btn.clicked.connect(self._check_patches)
        toolbar.addWidget(patch_btn)

        toolbar.addStretch()
        self._vuln_status = QLabel("Ready — click Scan to check installed packages against OSV.dev")
        self._vuln_status.setStyleSheet(f"color: {TEXT_SECONDARY};")
        toolbar.addWidget(self._vuln_status)
        layout.addLayout(toolbar)

        # Progress bar
        self._vuln_progress = QProgressBar()
        self._vuln_progress.setVisible(False)
        layout.addWidget(self._vuln_progress)

        # Summary line
        self._vuln_summary = QLabel("")
        self._vuln_summary.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 13px;")
        layout.addWidget(self._vuln_summary)

        # Results table
        self._vuln_table = QTableWidget(0, 6)
        self._vuln_table.setHorizontalHeaderLabels(
            ["CVE ID", "Package", "Installed", "Fixed In", "Severity", "Summary"]
        )
        self._vuln_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self._vuln_table.setAlternatingRowColors(True)
        self._vuln_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._vuln_table.setSortingEnabled(True)
        layout.addWidget(self._vuln_table)

        # Mass fix buttons
        fix_row = QHBoxLayout()
        self._track_btn = QPushButton("Track Selected CVEs")
        self._track_btn.clicked.connect(self._track_selected_cves)
        fix_row.addWidget(self._track_btn)

        self._fix_all_btn = QPushButton("Fix All Available Patches")
        self._fix_all_btn.clicked.connect(self._fix_all_patches)
        self._fix_all_btn.setStyleSheet(f"background-color: {BTN_BLUE};")
        fix_row.addWidget(self._fix_all_btn)

        verify_btn = QPushButton("Verify Patch Applied")
        verify_btn.clicked.connect(self._verify_patch)
        fix_row.addWidget(verify_btn)

        fix_row.addStretch()
        layout.addLayout(fix_row)

        # Patch tracker section
        patch_group = QGroupBox("Patch Tracker — Tracked CVEs")
        patch_layout = QVBoxLayout(patch_group)
        self._patch_table = QTableWidget(0, 5)
        self._patch_table.setHorizontalHeaderLabels(
            ["CVE", "Package", "Installed", "Available", "Status"]
        )
        self._patch_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._patch_table.setAlternatingRowColors(True)
        self._patch_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        patch_layout.addWidget(self._patch_table)

        layout.addWidget(patch_group)

        return w

    def _run_cve_scan(self):
        if self._cve_worker and self._cve_worker.isRunning():
            return
        self._vuln_progress.setVisible(True)
        self._vuln_progress.setRange(0, 0)
        self._vuln_status.setText("Scanning... this may take 30-60 seconds for 2600+ packages")
        self._cve_worker = _CVEWorker()
        self._cve_worker.finished.connect(self._on_cve_finished)
        self._cve_worker.start()

    def _on_cve_finished(self, result: dict):
        self._vuln_progress.setVisible(False)
        if "error" in result:
            self._vuln_status.setText(f"Error: {result['error']}")
            return

        found = result.get("vulnerabilities_found", 0)
        checked = result.get("packages_checked", 0)
        filtered = result.get("filtered_out", 0)
        self._vuln_status.setText("Scan complete")
        self._vuln_summary.setText(
            f"Checked {checked} packages · Found {found} vulnerabilities "
            f"({filtered} false positives filtered out)"
        )

        vulns = result.get("vulnerabilities", [])
        self._vuln_table.setRowCount(0)
        self._last_cve_results = vulns  # keep for tracking

        for v in vulns:
            row = self._vuln_table.rowCount()
            self._vuln_table.insertRow(row)
            self._vuln_table.setItem(row, 0, QTableWidgetItem(v.get("cve_id", "")))
            self._vuln_table.setItem(row, 1, QTableWidgetItem(v.get("app_name", "")))
            self._vuln_table.setItem(row, 2, QTableWidgetItem(v.get("installed_version", "")))
            self._vuln_table.setItem(row, 3, QTableWidgetItem(v.get("fixed_in", "No fix available")))
            sev = "HIGH"
            sev_str = str(v.get("severity", ""))
            if "CRITICAL" in sev_str.upper():
                sev = "CRITICAL"
            elif "MEDIUM" in sev_str.upper():
                sev = "MEDIUM"
            elif "LOW" in sev_str.upper():
                sev = "LOW"
            sev_item = QTableWidgetItem(sev)
            color = {"CRITICAL": DANGER, "HIGH": "#FF8800",
                     "MEDIUM": "#FFCC00", "LOW": SUCCESS}.get(sev, TEXT_SECONDARY)
            sev_item.setForeground(QColor(color))
            self._vuln_table.setItem(row, 4, sev_item)
            self._vuln_table.setItem(row, 5, QTableWidgetItem(v.get("summary", "")[:100]))

    def _track_selected_cves(self):
        """Track selected CVEs for patch monitoring."""
        rows = set()
        for item in self._vuln_table.selectedItems():
            rows.add(item.row())
        if not rows:
            QMessageBox.information(self, "Track CVEs", "Select one or more CVEs from the table first.")
            return

        tracked = 0
        for row in sorted(rows):
            cve_id = self._vuln_table.item(row, 0).text()
            pkg = self._vuln_table.item(row, 1).text()
            installed = self._vuln_table.item(row, 2).text()
            fixed_in = self._vuln_table.item(row, 3).text()
            if fixed_in == "No fix available":
                fixed_in = ""
            if pkg and cve_id:
                patches.track_cve(cve_id, pkg, installed, fixed_in)
                tracked += 1

        # Also create alerts for tracked CVEs
        for row in sorted(rows):
            cve_id = self._vuln_table.item(row, 0).text()
            pkg = self._vuln_table.item(row, 1).text()
            installed = self._vuln_table.item(row, 2).text()
            fixed_in = self._vuln_table.item(row, 3).text()
            if fixed_in == "No fix available":
                fix_cmd = f"No patch available. Check https://nvd.nist.gov/vuln/detail/{cve_id}"
            else:
                fix_cmd = f"sudo apt update && sudo apt upgrade {pkg}"

            alert = alerts.create_alert(
                severity="high",
                title=f"{cve_id} affects {pkg} {installed}",
                recommended_action=fix_cmd,
                affected_package=pkg,
                installed_version=installed,
                patch_available=bool(fixed_in and fixed_in != "No fix available"),
                source="OSV.dev",
                cve_id=cve_id,
            )
            alerts.add_alert(alert)

        QMessageBox.information(self, "Tracking", f"Tracking {tracked} CVE(s) for patch availability.")
        self._refresh_alerts()
        self._check_patches()

    def _check_patches(self):
        """Check for available patches in a background thread."""
        if self._patch_worker and self._patch_worker.isRunning():
            return
        self._vuln_status.setText("Checking for available patches...")
        self._patch_worker = _PatchWorker()
        self._patch_worker.finished.connect(self._on_patches_checked)
        self._patch_worker.start()

    def _on_patches_checked(self, result: dict):
        if "error" in result:
            self._vuln_status.setText(f"Patch check failed: {result['error']}")
            return

        tracked = patches.get_tracked()
        self._patch_table.setRowCount(0)
        for entry in tracked:
            row = self._patch_table.rowCount()
            self._patch_table.insertRow(row)
            self._patch_table.setItem(row, 0, QTableWidgetItem(entry.get("cve_id", "")))
            self._patch_table.setItem(row, 1, QTableWidgetItem(entry.get("package", "")))
            self._patch_table.setItem(row, 2, QTableWidgetItem(entry.get("installed_version", "")))
            self._patch_table.setItem(row, 3, QTableWidgetItem(entry.get("available_version", "—")))
            status = entry.get("status", "open")
            status_item = QTableWidgetItem(status)
            color = {"fix_available": "#FF8800", "applied": SUCCESS,
                     "open": DANGER, "patched_external": SUCCESS}.get(status, TEXT_SECONDARY)
            status_item.setForeground(QColor(color))
            self._patch_table.setItem(row, 4, status_item)

        fixes = result.get("fixes_available", 0)
        applied = result.get("fixes_applied", 0)
        open_count = result.get("open", 0)

        if open_count == 0:
            self._vuln_status.setText("No CVEs are being tracked. Select CVEs and click 'Track Selected CVEs' first.")
        elif fixes == 0 and applied == 0:
            self._vuln_status.setText(
                f"Tracking {open_count} CVEs — no patches available yet. "
                f"Run 'sudo apt update' to refresh package lists."
            )
        else:
            self._vuln_status.setText(
                f"Patches: {fixes} available to install, {applied} verified fixed"
            )

    def _fix_all_patches(self):
        """Mass-fix: upgrade all packages that have patches available."""
        tracked = patches.get_tracked()
        fix_available = [e for e in tracked if e.get("status") == "fix_available"]

        if not fix_available:
            QMessageBox.information(self, "Fix All Patches",
                "No patches are currently available. Click 'Check for Patches' first.\n\n"
                "If you have tracked CVEs but no patches show as available, it means\n"
                "your system is already up to date or the fix hasn't reached your\n"
                "distro's repositories yet.\n\n"
                "Try: sudo apt update && sudo apt upgrade")
            return

        pkgs = list(set(e["package"] for e in fix_available))
        pkg_list = " ".join(pkgs)
        confirm = QMessageBox.warning(
            self, "Confirm Mass Update",
            f"This will upgrade {len(pkgs)} package(s):\n\n{pkg_list}\n\n"
            f"You will be prompted for your password.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        for pkg in pkgs:
            result = apply_mod.apt_upgrade_package(pkg)
            if not result.get("success"):
                QMessageBox.warning(self, "Update Failed",
                    f"Failed to update {pkg}: {result.get('error', 'unknown error')}")
            else:
                # Verify the patch
                patches.verify_patch_applied(pkg)

        QMessageBox.information(self, "Updates Complete",
            "Package updates completed. Click 'Verify Patch Applied' to confirm CVEs are resolved.")
        self._check_patches()

    def _verify_patch(self):
        row = self._patch_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Verify Patch", "Select a package from the patch tracker first.")
            return
        tracked = patches.get_tracked()
        if row < len(tracked):
            pkg = tracked[row].get("package", "")
            cve_id = tracked[row].get("cve_id", "")
            if pkg:
                result = patches.verify_patch_applied(pkg, cve_id)
                # Audit 2026-08-31 A-7 fix: empty OSV results used to be
                # reported as "verified fixed". Inconclusive is not resolved.
                if result.get("status") == "inconclusive":
                    QMessageBox.warning(self, "Verification Inconclusive",
                        f"OSV returned no vulnerability data for {pkg}.\n\n"
                        f"{result.get('note', '')}")
                    self._check_patches()
                    return
                if result.get("all_resolved"):
                    QMessageBox.information(self, "Patch Verified",
                        f"✓ {pkg} has been updated and all CVEs are resolved!")
                else:
                    results = result.get("results", [])
                    still_vuln = [r for r in results if not r.get("resolved")]
                    if still_vuln:
                        QMessageBox.warning(self, "Still Vulnerable",
                            f"{pkg} is still vulnerable to {len(still_vuln)} CVE(s).\n"
                            f"Current version: {result.get('installed_version', '?')}\n"
                            f"The fix may not be available in your repos yet.")
                    else:
                        QMessageBox.information(self, "Verification",
                            f"No tracked CVEs found for {pkg}.")
                self._check_patches()

    # -----------------------------------------------------------------------
    # Security Audit — 4 non-redundant audit profiles
    # -----------------------------------------------------------------------
    def _build_audit_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(10)

        # Info
        info = QLabel("Run a security audit to check your system for issues. "
                       "Each audit produces a scored report with actionable findings and fix commands.")
        info.setWordWrap(True)
        info.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
        layout.addWidget(info)

        # Button grid (4 buttons, not 6)
        btn_layout = QHBoxLayout()
        for task_id, label in AUDIT_BUTTONS:
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked, tid=task_id: self._run_audit(tid))
            btn_layout.addWidget(btn)
        layout.addLayout(btn_layout)

        # Progress bar
        self._audit_progress = QProgressBar()
        self._audit_progress.setVisible(False)
        layout.addWidget(self._audit_progress)

        # Score label
        self._audit_score = QLabel("")
        self._audit_score.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self._audit_score.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._audit_score)

        # Report view
        self._audit_report = QTextEdit()
        self._audit_report.setReadOnly(True)
        self._audit_report.setPlaceholderText(
            "Click a button above to run a security audit.\n"
            "Results will appear here with [SEVERITY]-tagged findings and fix commands.\n\n"
            "• Full Security Audit: comprehensive scan of everything\n"
            "• Vulnerability Scan: CVE check against OSV.dev + patch status\n"
            "• Network Audit: connections, DNS, threats\n"
            "• Hardening Audit: sysctl, SSH, privacy, disk encryption"
        )
        layout.addWidget(self._audit_report, 1)

        # Action buttons
        action_row = QHBoxLayout()
        copy_btn = QPushButton("Copy Report")
        copy_btn.clicked.connect(self._copy_report)
        action_row.addWidget(copy_btn)

        save_btn = QPushButton("Save Report (HTML)")
        save_btn.clicked.connect(self._save_report)
        action_row.addWidget(save_btn)
        action_row.addStretch()
        layout.addLayout(action_row)

        return w

    def _run_audit(self, task_id: str):
        if self._worker and self._worker.isRunning():
            return
        self._audit_progress.setVisible(True)
        self._audit_progress.setRange(0, 0)
        self._audit_report.clear()
        self._audit_score.setText("Running checks...")
        self._worker = _AuditWorker(task_id)
        self._worker.finished.connect(self._on_audit_finished)
        self._worker.start()

    def _on_audit_finished(self, result):
        self._audit_progress.setVisible(False)
        if result is None:
            self._audit_score.setText("Audit failed")
            self._audit_report.setPlainText("An error occurred during the audit.")
            return

        score = result.score
        color = SUCCESS if score >= 80 else ("#FF8800" if score >= 60 else DANGER)
        self._audit_score.setText(f"Security Score: {score}/100")
        self._audit_score.setStyleSheet(f"color: {color}; font-size: 16px; font-weight: bold;")

        self._audit_report.setMarkdown(result.report_markdown)
        self._last_audit_result = result

    def _copy_report(self):
        if hasattr(self, "_last_audit_result"):
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText(self._last_audit_result.report_markdown)

    def _save_report(self):
        if not hasattr(self, "_last_audit_result"):
            return
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", "autobahn-security-report.html", "HTML (*.html)")
        if path:
            with open(path, "w") as f:
                f.write(self._last_audit_result.report_html)

    # -----------------------------------------------------------------------
    # Hardening — AppArmor, UFW, sysctl, SSH, Privacy
    # -----------------------------------------------------------------------
    def _build_hardening_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(10)

        info = QLabel("Apply security hardening to your system. "
                       "Every action requires your password (via pkexec) and shows the exact "
                       "command before executing. Changes are logged to actions.log.")
        info.setWordWrap(True)
        info.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
        layout.addWidget(info)

        # AppArmor
        aa_group = QGroupBox("AppArmor")
        aa_layout = QVBoxLayout(aa_group)
        aa_btn = QPushButton("Enforce All Profiles")
        aa_btn.clicked.connect(lambda: self._run_apply("apparmor"))
        aa_layout.addWidget(aa_btn)
        layout.addWidget(aa_group)

        # Firewall
        fw_group = QGroupBox("Firewall (UFW)")
        fw_layout = QVBoxLayout(fw_group)
        fw_btn_row = QHBoxLayout()
        fw_enable = QPushButton("Enable Firewall")
        fw_enable.clicked.connect(lambda: self._run_apply("fw_enable"))
        fw_btn_row.addWidget(fw_enable)
        fw_disable = QPushButton("Disable Firewall")
        fw_disable.clicked.connect(lambda: self._run_apply("fw_disable"))
        fw_btn_row.addWidget(fw_disable)
        fw_layout.addLayout(fw_btn_row)
        layout.addWidget(fw_group)

        # Sysctl hardening
        sys_group = QGroupBox("Kernel Hardening (sysctl — 13 settings)")
        sys_layout = QVBoxLayout(sys_group)
        sys_desc = QLabel("Applies kernel and network hardening: ASLR, kptr_restrict, "
                          "dmesg_restrict, ptrace_scope, BPF, syncookies, rp_filter, "
                          "redirect blocking, source route blocking, log_martians, etc.")
        sys_desc.setWordWrap(True)
        sys_desc.setStyleSheet(f"color: {TEXT_SECONDARY};")
        sys_layout.addWidget(sys_desc)
        sys_btn = QPushButton("Apply All Hardening Settings")
        sys_btn.clicked.connect(lambda: self._run_apply("sysctl"))
        sys_layout.addWidget(sys_btn)
        layout.addWidget(sys_group)

        # SSH
        ssh_group = QGroupBox("SSH Hardening")
        ssh_layout = QVBoxLayout(ssh_group)
        ssh_desc = QLabel("Disables root login and password authentication, sets MaxAuthTries=3. "
                          "Validates with sshd -t before reload; auto-rollback on failure.")
        ssh_desc.setWordWrap(True)
        ssh_desc.setStyleSheet(f"color: {TEXT_SECONDARY};")
        ssh_layout.addWidget(ssh_desc)
        ssh_btn = QPushButton("Harden SSH")
        ssh_btn.clicked.connect(lambda: self._run_apply("ssh"))
        ssh_layout.addWidget(ssh_btn)
        layout.addWidget(ssh_group)

        # Privacy
        priv_group = QGroupBox("Privacy Shield")
        priv_layout = QVBoxLayout(priv_group)
        priv_desc = QLabel("Checks and applies GNOME privacy settings (usage stats, recent files, "
                          "location, crash reporting, connectivity check) + sysctl hardening.")
        priv_desc.setWordWrap(True)
        priv_desc.setStyleSheet(f"color: {TEXT_SECONDARY};")
        priv_layout.addWidget(priv_desc)

        priv_check_btn = QPushButton("Check Privacy Settings")
        priv_check_btn.clicked.connect(self._check_privacy)
        priv_layout.addWidget(priv_check_btn)

        priv_apply_btn = QPushButton("Apply All Privacy Settings")
        priv_apply_btn.clicked.connect(lambda: self._run_apply("privacy"))
        priv_layout.addWidget(priv_apply_btn)
        layout.addWidget(priv_group)

        layout.addStretch()
        return w

    def _run_apply(self, action: str):
        confirm = QMessageBox.warning(
            self, "Confirm Action",
            f"This will apply {action} changes to your system.\n"
            f"You will be prompted for your password.\n\n"
            f"Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        result = None
        if action == "apparmor":
            result = apply_mod.apparmor_enforce()
        elif action == "fw_enable":
            result = apply_mod.firewall_enable()
        elif action == "fw_disable":
            result = apply_mod.firewall_disable()
        elif action == "sysctl":
            result = apply_mod.sysctl_harden()
        elif action == "ssh":
            result = apply_mod.ssh_harden()
        elif action == "privacy":
            result = privacy_mod.apply_all_privacy()

        if result:
            if result.get("success"):
                QMessageBox.information(self, "Success", "Action completed successfully.")
            else:
                QMessageBox.warning(self, "Action Failed",
                    f"The action failed: {result.get('error', 'Unknown error')}")

    def _check_privacy(self):
        results = privacy_mod.check_privacy_settings()
        if not results:
            QMessageBox.information(self, "Privacy Check",
                "No privacy settings to check on this desktop environment.")
            return
        report = "Privacy Settings Check:\n\n"
        for r in results:
            status = "✓" if r.get("is_hardened") else "✗"
            report += f"{status} {r['label']}: {r.get('current_value', '?')} (should be {r.get('hardened_value', '?')})\n"
        QMessageBox.information(self, "Privacy Check", report)

    # -----------------------------------------------------------------------
    # Network Watch — connections + blacklist + persistence
    # -----------------------------------------------------------------------
    def _build_network_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(10)

        info = QLabel("Monitor network connections against threat blacklists. "
                       "Download a blacklist first, then scan connections. "
                       "The persistence scanner checks crontab, systemd, and autostart for malware.")
        info.setWordWrap(True)
        info.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
        layout.addWidget(info)

        # Toolbar
        toolbar = QHBoxLayout()
        scan_btn = QPushButton("Scan Connections")
        scan_btn.clicked.connect(self._scan_network)
        toolbar.addWidget(scan_btn)

        bl_btn = QPushButton("Download Blacklist")
        bl_btn.clicked.connect(self._download_blacklist)
        toolbar.addWidget(bl_btn)

        toolbar.addStretch()
        self._net_status = QLabel("No blacklist loaded — download one to enable threat matching")
        self._net_status.setStyleSheet(f"color: {TEXT_SECONDARY};")
        toolbar.addWidget(self._net_status)
        layout.addLayout(toolbar)

        # Threats table
        self._threat_table = QTableWidget(0, 5)
        self._threat_table.setHorizontalHeaderLabels(
            ["IP", "Port", "Process", "Severity", "Reason"]
        )
        self._threat_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._threat_table.setAlternatingRowColors(True)
        layout.addWidget(self._threat_table)

        # All connections table (show all connections even if not on blacklist)
        conn_group = QGroupBox("All Active Connections")
        conn_layout = QVBoxLayout(conn_group)
        self._conn_table = QTableWidget(0, 4)
        self._conn_table.setHorizontalHeaderLabels(
            ["Peer IP", "Port", "PID", "Process"]
        )
        self._conn_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._conn_table.setAlternatingRowColors(True)
        conn_layout.addWidget(self._conn_table)
        layout.addWidget(conn_group)

        # Persistence scan
        pers_group = QGroupBox("Persistence & Hosts File Check")
        pers_layout = QVBoxLayout(pers_group)
        pers_btn = QPushButton("Scan Persistence + Hosts File")
        pers_btn.clicked.connect(self._scan_persistence)
        pers_layout.addWidget(pers_btn)
        self._pers_result = QTextEdit()
        self._pers_result.setReadOnly(True)
        self._pers_result.setMaximumHeight(150)
        pers_layout.addWidget(self._pers_result)
        layout.addWidget(pers_group)

        layout.addStretch()
        return w

    def _scan_network(self):
        """Scan connections and display both threats and all connections."""
        from engine.network_watch import get_connections

        # Always show all connections
        all_conns = get_connections()
        self._conn_table.setRowCount(0)
        for c in all_conns:
            row = self._conn_table.rowCount()
            self._conn_table.insertRow(row)
            self._conn_table.setItem(row, 0, QTableWidgetItem(c.get("peer_ip", "")))
            self._conn_table.setItem(row, 1, QTableWidgetItem(str(c.get("peer_port", ""))))
            self._conn_table.setItem(row, 2, QTableWidgetItem(str(c.get("pid", ""))))
            self._conn_table.setItem(row, 3, QTableWidgetItem(c.get("process", "")))

        # Check against blacklist
        threats = self._net_watch.scan()
        self._threat_table.setRowCount(0)
        for t in threats:
            row = self._threat_table.rowCount()
            self._threat_table.insertRow(row)
            self._threat_table.setItem(row, 0, QTableWidgetItem(t.get("ip", "")))
            self._threat_table.setItem(row, 1, QTableWidgetItem(str(t.get("port", ""))))
            self._threat_table.setItem(row, 2, QTableWidgetItem(t.get("process", "")))
            sev_item = QTableWidgetItem(t.get("severity", "MEDIUM"))
            sev_item.setForeground(QColor(DANGER if t.get("severity") == "HIGH" else "#FF8800"))
            self._threat_table.setItem(row, 3, sev_item)
            self._threat_table.setItem(row, 4, QTableWidgetItem(t.get("reason", "")))

        if self._net_watch.has_blacklist():
            self._net_status.setText(
                f"Scan complete — {len(all_conns)} connections, {len(threats)} threats found"
            )
        else:
            self._net_status.setText(
                f"Scan complete — {len(all_conns)} connections shown. "
                f"Download a blacklist to check for threats."
            )

    def _download_blacklist(self):
        self._net_status.setText("Downloading blacklist (this may take 30-60 seconds)...")
        QApplication_instance = self
        try:
            success = self._net_watch.refresh_blacklist()
            if success:
                self._net_status.setText("Blacklist downloaded and cached. Click 'Scan Connections' to check.")
            else:
                self._net_status.setText("Download failed — check network connectivity")
        except Exception as e:
            self._net_status.setText(f"Error: {e}")

    def _scan_persistence(self):
        pers = persistence.scan_persistence()
        hosts = persistence.check_hosts_file()

        report = "=== PERSISTENCE SCAN ===\n"
        findings = pers.get("suspicious_entries", [])
        if findings:
            report += f"Found {len(findings)} suspicious entries:\n"
            for f in findings:
                report += f"  [{f['type']}] {f['detail']}\n"
        else:
            report += "No suspicious persistence entries found.\n"

        report += "\n=== HOSTS FILE CHECK ===\n"
        if hosts.get("tampered"):
            report += f"WARNING: Hosts file has {len(hosts.get('redirects', []))} suspicious redirects!\n"
            for r in hosts.get("redirects", []):
                report += f"  {r['domain']} -> {r['ip']}\n"
        else:
            report += "Hosts file appears clean.\n"

        self._pers_result.setPlainText(report)