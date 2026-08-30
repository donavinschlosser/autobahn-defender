"""
Autobahn Defender v2.0 -- AI Security Tab UI.

Condensed button layout: 6 focused buttons + chat. The AI runs with
MAX Thinking enabled on LFM2.5-2.6B-Thinking at 90K context.

Layout:
  - Header (top): title, ON/OFF toggle, Auto Monitor toggle
  - Threat Dashboard: active alerts from automated monitoring
  - Control panel: 6 condensed buttons organized by category
  - AI output panel (middle): streaming, color-coded prefixes
  - Chat input: freeform text input for questions
  - Report summary (bottom): last audit results, action buttons

The user-facing controls are:
  - AI enable/disable toggle (MUST be manually enabled, never auto-starts)
  - Auto Monitor toggle (requires AI on)
  - Chat input field (requires AI on)
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import re
import subprocess
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QRect
from PyQt6.QtGui import QColor, QFont, QDragEnterEvent, QDropEvent, QPainter, QBrush, QPen, QPaintEvent
from PyQt6.QtWidgets import (
    QCheckBox, QFileDialog, QFrame, QGroupBox, QHBoxLayout, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPlainTextEdit,
    QPushButton, QScrollArea, QSizePolicy, QTextEdit, QVBoxLayout, QWidget,
)

from ai import (
    APP_VERSION, REPORTS_DIR, INTEL_DIR,
)
from ai import intel_db, rss_feeds
from ai.ollama_manager import OllamaManager, find_ollama_binary
from ai.worker import AIWorker

log = logging.getLogger(__name__)

# Reuse theme colors from ui_tabs for visual consistency
try:
    from ui_tabs import BG_DARK, BG_CARD, BORDER, ACCENT, ACCENT_HOVER
    from ui_tabs import TEXT_PRIMARY, TEXT_SECONDARY, DANGER, SUCCESS
except Exception:
    BG_DARK = "#121212"; BG_CARD = "#1E1E1E"; BORDER = "#2C2C2C"
    ACCENT = "#2962FF"; ACCENT_HOVER = "#1E53E0"
    TEXT_PRIMARY = "#E0E0E0"; TEXT_SECONDARY = "#A0A0A0"
    DANGER = "#CF6679"; SUCCESS = "#4CAF50"


# Task definitions: (task_id, button_label, user_prompt, category)
# Condensed from ~30 buttons to 6 focused buttons + chat (v2.0 rework)
TASKS = [
    # Security Analysis (5 buttons)
    ("full_audit", "Full Security Audit",
     "Call the system_audit tool now. This tool runs real commands on "
     "this machine and returns real data. It is NOT simulated.\n\n"
     "After you get the results, analyze EVERY section:\n"
     "- firewall: Are there rules? Did it error? (permission error = "
     "tell user to run sudo autobahn-defender)\n"
     "- apparmor: Is it loaded? What profiles? Any in complain mode?\n"
     "- processes: List any suspicious processes. High CPU? Running "
     "from /tmp? Unusual parent-child?\n"
     "- ports: List every open port with the process name. Flag any "
     "exposed to 0.0.0.0 (all interfaces).\n"
     "- updates: Are there pending updates? List them.\n"
     "- suid: List the suid binaries. Flag any unusual ones.\n"
     "- ssh_config: Is SSH installed? If not, that's fine. If yes, "
     "check PermitRootLogin, PasswordAuthentication.\n"
     "- kernel: What kernel version? Is it current?\n"
     "- auth_log: Any failed login attempts? Unusual sudo activity?\n\n"
     "Also call scan_persistence and check_hosts for additional findings.\n"
     "Call network_security for network threat analysis.\n\n"
     "For each finding, write:\n"
     "[SEVERITY] Title\n"
     "What this means: (name the specific process, port, or config)\n"
     "Why it matters: (what an attacker could do)\n"
     "How to fix it: (exact command)\n\n"
     "Start with SECURITY SCORE: 0-100. Score 100 only if there are "
     "ZERO issues. Deduct -20 per CRITICAL, -10 per HIGH, -5 per MEDIUM, "
     "-2 per LOW. Permission errors count as findings.\n"
     "List findings from most to least severe. Use CRITICAL, HIGH, "
     "MEDIUM, LOW, or INFO.",
     "Security Analysis"),
    ("vuln_check", "Vulnerability Check",
     "Call the vulnerability_scan tool now. This tool checks installed "
     "packages against the OSV.dev CVE database, checks for pending "
     "security updates, and returns combined results.\n\n"
     "Then call read_intel_db with database 'vulnerabilities' and limit 10 "
     "to check stored vulnerability data.\n\n"
     "List each CVE by: CVE number, package name, installed version, "
     "severity, and whether it is actively exploited. For each one, give "
     "the exact command: sudo apt update && sudo apt upgrade <package>\n\n"
     "If you find CVEs in security news articles, call cve_detail for "
     "each one to get full details (affected versions, CVSS score, patch "
     "status). Then check if the affected package is installed.\n\n"
     "If no CVEs are found, say so clearly. Do not make up CVE numbers.",
     "Security Analysis"),
    ("security_news", "Security News & Threats",
     "Step 1: Call the rss_poll tool (no arguments needed). This polls "
     "all RSS feeds for new articles.\n"
     "Step 2: Even if rss_poll returns 0 new articles, STILL call "
     "read_intel_db with database 'security_news' and limit 20. There "
     "may be older articles already stored.\n"
     "Step 3: Call read_intel_db with database 'zero_day_alerts' and "
     "limit 10 to check for zero-day alerts.\n\n"
     "After all tools return, list each article by title and date. For "
     "each article, say what the vulnerability or news is about. Then "
     "check if it affects this system by matching against packages and "
     "services running here. If an article mentions a CVE, call cve_detail "
     "to get full details. If an article is about a vulnerability in "
     "a package you see installed, highlight it as RELEVANT and give "
     "the fix command.\n\n"
     "If all tools return zero articles, say so clearly: 'No security "
     "news articles found. The RSS feeds may not have been polled yet "
     "or no new articles are available.' Do not make up articles.",
     "Security Analysis"),
    ("network_scan", "Network Security",
     "Call the network_security tool now. This tool combines network "
     "connections, threat monitoring, DNS checks, and firewall status "
     "into one result.\n\n"
     "For each finding, report:\n"
     "- The type (suspicious_port, high_risk_port, lateral_movement, "
     "DNS issue, firewall gap)\n"
     "- The remote IP and port (if applicable)\n"
     "- The severity (CRITICAL, HIGH, or MEDIUM)\n"
     "- The indicator description\n"
     "- Whether the connection looks like a legitimate service or a "
     "potential reverse shell / C2 beacon\n\n"
     "If there are critical findings (backdoor ports), recommend immediate "
     "investigation: identify the process with ss -tupn or lsof, and kill "
     "it if malicious.\n\n"
     "If no findings, say: 'No suspicious network connections detected. "
     "All active connections look clean.'",
     "Security Analysis"),
    ("hardening_audit", "System Hardening",
     "Call the hardening_audit tool now. This tool combines kernel sysctl "
     "hardening, SSH config, MAC (AppArmor/SELinux/fail2ban), screen lock, "
     "password policy, and disk encryption checks into one result.\n\n"
     "For each finding, report:\n"
     "[SEVERITY] Setting name\n"
     "Current value: ...\n"
     "Recommended value: ...\n"
     "Why it matters: ...\n"
     "How to fix it: (exact command)\n\n"
     "Focus on: SSH hardening, kernel sysctl settings, AppArmor/SELinux "
     "mode, password policy, disk encryption status. Provide the exact "
     "commands to fix each issue.",
     "Security Analysis"),

    # Investigate (1 button + input fields)
    ("investigate_file", "Investigate File",
     "Call the file_info tool for each file provided. Then call "
     "yara_scan_file for each file. Then call analyze_script for script "
     "files. Then call web_search with the sha256 hash and filename to "
     "check for known malware.\n\n"
     "For each file, report: filename, file type, sha256 hash, YARA "
     "matches (if any), script indicators (if any), and web search "
     "results. Give a verdict: Safe, Suspicious, or Malicious, with "
     "reasoning based on the actual tool data.",
     "Investigate"),
]


# ---------------------------------------------------------------------------
# AI Security Tab
# ---------------------------------------------------------------------------

class AISecurityTab(QWidget):
    """The AI Security tab. Button-driven + chat-driven.

    User controls: ON/OFF toggle, Auto Monitor toggle, Chat input.
    When AI is OFF, no Ollama process runs.
    """

    # Signal to request the main window to start/stop the Ollama sidecar
    toggle_ai_requested = pyqtSignal(bool)  # True = enable, False = disable

    def __init__(self, settings_mgr=None, parent=None):
        super().__init__(parent)
        self.settings_mgr = settings_mgr
        self.ollama = None         # OllamaManager (set by main.py)
        self.worker = None         # current AIWorker
        self._ai_enabled = False
        self._threat_monitor = None  # ThreatMonitor (started when Auto Monitor is on)
        self._files_for_investigation: list[str] = []
        self._ip_for_investigation = ""
        self._pid_for_investigation = ""
        # Chat mode: conversation messages persist across turns
        self._chat_messages: list[dict] = []
        self._in_chat_mode = False
        self._ui_built = True

        # Build UI eagerly but disable paint updates during construction
        # to avoid expensive repaints for each widget added.
        self.setUpdatesEnabled(False)
        try:
            self._build_ui()
        finally:
            self.setUpdatesEnabled(True)

    # --- UI construction ---------------------------------------------

    def _build_ui(self):
        # Ensure AI data dirs exist
        INTEL_DIR.mkdir(parents=True, exist_ok=True)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # SINGLE comprehensive stylesheet on the content widget.
        # This is dramatically faster than calling setStyleSheet() on each of
        # the ~100 individual widgets (Qt parses the sheet once, not 100 times).
        PAGE_QSS = f"""
            QWidget#aiContent {{ background-color: {BG_DARK}; }}
            QLabel {{ color: {TEXT_SECONDARY}; background: transparent; font-size: 13px; }}
            QLabel[sectionTitle="true"] {{
                color: {TEXT_PRIMARY}; background: transparent;
                font-size: 15px; font-weight: bold;
            }}
            QLabel[catTitle="true"] {{
                color: {ACCENT}; background: transparent;
                font-size: 14px; font-weight: bold;
            }}
            QLabel#title {{
                color: {TEXT_PRIMARY}; background: transparent;
                font-size: 22px; font-weight: bold;
            }}
            QLabel#toggleLabel {{
                color: {TEXT_SECONDARY}; background: transparent; font-size: 13px;
            }}
            QLabel#statusLabel {{
                color: {TEXT_SECONDARY}; background-color: {BG_CARD};
                border: 1px solid {BORDER}; border-radius: 8px;
                padding: 10px 14px; font-size: 13px;
            }}
            QLabel#monitorStatus {{
                color: {TEXT_SECONDARY}; background: transparent; font-size: 12px;
            }}
            QLabel#ramWarning {{
                color: {TEXT_SECONDARY}; background: transparent; font-size: 11px;
            }}
            QLabel#reportSummary {{
                color: {TEXT_SECONDARY}; background-color: {BG_CARD};
                border: 1px solid {BORDER}; border-radius: 8px;
                padding: 12px; font-size: 13px;
            }}
            QLabel#tpsLabel {{
                color: {TEXT_SECONDARY}; background: transparent;
                font-size: 12px; font-family: monospace; padding: 2px 8px;
            }}
            QScrollArea {{ border: none; background: transparent; }}
            QScrollArea#dashboardScroll {{
                border: 1px solid {BORDER}; border-radius: 8px;
                background-color: {BG_CARD};
            }}
            QGroupBox {{
                color: {TEXT_PRIMARY}; background: transparent;
                border: 1px solid {BORDER}; border-radius: 8px;
                margin-top: 10px; padding-top: 10px;
                font-size: 14px; font-weight: bold;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin; subcontrol-position: top left;
                padding: 0 8px; color: {TEXT_PRIMARY};
            }}
            QPushButton {{
                background-color: {BG_CARD}; border: 1px solid {BORDER};
                border-radius: 6px; padding: 6px 12px;
                color: {TEXT_PRIMARY}; font-size: 13px;
            }}
            QPushButton:hover {{
                background-color: {ACCENT}; border-color: {ACCENT};
            }}
            QPushButton:pressed {{
                background-color: {ACCENT_HOVER};
            }}
            QPushButton:disabled {{
                background-color: #2A2A2A; color: #666; border-color: #333;
            }}
            QPushButton#stopBtn {{
                background-color: #b71c1c; border-color: #8e0000;
                color: white;
            }}
            QPushButton#stopBtn:hover {{ background-color: #d32f2f; }}
            QPushButton#stopBtn:disabled {{ background-color: #455A64; color: #999; }}
            QLineEdit {{
                background-color: {BG_CARD}; border: 1px solid {BORDER};
                border-radius: 6px; padding: 6px; color: {TEXT_PRIMARY};
            }}
            QLineEdit#chatInput {{
                background-color: #0d0d0d; border: 1px solid {BORDER};
                border-radius: 8px; color: {TEXT_PRIMARY}; padding: 8px 12px;
                font-size: 13px;
            }}
            QLineEdit#chatInput:focus {{ border-color: {ACCENT}; }}
            QLineEdit#chatInput:disabled {{ background-color: #1a1a1a; color: #555; }}
            QTextEdit {{
                background-color: #0d0d0d; border: 1px solid {BORDER};
                border-radius: 8px; color: {TEXT_PRIMARY}; padding: 12px;
                font-family: 'Consolas', 'Monaco', monospace; font-size: 13px;
            }}
            QPlainTextEdit {{
                background-color: #0a0a0a; border: 1px solid {BORDER};
                border-radius: 8px; color: #B0B0B0; padding: 10px;
                font-family: 'Consolas', 'Monaco', monospace; font-size: 12px;
            }}
            QListWidget {{
                background-color: {BG_CARD}; border: 1px dashed {BORDER};
                border-radius: 8px; padding: 6px; color: {TEXT_PRIMARY};
            }}
        """

        # Scroll area wrapping everything
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget()
        content.setObjectName("aiContent")
        content.setStyleSheet(PAGE_QSS)
        content.setSizePolicy(QSizePolicy.Policy.MinimumExpanding, QSizePolicy.Policy.Preferred)
        clayout = QVBoxLayout(content)
        clayout.setContentsMargins(24, 24, 24, 24)
        clayout.setSpacing(16)

        # Header + ON/OFF toggle
        header_row = QHBoxLayout()
        title = QLabel("AI Security")
        title.setObjectName("title")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        header_row.addWidget(title)
        header_row.addStretch()

        self.toggle_label = QLabel("AI Engine: OFF")
        self.toggle_label.setObjectName("toggleLabel")
        header_row.addWidget(self.toggle_label)

        self.ai_toggle = ToggleSwitch("Enable AI Security")
        self.ai_toggle.toggled.connect(self._on_toggle_ai)
        header_row.addWidget(self.ai_toggle)
        clayout.addLayout(header_row)

        # Subtitle / description
        desc = QLabel(
            "Local AI-powered security analysis. The AI runs 100% on your CPU "
            "using LFM2.5-2.6B-Thinking (2.6B params, 90K context, MAX Thinking). "
            "No data leaves your machine. Click a button to trigger a security "
            "analysis workflow. Full input/output is logged for total transparency."
        )
        desc.setWordWrap(True)
        clayout.addWidget(desc)

        # Status bar
        self.status_label = QLabel("AI engine is off. Enable to start the local AI model.")
        self.status_label.setObjectName("statusLabel")
        clayout.addWidget(self.status_label)

        # --- Auto Monitor toggle + RAM warning ---
        monitor_row = QHBoxLayout()
        monitor_row.setSpacing(12)
        self.monitor_toggle = ToggleSwitch("Auto Monitor")
        self.monitor_toggle.setChecked(False)
        self.monitor_toggle.toggled.connect(self._on_toggle_monitor)
        self.monitor_toggle.setEnabled(False)  # enabled only when AI is on
        monitor_row.addWidget(self.monitor_toggle)

        self.monitor_status = QLabel("OFF")
        self.monitor_status.setObjectName("monitorStatus")
        monitor_row.addWidget(self.monitor_status)
        monitor_row.addStretch()

        self.ram_warning = QLabel(
            "⚠ Auto Monitor requires 8GB+ RAM. AI runs locally on CPU."
        )
        self.ram_warning.setObjectName("ramWarning")
        self.ram_warning.setWordWrap(True)
        monitor_row.addWidget(self.ram_warning)
        clayout.addLayout(monitor_row)

        # --- Threat Dashboard ---
        self.dashboard_label = QLabel("Threat Dashboard")
        self.dashboard_label.setProperty("sectionTitle", True)
        clayout.addWidget(self.dashboard_label)

        self.dashboard_scroll = QScrollArea()
        self.dashboard_scroll.setObjectName("dashboardScroll")
        self.dashboard_scroll.setWidgetResizable(True)
        self.dashboard_scroll.setMaximumHeight(200)
        self.dashboard_widget = QWidget()
        self.dashboard_layout = QVBoxLayout(self.dashboard_widget)
        self.dashboard_layout.setContentsMargins(8, 8, 8, 8)
        self.dashboard_layout.setSpacing(6)

        self._dashboard_placeholder = QLabel("No active alerts. System monitoring is off.")
        self._dashboard_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.dashboard_layout.addWidget(self._dashboard_placeholder)
        self.dashboard_scroll.setWidget(self.dashboard_widget)
        clayout.addWidget(self.dashboard_scroll)

        # --- Control panel: buttons by category ---
        controls = QGroupBox("Security Analysis")
        controls_layout = QVBoxLayout(controls)
        controls_layout.setSpacing(12)

        # Group tasks by category
        categories: dict[str, list] = {}
        for task_id, label, prompt, cat in TASKS:
            categories.setdefault(cat, []).append((task_id, label, prompt))

        from PyQt6.QtWidgets import QGridLayout
        for cat_name in ["Security Analysis", "Investigate"]:
            tasks = categories.get(cat_name, [])
            if not tasks:
                continue
            cat_label = QLabel(cat_name)
            cat_label.setProperty("catTitle", True)
            controls_layout.addWidget(cat_label)

            btn_grid = QGridLayout()
            btn_grid.setSpacing(8)
            cols = 4
            for idx, (task_id, label, prompt) in enumerate(tasks):
                btn = QPushButton(label)
                btn.setMinimumHeight(40)
                btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                btn.setEnabled(False)  # disabled until AI is enabled
                btn.clicked.connect(
                    lambda checked, tid=task_id, plabel=label, pprompt=prompt:
                        self._start_task(tid, plabel, pprompt)
                )
                btn_grid.addWidget(btn, idx // cols, idx % cols)
            controls_layout.addLayout(btn_grid)

        # Investigate file drop zone + browse
        file_row = QHBoxLayout()
        file_label = QLabel("Files for investigation:")
        file_row.addWidget(file_label)
        self.file_list = QListWidget()
        self.file_list.setMaximumHeight(70)
        self.file_list.setAcceptDrops(True)
        self.file_list.setDragDropMode(QListWidget.DragDropMode.DropOnly)
        self.file_list.dragEnterEvent = self._on_drag_enter
        self.file_list.dropEvent = self._on_drop
        self.file_list.dragMoveEvent = self._on_drag_move
        file_row.addWidget(self.file_list, 1)

        browse_btn = QPushButton("Browse")
        browse_btn.setMinimumHeight(36)
        browse_btn.setEnabled(False)
        browse_btn.clicked.connect(self._browse_file)
        self._browse_btn = browse_btn
        file_row.addWidget(browse_btn)
        controls_layout.addLayout(file_row)

        # IP/domain input
        ip_row = QHBoxLayout()
        ip_label = QLabel("IP / Domain:")
        ip_row.addWidget(ip_label)
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("e.g. 8.8.8.8 or example.com")
        ip_row.addWidget(self.ip_input, 1)
        controls_layout.addLayout(ip_row)

        # PID input
        pid_row = QHBoxLayout()
        pid_label = QLabel("Process PID:")
        pid_row.addWidget(pid_label)
        self.pid_input = QLineEdit()
        self.pid_input.setPlaceholderText("e.g. 1234")
        pid_row.addWidget(self.pid_input, 1)
        controls_layout.addLayout(pid_row)

        clayout.addWidget(controls)

        # --- AI output panel ---
        output_label = QLabel("AI Output")
        output_label.setProperty("sectionTitle", True)
        clayout.addWidget(output_label)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setMinimumHeight(280)
        self.output.append(
            '<span style="color:#888">AI output will appear here when you click a button above.</span>'
        )
        clayout.addWidget(self.output, 1)

        # tok/s counter + status row below the output
        counter_row = QHBoxLayout()
        self.tps_label = QLabel("")
        self.tps_label.setObjectName("tpsLabel")
        counter_row.addWidget(self.tps_label)
        counter_row.addStretch()
        clayout.addLayout(counter_row)

        # --- Chat input (v2.0) ---
        chat_label = QLabel("Ask the AI")
        chat_label.setProperty("sectionTitle", True)
        clayout.addWidget(chat_label)

        chat_row = QHBoxLayout()
        self.chat_input = QLineEdit()
        self.chat_input.setObjectName("chatInput")
        self.chat_input.setPlaceholderText(
            "Ask a question about your PC, security, or vulnerabilities... "
            "(requires AI enabled)"
        )
        self.chat_input.setMinimumHeight(38)
        self.chat_input.returnPressed.connect(self._send_chat)
        self.chat_input.setEnabled(False)
        chat_row.addWidget(self.chat_input, 1)

        self.chat_send_btn = QPushButton("Send")
        self.chat_send_btn.setMinimumHeight(38)
        self.chat_send_btn.setEnabled(False)
        self.chat_send_btn.clicked.connect(self._send_chat)
        chat_row.addWidget(self.chat_send_btn)

        self.chat_clear_btn = QPushButton("Clear Chat")
        self.chat_clear_btn.setMinimumHeight(38)
        self.chat_clear_btn.setEnabled(False)
        self.chat_clear_btn.setToolTip("Clear conversation history and start fresh")
        self.chat_clear_btn.clicked.connect(self._clear_chat)
        chat_row.addWidget(self.chat_clear_btn)

        clayout.addLayout(chat_row)

        # --- Full I/O Log panel (transparency) ---
        io_label = QLabel("Full I/O Log (untruncated -- what goes in and what comes out)")
        io_label.setProperty("sectionTitle", True)
        clayout.addWidget(io_label)

        self.io_log = QPlainTextEdit()
        self.io_log.setReadOnly(True)
        self.io_log.setMaximumHeight(200)
        self.io_log.setPlaceholderText("Full untruncated model input and output will appear here...")
        clayout.addWidget(self.io_log)

        # --- Report summary ---
        report_row = QHBoxLayout()
        self.report_summary = QLabel("No report generated yet.")
        self.report_summary.setObjectName("reportSummary")
        self.report_summary.setWordWrap(True)
        report_row.addWidget(self.report_summary, 1)

        save_btn = QPushButton("Save Report")
        save_btn.setMinimumHeight(36)
        save_btn.clicked.connect(self._save_report)
        report_row.addWidget(save_btn)

        clear_btn = QPushButton("Clear Output")
        clear_btn.setMinimumHeight(36)
        clear_btn.clicked.connect(self._clear_output)
        report_row.addWidget(clear_btn)

        # Stop button -- cancels the current AI task
        self.stop_btn = QPushButton("Stop AI")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setMinimumHeight(36)
        self.stop_btn.setEnabled(False)  # enabled only when a task is running
        self.stop_btn.clicked.connect(self._stop_ai_task)
        report_row.addWidget(self.stop_btn)
        clayout.addLayout(report_row)

        scroll.setWidget(content)
        layout.addWidget(scroll)

        # Store references to all task buttons for enabling/disabling
        self._task_buttons = controls.findChildren(QPushButton)

    # --- AI toggle ---------------------------------------------------

    def _on_toggle_ai(self, enabled: bool):
        """Handle the ON/OFF toggle. Requests main.py to start/stop Ollama."""
        self._ai_enabled = enabled
        # Update the switch label: "Disable" when ON, "Enable" when OFF
        self.ai_toggle._label.setText("Disable AI Security" if enabled else "Enable AI Security")
        self.toggle_ai_requested.emit(enabled)

        if enabled:
            self.toggle_label.setText("AI Engine: starting...")
            self.toggle_label.setStyleSheet(
                f"color: #FFB74D; background: transparent; font-size: 13px; font-weight: bold;"
            )
            self.status_label.setText("Starting local AI engine (first run may take a minute)...")
        else:
            self.toggle_label.setText("AI Engine: OFF")
            self.toggle_label.setStyleSheet(
                f"color: {TEXT_SECONDARY}; background: transparent; font-size: 13px;"
            )
            self.status_label.setText("AI engine is off. Enable to start the local AI model.")
            self._set_buttons_enabled(False)

    def on_ollama_started(self, success: bool):
        """Called by main.py when Ollama startup completes."""
        if success:
            self.toggle_label.setText("AI Engine: ON")
            self.toggle_label.setStyleSheet(
                f"color: {SUCCESS}; background: transparent; font-size: 13px; font-weight: bold;"
            )
            self.status_label.setText(
                "AI engine is ready. Click a button above to start a security analysis."
            )
            self._set_buttons_enabled(True)
        else:
            self.toggle_label.setText("AI Engine: FAILED")
            self.toggle_label.setStyleSheet(
                f"color: {DANGER}; background: transparent; font-size: 13px; font-weight: bold;"
            )
            self.status_label.setText(
                "Failed to start AI engine. Check that Ollama is installed and the "
                "model is available. See the AI output panel for details."
            )
            self.ai_toggle.setCheckedSilent(False)

    def _set_buttons_enabled(self, enabled: bool):
        for btn in self._task_buttons:
            # Don't enable Browse until AI is on
            if btn.text() == "Browse":
                btn.setEnabled(enabled)
            else:
                btn.setEnabled(enabled)
        # Enable/disable the Auto Monitor toggle too
        self.monitor_toggle.setEnabled(enabled)
        # Enable/disable chat input
        self.chat_input.setEnabled(enabled)
        self.chat_send_btn.setEnabled(enabled)
        self.chat_clear_btn.setEnabled(enabled)
        if not enabled:
            # If AI is turned off, also turn off the monitor
            self.monitor_toggle.setChecked(False)

    # --- Auto Monitor --------------------------------------------------

    def _on_toggle_monitor(self, enabled: bool):
        """Handle the Auto Monitor ON/OFF toggle."""
        if enabled and not self._ai_enabled:
            QMessageBox.warning(
                self, "Auto Monitor",
                "AI Security must be enabled first before turning on Auto Monitor.\n\n"
                "Turn on the AI engine toggle above, wait for it to start, "
                "then enable Auto Monitor."
            )
            self.monitor_toggle.setChecked(False)
            return

        if enabled:
            # Check RAM
            try:
                meminfo = Path("/proc/meminfo").read_text()
                mem_total_kb = int(re.search(r"MemTotal:\s+(\d+)", meminfo).group(1))
                mem_total_gb = mem_total_kb / 1024 / 1024
                if mem_total_gb < 8:
                    QMessageBox.warning(
                        self, "Auto Monitor",
                        f"WARNING: This system has {mem_total_gb:.1f}GB RAM.\n"
                        "Auto Monitor requires at least 8GB RAM to run the AI "
                        "engine alongside your normal applications.\n\n"
                        "You can still enable it, but your system may become "
                        "slow or unresponsive during AI analysis."
                    )
            except Exception:
                pass

            self.monitor_status.setText("Monitoring")
            self.monitor_status.setStyleSheet(
                f"color: {SUCCESS}; background: transparent; font-size: 12px; font-weight: bold;"
            )
            self._start_auto_monitor()
        else:
            self.monitor_status.setText("OFF")
            self.monitor_status.setStyleSheet(
                f"color: {TEXT_SECONDARY}; background: transparent; font-size: 12px;"
            )
            self._stop_auto_monitor()

    def _start_auto_monitor(self):
        """Start the background threat monitor."""
        from ai.threat_monitor import ThreatMonitor
        self._threat_monitor = ThreatMonitor(self.ollama)
        self._threat_monitor.alert_created.connect(self._on_alert_created)
        self._threat_monitor.monitor_status.connect(self._on_monitor_status)
        self._threat_monitor.scan_started.connect(self._on_monitor_scan_started)
        self._threat_monitor.scan_finished.connect(self._on_monitor_scan_finished)
        self._threat_monitor.start()
        self._refresh_dashboard()

    def _stop_auto_monitor(self):
        """Stop the background threat monitor."""
        if hasattr(self, "_threat_monitor") and self._threat_monitor:
            self._threat_monitor.stop()
            self._threat_monitor = None
        self._dashboard_placeholder.setText("No active alerts. Auto Monitor is off.")
        self._dashboard_placeholder.show()
        # Clear dashboard cards
        while self.dashboard_layout.count() > 1:
            item = self.dashboard_layout.takeAt(1)
            if item.widget():
                item.widget().deleteLater()

    def _on_alert_created(self, alert_json: str):
        """Called when the threat monitor creates a new alert."""
        try:
            alert = json.loads(alert_json)
        except Exception:
            return
        self._refresh_dashboard()
        severity = alert.get("severity", "MEDIUM")
        if severity in ("CRITICAL", "HIGH"):
            QMessageBox.warning(
                self, "Security Alert",
                f"{severity}: {alert.get('title', 'Unknown')}\n\n"
                f"Affected: {alert.get('affected_package', 'N/A')}\n"
                f"Recommended action:\n{alert.get('recommended_action', 'N/A')}\n\n"
                "See the Threat Dashboard for details."
            )

    def _on_monitor_status(self, text: str):
        """Update the monitor status label."""
        self.monitor_status.setText(text)

    def _on_monitor_scan_started(self):
        """Called when a monitoring scan begins."""
        self._append_output("[MONITOR] Starting automated threat scan...\n", color="#FFB74D")
        self.monitor_status.setText("Scanning...")

    def _on_monitor_scan_finished(self):
        """Called when a monitoring scan completes."""
        self._append_output("[MONITOR] Scan complete. Checking for alerts...\n", color="#FFB74D")
        self.monitor_status.setText("Monitoring")
        self._refresh_dashboard()

    def _refresh_dashboard(self):
        """Refresh the Threat Dashboard with current alerts."""
        from ai.alerts import load_alerts

        # Clear existing dashboard items
        while self.dashboard_layout.count() > 0:
            item = self.dashboard_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        alerts = load_alerts(active_only=True)
        if not alerts:
            self._dashboard_placeholder = QLabel("No active alerts. System is clean.")
            self._dashboard_placeholder.setStyleSheet(
                f"color: {SUCCESS}; background: transparent; font-size: 13px;"
            )
            self._dashboard_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.dashboard_layout.addWidget(self._dashboard_placeholder)
            return

        for alert in alerts:
            card = self._create_alert_card(alert)
            self.dashboard_layout.addWidget(card)
        self.dashboard_layout.addStretch()

    def _create_alert_card(self, alert: dict) -> QWidget:
        """Create a single alert card widget for the dashboard."""
        card = QFrame()
        severity = alert.get("severity", "MEDIUM")
        border_colors = {
            "CRITICAL": "#CF6679",
            "HIGH": "#FFB74D",
            "MEDIUM": "#FFE082",
        }
        border_color = border_colors.get(severity, BORDER)
        card.setStyleSheet(
            f"QFrame {{ background-color: {BG_CARD}; "
            f"border-left: 4px solid {border_color}; "
            f"border-radius: 6px; padding: 8px; }}"
        )
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(4)

        # Title row
        title_label = QLabel(f"[{severity}] {alert.get('title', 'Unknown')}")
        title_label.setStyleSheet(
            f"color: {TEXT_PRIMARY}; background: transparent; font-size: 13px; font-weight: bold;"
        )
        title_label.setWordWrap(True)
        card_layout.addWidget(title_label)

        # Details
        details = ""
        if alert.get("affected_package"):
            details += f"Affected: {alert['affected_package']}"
            if alert.get("installed_version"):
                details += f" {alert['installed_version']} (installed)"
            details += "\n"
        if alert.get("recommended_action"):
            details += f"Fix: {alert['recommended_action']}"
        if alert.get("source"):
            details += f"\nSource: {alert['source']}"
        if details:
            details_label = QLabel(details)
            details_label.setStyleSheet(
                f"color: {TEXT_SECONDARY}; background: transparent; font-size: 12px;"
            )
            details_label.setWordWrap(True)
            card_layout.addWidget(details_label)

        # Action buttons row
        btn_row = QHBoxLayout()

        copy_btn = QPushButton("Copy Command")
        copy_btn.setFixedHeight(30)
        copy_btn.setStyleSheet(
            f"QPushButton {{ background-color: #2E2E2E; border: 1px solid {BORDER}; "
            f"border-radius: 4px; color: {TEXT_PRIMARY}; padding: 4px 12px; font-size: 12px; }}"
            f"QPushButton:hover {{ background-color: #3A3A3A; }}"
        )
        action = alert.get("recommended_action", "")
        copy_btn.clicked.connect(lambda checked, cmd=action: self._copy_to_clipboard(cmd))
        btn_row.addWidget(copy_btn)

        # Stop Service button (pkexec) for zero-day mitigations
        alt_action = alert.get("alternative_action", "")
        if alt_action and "systemctl" in alt_action:
            stop_btn = QPushButton("Stop Service (pkexec)")
            stop_btn.setFixedHeight(30)
            stop_btn.setStyleSheet(
                f"QPushButton {{ background-color: #b71c1c; border: 1px solid #8e0000; "
                f"border-radius: 4px; color: white; padding: 4px 12px; font-size: 12px; }}"
                f"QPushButton:hover {{ background-color: #d32f2f; }}"
            )
            stop_btn.clicked.connect(
                lambda checked, cmd=alt_action: self._run_pkexec_command(cmd)
            )
            btn_row.addWidget(stop_btn)

        dismiss_btn = QPushButton("Dismiss")
        dismiss_btn.setFixedHeight(30)
        dismiss_btn.setStyleSheet(
            f"QPushButton {{ background-color: #2E2E2E; border: 1px solid {BORDER}; "
            f"border-radius: 4px; color: {TEXT_SECONDARY}; padding: 4px 12px; font-size: 12px; }}"
            f"QPushButton:hover {{ background-color: #3A3A3A; }}"
        )
        alert_id = alert.get("id", "")
        dismiss_btn.clicked.connect(
            lambda checked, aid=alert_id: self._dismiss_alert(aid)
        )
        btn_row.addWidget(dismiss_btn)

        btn_row.addStretch()
        card_layout.addLayout(btn_row)
        return card

    def _copy_to_clipboard(self, text: str):
        """Copy the given text to the system clipboard."""
        from PyQt6.QtWidgets import QApplication
        cb = QApplication.clipboard()
        cb.setText(text)
        self._append_output(f"[COPIED] {text}\n", color="#69F0AE")

    def _run_pkexec_command(self, command: str):
        """Run a system command via pkexec (polkit password prompt).

        This pops up the system's native polkit password dialog. The user
        must enter their password each time -- no silent auto-execution.
        """
        reply = QMessageBox.question(
            self, "Execute System Command",
            f"The following command will be executed with root privileges:\n\n"
            f"{command}\n\n"
            "You will be prompted for your password. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        # Extract the actual command (strip "sudo " prefix if present)
        cmd = command.strip()
        if cmd.startswith("sudo "):
            cmd = cmd[5:]

        try:
            result = subprocess.run(
                ["pkexec", "sh", "-c", cmd],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0:
                self._append_output(
                    f"[EXEC] Command completed successfully: {cmd}\n",
                    color="#69F0AE",
                )
                self._refresh_dashboard()
            else:
                self._append_output(
                    f"[EXEC] Command failed (exit {result.returncode}): {result.stderr}\n",
                    color="#EF5350",
                )
        except subprocess.TimeoutExpired:
            self._append_output("[EXEC] Command timed out.\n", color="#EF5350")
        except Exception as e:
            self._append_output(f"[EXEC] Error: {e}\n", color="#EF5350")

    def _dismiss_alert(self, alert_id: str):
        """Dismiss an alert from the dashboard."""
        from ai.alerts import dismiss_alert
        dismiss_alert(alert_id)
        self._refresh_dashboard()

    # --- Task execution ----------------------------------------------

    def _start_task(self, task_id: str, label: str, prompt: str):
        if not self.ollama or not self.ollama.is_ready:
            QMessageBox.warning(self, "AI Security", "AI engine is not running.")
            return
        if self.worker is not None:
            QMessageBox.warning(self, "AI Security",
                                "An AI analysis is already running. Wait for it to finish.")
            return

        # Gather extra context based on task type
        extra_context = ""
        if task_id == "investigate_file":
            files = [self.file_list.item(i).text() for i in range(self.file_list.count())]
            if not files:
                QMessageBox.information(self, "AI Security",
                                        "Add files to investigate by dragging them into "
                                        "the file list or clicking Browse.")
                return
            self._files_for_investigation = files
            extra_context = "Files to investigate:\n" + "\n".join(files)
        elif task_id == "investigate_ip":
            ip = self.ip_input.text().strip()
            if not ip:
                QMessageBox.information(self, "AI Security",
                                        "Enter an IP address or domain to investigate.")
                return
            self._ip_for_investigation = ip
            extra_context = f"IP/Domain to investigate: {ip}"
        elif task_id == "investigate_process":
            pid = self.pid_input.text().strip()
            if not pid or not pid.isdigit():
                QMessageBox.information(self, "AI Security",
                                        "Enter a numeric process PID to investigate.")
                return
            self._pid_for_investigation = pid
            extra_context = f"Process PID to investigate: {pid}"

        # Clear output and start
        self.output.clear()
        self._append_output(f"[AI] Starting: {label}\n", color="#2962FF")
        self._append_output(f"[AI] {prompt[:200]}...\n", color="#888")

        self.worker = AIWorker(
            self.ollama, task_id, prompt, extra_context=extra_context
        )
        self.worker.token.connect(self._on_token)
        self.worker.tool_call.connect(self._on_tool_call)
        self.worker.tool_result.connect(self._on_tool_result)
        self.worker.warning.connect(self._on_warning)
        self.worker.finished_result.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self.worker.status.connect(self._on_status)
        self.worker.full_io.connect(self._on_full_io)
        # Enable Stop button while task is running
        self._on_task_started()
        self.worker.finished_result.connect(self._on_task_finished)
        self.worker.error.connect(self._on_task_finished)
        # QThread.finished fires AFTER run() returns, including model unload.
        # This is the true "worker is done" signal.
        self.worker.finished.connect(self._on_worker_done)
        self.worker.start()

    # --- Worker signal handlers --------------------------------------

    def _on_token(self, text):
        self._append_output(text, color="#90CAF9")

    def _on_tool_call(self, text):
        self._append_output("\n" + text + "\n", color="#69F0AE")

    def _on_tool_result(self, text):
        self._append_output(text + "\n", color="#BDBDBD")

    def _on_warning(self, text):
        self._append_output("[WARNING] " + text + "\n", color="#FFB74D")

    def _on_status(self, text):
        self.status_label.setText(f"Status: {text}")
        # Also update the tok/s counter if the message contains tok/s info
        if "tok/s" in text:
            self.tps_label.setText(text)

    def _on_full_io(self, text):
        """Display full untruncated I/O log for transparency."""
        self.io_log.appendPlainText(text)

    def _on_error(self, text):
        self._append_output("[ERROR] " + text + "\n", color="#EF5350")
        self.status_label.setText("Error: " + text)
        # Re-enable chat UI if in chat mode (error during chat should not lock UI)
        if self._in_chat_mode:
            self.chat_input.setEnabled(True)
            self.chat_send_btn.setEnabled(True)
            self.chat_clear_btn.setEnabled(True)
            self._in_chat_mode = False
            self.stop_btn.setEnabled(False)
            if self._ai_enabled:
                self._set_buttons_enabled(True)

    def _on_finished(self, text):
        if text and text.strip():
            self._append_output("\n[AI] Analysis complete.\n", color="#2962FF")
            self._append_output(text + "\n", color="#E0E0E0")
        else:
            self._append_output("\n[AI] No analysis output was produced. See the I/O log for tool call details.\n", color="#FFB74D")
        self.status_label.setText("Analysis complete.")
        # Save full results to a log file so the user has a complete record
        self._save_full_log(text)
        # If this was a report generation, save it as HTML
        if "report" in text.lower() or "score" in text.lower() or "findings" in text.lower():
            self._save_report_from_plain_text(text)

    # --- File drag-drop ----------------------------------------------

    def _on_drag_enter(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def _on_drag_move(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def _on_drop(self, event: QDropEvent):
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if path and Path(path).is_file():
                # Avoid duplicates
                existing = [self.file_list.item(i).text() for i in range(self.file_list.count())]
                if path not in existing:
                    self.file_list.addItem(path)

    def _browse_file(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Select file(s) to investigate")
        for p in paths:
            existing = [self.file_list.item(i).text() for i in range(self.file_list.count())]
            if p not in existing:
                self.file_list.addItem(p)

    # --- Output helpers ----------------------------------------------

    def _append_output(self, text: str, color: str = "#E0E0E0"):
        """Append text to the output panel.

        Uses insertPlainText for streaming tokens (no auto-newline) and
        append() for block messages (with auto-newline). We detect which
        to use based on whether the text starts with \n (block message).
        """
        if text.startswith("\n") or text.endswith("\n"):
            # Block message -- use append (adds newline)
            safe = (text.replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                        .replace("\n", "<br>"))
            self.output.append(f'<span style="color:{color}">{safe}</span>')
        else:
            # Streaming token -- insert at cursor position, no auto-newline
            cursor = self.output.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            cursor.insertText(text)

    def _clear_output(self):
        self.output.clear()
        self.io_log.clear()
        self.report_summary.setText("No report generated yet.")

    def _stop_ai_task(self):
        """Cancel the current AI analysis task."""
        if self.worker is not None:
            self.worker.cancel()
            self.status_label.setText("Stopping AI task...")
            self._append_output("\n[USER] Task stop requested. Finishing current step...\n", color="#FFB74D")

    def _on_task_started(self):
        """Called when an AI task starts -- enable the Stop button."""
        self.stop_btn.setEnabled(True)

    def _on_task_finished(self):
        """Called when an AI task's result/error signal fires."""
        self.stop_btn.setEnabled(False)

    def _on_worker_done(self):
        """Called when the QThread truly finishes (after run() returns,
        including model unload). Clears the worker reference so new
        tasks can start immediately."""
        if self.worker:
            self.worker = None
        # Re-enable buttons if AI is still on
        if self._ai_enabled and self.ollama and self.ollama.is_ready:
            self._set_buttons_enabled(True)
            self.chat_input.setEnabled(True)
            self.chat_send_btn.setEnabled(True)
            self.chat_clear_btn.setEnabled(True)
            self.status_label.setText(
                "AI engine is ready. Click a button or type a question below."
            )

    # --- Chat mode (v2.0) --------------------------------------------

    def _send_chat(self):
        """Send the chat input text to the AI as a new conversation turn."""
        text = self.chat_input.text().strip()
        if not text:
            return
        if not self.ollama or not self.ollama.is_ready:
            QMessageBox.warning(self, "Chat", "AI engine is not ready yet. Wait for it to start.")
            return
        if self.worker is not None:
            QMessageBox.warning(self, "Chat", "AI is still working. Wait for it to finish or click Stop AI.")
            return

        # Display the user's question in the output panel
        self._append_output(f"\n[USER] {text}\n", color="#4FC3F7")

        # First chat turn: start with system prompt + user message
        # Subsequent turns: append to existing conversation
        if not self._chat_messages:
            # First turn: initialize with system prompt
            from ai.worker import SYSTEM_PROMPT
            self._chat_messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
            ]

        # Add the user's message
        self._chat_messages.append({"role": "user", "content": text})

        # Clear the input field
        self.chat_input.clear()

        # Create the worker in chat mode
        # Give it access to ALL tools (not just a task subset) since
        # we don't know what the user will ask about
        self._in_chat_mode = True
        self.worker = AIWorker(
            self.ollama,
            task_id="chat",
            user_prompt=text,
            is_chat=True,
            parent=self,
        )
        # Pre-load the conversation messages into the worker
        self.worker._messages = list(self._chat_messages)  # copy

        # Wire signals
        self.worker.token.connect(self._on_token)
        self.worker.tool_call.connect(self._on_tool_call)
        self.worker.tool_result.connect(self._on_tool_result)
        self.worker.warning.connect(self._on_warning)
        self.worker.status.connect(self._on_status)
        self.worker.error.connect(self._on_error)
        self.worker.finished_result.connect(self._on_chat_finished)
        self.worker.finished_result.connect(self._on_task_finished)
        self.worker.error.connect(self._on_task_finished)
        self.worker.full_io.connect(self._on_full_io)
        self.worker.finished.connect(self._on_worker_done)

        # Enable stop button
        self.stop_btn.setEnabled(True)
        self._set_buttons_enabled(False)
        # Keep chat input enabled so user can queue next question? No --
        # disable until this turn finishes
        self.chat_input.setEnabled(False)
        self.chat_send_btn.setEnabled(False)

        self.status_label.setText("AI is thinking...")
        self.worker.start()

    def _on_chat_finished(self, final_text: str):
        """Called when a chat turn finishes. Save the response to conversation history."""
        if not final_text or not final_text.strip():
            final_text = "(No response was generated. The model may have called tools without producing a final answer.)"
        # Append the assistant's final response to the conversation
        self._chat_messages.append({"role": "assistant", "content": final_text})

        # Display the response
        self._append_output(f"\n[AI] {final_text}\n", color="#81C784")

        # Re-enable chat input
        self.chat_input.setEnabled(True)
        self.chat_send_btn.setEnabled(True)
        self.chat_clear_btn.setEnabled(True)
        self._in_chat_mode = False
        self.stop_btn.setEnabled(False)

        # Re-enable task buttons
        if self._ai_enabled:
            self._set_buttons_enabled(True)

        # Update status
        self.status_label.setText("AI idle. Ready for questions or tasks.")
        self.tps_label.setText("")

        # Auto-compress chat history if it's getting long
        # (keep last 20 messages to prevent unbounded growth)
        if len(self._chat_messages) > 42:  # system + 20 turns * 2 messages
            # Keep system prompt + last 20 messages
            system_msg = self._chat_messages[0]
            recent = self._chat_messages[-20:]
            self._chat_messages = [system_msg] + recent
            self._append_output(
                "\n[SYSTEM] Chat history compressed to last 20 messages.\n",
                color="#FFB74D"
            )

    def _clear_chat(self):
        """Clear the chat conversation history."""
        self._chat_messages = []
        self._in_chat_mode = False
        self._append_output("\n[SYSTEM] Chat history cleared.\n", color="#FFB74D")
        self.chat_input.clear()

    # --- Report saving -----------------------------------------------

    def _save_full_log(self, final_text: str):
        """Save the complete AI analysis output to a timestamped log file.

        The log is formatted in a human-readable way with clear section
        headers, tool call results, and the final analysis.
        """
        try:
            from ai import REPORTS_DIR as default_reports
            report_dir = self.settings_mgr.get_ai_report_dir() if self.settings_mgr else str(default_reports)
            Path(report_dir).mkdir(parents=True, exist_ok=True)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = Path(report_dir) / f"ai_analysis_{ts}.log"
            # Get the full output panel text (untruncated)
            full_output = self.output.toPlainText()
            log_content = (
                "=" * 70 + "\n"
                f"  AUTOBAHN DEFENDER v2.0 -- AI SECURITY ANALYSIS REPORT\n"
                f"  Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"  Host: {os.uname().nodename}\n"
                f"  OS: {' '.join(os.uname())}\n"
                "=" * 70 + "\n\n"
                f"--- AI Activity Log (tool calls and results) ---\n\n"
                f"{full_output}\n\n"
                "=" * 70 + "\n"
                f"--- Full I/O Log (untruncated model input/output) ---\n"
                "=" * 70 + "\n\n"
                f"{self.io_log.toPlainText()}\n\n"
                "=" * 70 + "\n"
                f"--- FINAL ANALYSIS ---\n"
                "=" * 70 + "\n\n"
                f"{final_text}\n\n"
                "=" * 70 + "\n"
                f"  End of report\n"
                "=" * 70 + "\n"
            )
            filename.write_text(log_content, encoding="utf-8")
            self.report_summary.setText(
                f"Full log saved: {filename.name}"
            )
        except Exception as e:
            log.warning("Failed to save full log: %s", e)

    def _save_report_from_plain_text(self, text: str):
        """Convert a plain-English AI report into the HTML template.

        The AI now outputs reports in plain English with this format:
          SECURITY SCORE: 75
          SUMMARY: ...
          [CRITICAL] Title
          What this means: ...
          Why it matters: ...
          How to fix it: ...

        We parse this text and inject it into the HTML template as
        paragraph-formatted HTML (not a JSON object).
        """
        template_path = Path(__file__).resolve().parent.parent / "templates" / "report_template.html"
        if not template_path.exists():
            return
        try:
            template = template_path.read_text(encoding="utf-8")

            # Parse the plain-English report text
            score = "N/A"
            score_class = "score-warn"
            summary = ""
            findings_html = ""

            # Extract score
            score_match = re.search(r'(?:SECURITY\s+SCORE|Score)\s*[:=]\s*(\d+)', text, re.IGNORECASE)
            if score_match:
                score = score_match.group(1)
                try:
                    s = int(score)
                    if s >= 80:
                        score_class = "score-good"
                    elif s >= 50:
                        score_class = "score-warn"
                    else:
                        score_class = "score-bad"
                except ValueError:
                    pass

            # Extract summary
            summary_match = re.search(
                r'(?:SUMMARY|Executive Summary)\s*[:=]?\s*\n(.*?)(?=\n\s*(?:FINDINGS|\[|\d+\.)|\Z)',
                text, re.IGNORECASE | re.DOTALL,
            )
            if summary_match:
                summary = summary_match.group(1).strip()

            # Extract findings -- each starts with [SEVERITY] or SEVERITY:
            # Build HTML paragraphs for each finding
            findings = []
            # Pattern: [SEVERITY] Title followed by What/Why/How lines
            finding_pattern = re.compile(
                r'\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+?)(?=\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\]|\Z)',
                re.DOTALL | re.IGNORECASE,
            )
            for m in finding_pattern.finditer(text):
                severity = m.group(1).upper()
                body = m.group(2).strip()
                # Extract title (first line), what/why/how
                lines = body.split('\n')
                title = lines[0].strip() if lines else "Finding"
                what = ""
                why = ""
                how = ""
                current = None
                for line in lines[1:]:
                    line = line.strip()
                    if not line:
                        continue
                    lower = line.lower()
                    if lower.startswith("what this means") or lower.startswith("what:"):
                        current = "what"
                        what = line.split(":", 1)[-1].strip() if ":" in line else ""
                    elif lower.startswith("why it matters") or lower.startswith("why:"):
                        current = "why"
                        why = line.split(":", 1)[-1].strip() if ":" in line else ""
                    elif lower.startswith("how to fix") or lower.startswith("how:"):
                        current = "how"
                        how = line.split(":", 1)[-1].strip() if ":" in line else ""
                    elif current:
                        # Continuation of the current field
                        if current == "what":
                            what += " " + line
                        elif current == "why":
                            why += " " + line
                        elif current == "how":
                            how += " " + line

                findings.append({
                    "severity": severity,
                    "title": title,
                    "what": what,
                    "why": why,
                    "how": how,
                })

            # Also try pattern without brackets: "CRITICAL: Title"
            if not findings:
                finding_pattern2 = re.compile(
                    r'(?:^|\n)\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*[:=]\s*(.+?)(?=\n\s*(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*[:=]|\Z)',
                    re.DOTALL | re.IGNORECASE,
                )
                for m in finding_pattern2.finditer(text):
                    severity = m.group(1).upper()
                    body = m.group(2).strip()
                    lines = body.split('\n')
                    title = lines[0].strip() if lines else "Finding"
                    what = ""
                    why = ""
                    how = ""
                    current = None
                    for line in lines[1:]:
                        line = line.strip()
                        if not line:
                            continue
                        lower = line.lower()
                        if lower.startswith("what this means") or lower.startswith("what:"):
                            current = "what"
                            what = line.split(":", 1)[-1].strip() if ":" in line else ""
                        elif lower.startswith("why it matters") or lower.startswith("why:"):
                            current = "why"
                            why = line.split(":", 1)[-1].strip() if ":" in line else ""
                        elif lower.startswith("how to fix") or lower.startswith("how:"):
                            current = "how"
                            how = line.split(":", 1)[-1].strip() if ":" in line else ""
                        elif current:
                            if current == "what":
                                what += " " + line
                            elif current == "why":
                                why += " " + line
                            elif current == "how":
                                how += " " + line
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "what": what,
                        "why": why,
                        "how": how,
                    })

            # Build findings HTML -- each finding as a paragraph block
            if findings:
                sev_class = {
                    "CRITICAL": "sev-critical",
                    "HIGH": "sev-high",
                    "MEDIUM": "sev-medium",
                    "LOW": "sev-low",
                    "INFO": "sev-info",
                }
                findings_html = '<div class="findings-list">\n'
                for f in findings:
                    sev = f["severity"]
                    cls = sev_class.get(sev, "sev-info")
                    findings_html += (
                        f'  <div class="finding">\n'
                        f'    <div class="finding-header">\n'
                        f'      <span class="sev {cls}">{sev}</span>\n'
                        f'      <span class="finding-title">{_esc(f["title"])}</span>\n'
                        f'    </div>\n'
                        f'    <p class="finding-desc"><strong>What this means:</strong> {_esc(f["what"])}</p>\n'
                        f'    <p class="finding-desc"><strong>Why it matters:</strong> {_esc(f["why"])}</p>\n'
                        f'    <p class="finding-desc"><strong>How to fix it:</strong> '
                        f'<span class="recommendation">{_esc(f["how"])}</span></p>\n'
                        f'  </div>\n'
                    )
                findings_html += '</div>\n'
            else:
                # No structured findings found -- just put the whole text in
                findings_html = f'<div class="summary">{_esc(text)}</div>'

            # Build the final HTML
            import html as _html2
            hostname = os.uname().nodename
            date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            os_info = " ".join(os.uname())

            # Escape all values for HTML safety
            data = {
                "hostname": _esc(hostname),
                "date": _esc(date_str),
                "os_info": _esc(os_info),
                "score": _esc(str(score)),
                "score_class": score_class,
                "score_trend": "",
                "executive_summary": _esc(summary) if summary else _esc("See findings below."),
                "findings_table": findings_html,
                "timeline": '<div class="timeline-item"><span class="timeline-date">' + _esc(date_str) + '</span> Report generated</div>',
            }

            html_out = template.format_map(_SafeDict(data))
            # Save
            REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = REPORTS_DIR / f"security_report_{ts}.html"
            filename.write_text(html_out, encoding="utf-8")
            self.report_summary.setText(
                f"Report saved: {filename.name} | Score: {score}/100"
            )
        except Exception as e:
            log.warning("Failed to save report: %s", e)

    def _save_report(self):
        """Manual save -- opens a file dialog to save the current output."""
        if not self.output.toPlainText().strip():
            QMessageBox.information(self, "AI Security", "Nothing to save yet.")
            return
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"autobahn_ai_report_{ts}.html"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", default_name, "HTML Files (*.html);;Text Files (*.txt)"
        )
        if not path:
            return
        try:
            if path.endswith(".html"):
                # SECURITY: HTML-escape all content to prevent stored XSS
                # from model output or tool results that may contain
                # prompt-injected <script> tags
                import html as _html
                safe = _html.escape(self.output.toPlainText(), quote=False)
                content = (
                    "<html><body style='font-family:monospace;background:#121212;color:#e0e0e0;'>"
                    + safe.replace("\n", "<br>")
                    + "</body></html>"
                )
            else:
                content = self.output.toPlainText()
            Path(path).write_text(content, encoding="utf-8")
            QMessageBox.information(self, "AI Security", f"Report saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "AI Security", f"Failed to save: {e}")


class _SafeDict(dict):
    """dict subclass for str.format_map that returns the key for missing
    keys instead of raising KeyError. Prevents template rendering crashes."""
    def __missing__(self, key):
        return "{" + key + "}"


def _esc(text: str) -> str:
    """HTML-escape text for safe insertion into the report template."""
    import html as _html
    if not text:
        return ""
    if not isinstance(text, str):
        text = str(text)
    return _html.escape(text, quote=False)


class ToggleSwitch(QWidget):
    """A modern ON/OFF toggle switch widget (like iOS/Android switches).

    Slides right and turns blue when ON, slides left and stays grey/black
    when OFF. Emits toggled(bool) when the user clicks it.
    """

    toggled = pyqtSignal(bool)

    def __init__(self, label_text="", parent=None):
        super().__init__(parent)
        self._checked = False
        self._track_width = 52
        self._track_height = 26
        self._knob_size = 20
        self.setFixedHeight(self._track_height + 8)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self._label = QLabel(label_text)
        self._label.setStyleSheet("color: #E0E0E0; background: transparent; font-size: 14px; font-weight: bold;")
        layout.addWidget(self._label)

    @property
    def checked(self) -> bool:
        return self._checked

    def setChecked(self, checked: bool):
        if checked == self._checked:
            return
        self._checked = checked
        self.update()
        self.toggled.emit(checked)

    def isChecked(self) -> bool:
        return self._checked

    def setCheckedSilent(self, checked: bool):
        """Set checked without emitting the signal (for programmatic restore)."""
        self.blockSignals(True)
        self._checked = checked
        self.update()
        self.blockSignals(False)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._checked = not self._checked
            self.update()
            self.toggled.emit(self._checked)

    def paintEvent(self, event: QPaintEvent):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        label_w = self._label.sizeHint().width() + 8
        x = label_w
        y = (self.height() - self._track_height) // 2
        # Track
        if self._checked:
            track_color = QColor("#2962FF")
        else:
            track_color = QColor("#3A3A3A")
        p.setBrush(QBrush(track_color))
        p.setPen(QPen(Qt.PenStyle.NoPen))
        p.drawRoundedRect(QRect(x, y, self._track_width, self._track_height), 13, 13)
        # Knob
        margin = (self._track_height - self._knob_size) // 2
        if self._checked:
            knob_x = x + self._track_width - self._knob_size - margin
        else:
            knob_x = x + margin
        knob_y = y + margin
        p.setBrush(QBrush(QColor("#FFFFFF")))
        p.drawEllipse(int(knob_x), int(knob_y), self._knob_size, self._knob_size)