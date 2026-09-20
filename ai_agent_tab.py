"""AI Agent integration tab — connect external AI agents (Hermes, Claude
Code/OpenClaw, any MCP host) to Autobahn Defender safely.

Design principles:
  * The engine's guarantees stay intact: an agent can read everything, but
    every write path (updates, containment, firewall) is token-gated by the
    engine's read-before-write remediation contract — no AI can skip it.
  * This tab does NOT auto-edit other apps' config files. It shows the exact
    setup command to run, so the user stays in control of what connects.
  * The local policy file (~/.autobahn/mcp_policy.json) is enforced by the
    MCP server process itself on every tool call — not just by the UI.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from PyQt6.QtCore import Qt, QProcess, QTimer
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

try:
    from ui_tabs import (
        CardWidget, BG_DARK, BG_CARD, BORDER, ACCENT,
        TEXT_PRIMARY, TEXT_SECONDARY, SUCCESS, DANGER,
    )
except Exception:  # pragma: no cover — minimal fallback theme
    BG_DARK = "#121212"
    BG_CARD = "#1E1E1E"
    BORDER = "#2C2C2C"
    ACCENT = "#2962FF"
    TEXT_PRIMARY = "#E0E0E0"
    TEXT_SECONDARY = "#A0A0A0"
    SUCCESS = "#4CAF50"
    DANGER = "#E57373"

    class CardWidget(QWidget):  # minimal fallback (real one is a QGroupBox)
        def __init__(self, title="", parent=None):
            super().__init__(parent)
            self._lay = QVBoxLayout(self)
            self._lay.addWidget(QLabel(title))

        def layout(self):
            return self._lay

# v2.0.4: resolve through engine.paths (sudo-safe data dir — see that module)
try:
    from engine.paths import APP_DIR
except ImportError:  # pragma: no cover
    APP_DIR = Path.home() / ".autobahn"
POLICY_FILE = APP_DIR / "mcp_policy.json"
DEFAULT_POLICY = {
    "mode": "read",       # off | read | full
    "allow_update": True,
    "allow_contain": False,
    "allow_firewall": False,
    "require_token": True,   # engine-enforced; shown for transparency
}

# Hosts we can detect configs for. Detection only — never auto-edit.
_MCP_HOSTS = [
    ("Hermes Agent", "~/.hermes/config.yaml",
     "hermes mcp add autobahn --command autobahn-defender --args mcp"),
    ("Claude Code / Claude Desktop", "~/.claude.json",
     "claude mcp add autobahn -- autobahn-defender mcp"),
    ("OpenClaw", "~/.openclaw/config.json",
     "openclaw mcp add autobahn --command autobahn-defender --args mcp"),
]


def load_policy() -> dict:
    try:
        data = json.loads(POLICY_FILE.read_text())
        if isinstance(data, dict):
            merged = dict(DEFAULT_POLICY)
            merged.update({k: v for k, v in data.items() if k in DEFAULT_POLICY})
            return merged
    except Exception:
        pass
    return dict(DEFAULT_POLICY)


def save_policy(policy: dict) -> None:
    POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
    POLICY_FILE.write_text(json.dumps(policy, indent=2))
    try:
        POLICY_FILE.chmod(0o600)
    except Exception:
        pass


class AIAgentTab(QWidget):
    """Dedicated tab for connecting an external AI agent (Hermes, Claude…)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.policy = load_policy()
        self._mcp_proc: QProcess | None = None
        self._build_ui()
        self._refresh_status()

    # ------------------------------------------------------------- UI
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(16)

        header = QLabel("AI Agent")
        header.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        header.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent;")
        root.addWidget(header)

        sub = QLabel(
            "Connect an AI assistant (Hermes, Claude, OpenClaw…) to Autobahn Defender "
            "over MCP so it can run scans, explain alerts in plain language, and — only "
            "if you allow it — apply fixes.")
        sub.setWordWrap(True)
        sub.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        root.addWidget(sub)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        content = QWidget()
        content.setStyleSheet(f"background-color: {BG_DARK};")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        # ── Card 1: What the agent gets ─────────────────────────────
        c1 = CardWidget("What the agent can do")
        l1 = QVBoxLayout(c1)
        c1_text = QLabel(
            "When connected over MCP, your AI assistant gains safe, structured "
            "access to:\n"
            "  •  Run antivirus scans and read the results\n"
            "  •  List and explain every CVE/alert affecting your PC in plain language\n"
            "  •  Run security audits (hardening, network, full)\n"
            "  •  Poll threat feeds (CISA KEV, Ubuntu notices, exploit predictions)\n\n"
            "Write actions (installing updates, masking services, firewall rules) are "
            "LOCKED behind a one-time confirm token: the agent must plan first, you "
            "approve, and the engine refuses any write without that token. The agent "
            "cannot bypass this even if it wants to.")
        c1_text.setWordWrap(True)
        c1_text.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent;")
        l1.addWidget(c1_text)

        guide_btn = QPushButton("Open the full AI integration guide (docs/AGENTS.md)")
        guide_btn.clicked.connect(self._open_guide)
        l1.addWidget(guide_btn)
        layout.addWidget(c1)

        # ── Card 2: Connection status ────────────────────────────────
        c2 = CardWidget("Connection Status")
        l2 = QVBoxLayout(c2)
        self.status_label = QLabel("Checking…")
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.status_label.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent;")
        l2.addWidget(self.status_label)

        test_row = QHBoxLayout()
        self.test_btn = QPushButton("Test Local MCP Server")
        self.test_btn.clicked.connect(self._test_mcp)
        test_row.addWidget(self.test_btn)
        self.test_result = QLabel("")
        self.test_result.setWordWrap(True)
        self.test_result.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        test_row.addWidget(self.test_result, 1)
        l2.addLayout(test_row)
        layout.addWidget(c2)

        # ── Card 3: Connect an agent ───────────────────────────────
        c3 = CardWidget("Connect an Agent")
        l3 = QVBoxLayout(c3)
        conn_text = QLabel(
            "Run ONE of these commands in a terminal to introduce your AI "
            "assistant to Defender (the agent app stores it in its own config):")
        conn_text.setWordWrap(True)
        conn_text.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent;")
        l3.addWidget(conn_text)
        self.cmd_labels: list[QLabel] = []
        for name, _cfg, cmd in _MCP_HOSTS:
            row = QHBoxLayout()
            lbl = QLabel(f"{name}:  {cmd}")
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            lbl.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
            cp = QPushButton("Copy")
            cp.setFixedWidth(70)
            cp.clicked.connect(lambda _=False, t=cmd: self._copy(t))
            row.addWidget(lbl, 1)
            row.addWidget(cp)
            l3.addLayout(row)
            self.cmd_labels.append(lbl)
        l3.addWidget(QLabel(
            "After adding, restart your AI assistant and ask it: "
            "\"run an autobahn security audit\"."))
        last = l3.itemAt(l3.count() - 1)
        if last and last.widget():
            last.widget().setWordWrap(True)
            last.widget().setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        layout.addWidget(c3)

        # ── Card 4: Permissions ─────────────────────────────────────
        c4 = CardWidget("Agent Permissions")
        l4 = QVBoxLayout(c4)

        mode_row = QHBoxLayout()
        mode_lbl = QLabel("Access mode:")
        mode_row.addWidget(mode_lbl)
        self.mode_combo = QComboBox()
        self.mode_combo.addItem("Off — no AI access", "off")
        self.mode_combo.addItem("Read-only (recommended)", "read")
        self.mode_combo.addItem("Full — token-gated writes", "full")
        self.mode_combo.setCurrentIndex({"off": 0, "read": 1, "full": 2}.get(
            self.policy.get("mode", "read"), 1))
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        mode_row.addWidget(self.mode_combo, 1)
        l4.addLayout(mode_row)

        self.mode_hint = QLabel("")
        self.mode_hint.setWordWrap(True)
        self.mode_hint.setStyleSheet(f"color: {TEXT_SECONDARY}; background: transparent;")
        l4.addWidget(self.mode_hint)

        self.chk_update = QCheckBox(
            "Allow package security updates (apt upgrade of affected packages)")
        self.chk_contain = QCheckBox(
            "Allow service containment (mask/unmask a service during an incident)")
        self.chk_firewall = QCheckBox("Allow firewall rule changes (ufw hardening profile)")
        self.chk_token = QCheckBox(
            "Require one-time token for every write (read-before-write)")
        self.chk_token.setToolTip("Always enforced by the engine — cannot be disabled.")
        for chk, key in ((self.chk_update, "allow_update"),
                         (self.chk_contain, "allow_contain"),
                         (self.chk_firewall, "allow_firewall"),
                         (self.chk_token, "require_token")):
            chk.setChecked(bool(self.policy.get(key)))
            chk.stateChanged.connect(self._persist_policy)
            l4.addWidget(chk)

        apply_row = QHBoxLayout()
        apply_btn = QPushButton("Save Permissions")
        apply_btn.clicked.connect(self._persist_policy)
        hermes_btn = QPushButton("Copy Hermes Setup Command")
        hermes_btn.clicked.connect(self._copy_hermes_cmd)
        apply_row.addWidget(apply_btn)
        apply_row.addWidget(hermes_btn)
        apply_row.addStretch(1)
        l4.addLayout(apply_row)

        self.policy_note = QLabel("")
        self.policy_note.setWordWrap(True)
        self.policy_note.setStyleSheet(f"color: {SUCCESS}; background: transparent;")
        l4.addWidget(self.policy_note)
        layout.addWidget(c4)

        # ── Card 5: Why this is safe ────────────────────────────────
        c5 = CardWidget("Why this is safe")
        l5 = QVBoxLayout(c5)
        safe_text = QLabel(
            "•  The MCP server runs locally on your machine. Nothing is uploaded anywhere.\n"
            "•  Reads let the agent explain; writes require a fresh token per action — the "
            "engine refuses every write that skips the plan→token→execute sequence.\n"
            "•  Access mode Off makes the MCP server refuse to start at all — no agent, "
            "AI or otherwise, can talk to Defender.\n"
            "•  Disconnect an agent any time by removing one line from its own config — "
            "this app never edits other programs' files for you.")
        safe_text.setWordWrap(True)
        safe_text.setStyleSheet(f"color: {TEXT_PRIMARY}; background: transparent;")
        l5.addWidget(safe_text)
        layout.addWidget(c5)

        layout.addStretch()
        scroll.setWidget(content)
        root.addWidget(scroll, 1)

        # small-window safety net: wrap any label that can't fit
        for lbl in content.findChildren(QLabel):
            if not lbl.wordWrap():
                lbl.setWordWrap(True)

    # --------------------------------------------------------- slots
    def _open_guide(self):
        guide = Path(__file__).resolve().parent / "docs" / "AGENTS.md"
        if guide.exists():
            subprocess.Popen(["xdg-open", str(guide)])
        else:
            QMessageBox.information(self, "Guide", "docs/AGENTS.md is missing from this install.")

    def _refresh_status(self):
        lines = []
        binary = shutil.which("autobahn-defender")
        lines.append(f"Defender CLI: {'✓ ' + binary if binary else '✗ not found on PATH'}")
        try:
            from engine.version import APP_VERSION
            lines.append(f"Engine: v{APP_VERSION}")
        except Exception:
            pass
        lines.append("")
        for name, cfg_path, _cmd in _MCP_HOSTS:
            p = Path(cfg_path).expanduser()
            state = ("config found — run the command below to connect"
                     if p.exists() else "not installed (config not found)")
            lines.append(f"  {name}: {state}")
        self.status_label.setText("\n".join(lines))
        self._mode_hint()

    def _mode_hint(self):
        mode = self.mode_combo.currentData()
        hints = {
            "off": "MCP server disabled — it will refuse to start. No AI assistant "
                   "can query Defender.",
            "read": "Agents can run scans, list alerts and audits — everything read-only. "
                    "They cannot change anything on this PC.",
            "full": "The agent may also apply fixes — but every individual write still needs "
                    "its own one-time token from a plan call, and only in the categories "
                    "ticked below.",
        }
        self.mode_hint.setText(hints.get(mode, ""))

    def _on_mode_changed(self, _idx):
        self._mode_hint()
        self._persist_policy()

    def _persist_policy(self):
        self.policy.update({
            "mode": self.mode_combo.currentData(),
            "allow_update": self.chk_update.isChecked(),
            "allow_contain": self.chk_contain.isChecked(),
            "allow_firewall": self.chk_firewall.isChecked(),
            "require_token": True,
        })
        try:
            save_policy(self.policy)
            self.policy_note.setText(
                f"Saved → {POLICY_FILE}  (enforced by the MCP server on every call)")
        except Exception as e:
            self.policy_note.setText(f"Save failed: {e}")

    def _copy(self, text):
        QApplication.clipboard().setText(text)
        self.policy_note.setText("Setup command copied to clipboard — paste it in a terminal.")

    def _copy_hermes_cmd(self):
        for _name, cfg, cmd in _MCP_HOSTS:
            if Path(cfg).expanduser().exists():
                self._copy(cmd)
                return
        self._copy(_MCP_HOSTS[0][2])

    # -------------------------------------------------- MCP live test
    def _test_mcp(self):
        if self._mcp_proc is not None:
            return
        self.test_result.setText("starting stdio MCP server…")
        self.test_btn.setEnabled(False)
        proc = QProcess(self)
        self._mcp_proc = proc
        proc.setProgram(shutil.which("autobahn-defender") or "/usr/bin/autobahn-defender")
        proc.setArguments(["mcp"])
        outbuf = {"data": b""}

        def _on_out():
            outbuf["data"] += bytes(proc.readAllStandardOutput())
            if b'"tools"' in outbuf["data"]:
                try:
                    proc.terminate()
                except Exception:
                    pass

        def _on_done(_code, _status):
            self._mcp_proc = None
            self.test_btn.setEnabled(True)
            data = outbuf["data"].decode(errors="replace")
            if '"tools"' in data and '"autobahn.' in data:
                n = len(re.findall(r'"name":\s*"autobahn\.', data))
                self.test_result.setText(
                    f"✔ MCP server answered: initialize OK, {n} tools exposed. "
                    "An AI agent can connect.")
                self.test_result.setStyleSheet(f"color: {SUCCESS}; background: transparent;")
            else:
                self.test_result.setText(f"MCP server did not answer correctly. Raw: {data[:160]}")
                self.test_result.setStyleSheet(f"color: {DANGER}; background: transparent;")

        proc.readyReadStandardOutput.connect(_on_out)
        proc.finished.connect(_on_done)
        init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "autobahn-ui-test", "version": "2.0"}}})
        tlist = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})

        def _start():
            proc.start()
            if not proc.waitForStarted(5000):
                self._mcp_proc = None
                self.test_btn.setEnabled(True)
                self.test_result.setText("Could not start the MCP server subprocess.")
                self.test_result.setStyleSheet(f"color: {DANGER}; background: transparent;")
                return
            proc.write((init + "\n").encode())
            proc.write((tlist + "\n").encode())

        QTimer.singleShot(0, _start)
        QTimer.singleShot(10000, lambda: proc.state() != QProcess.ProcessState.NotRunning
                          and proc.kill())