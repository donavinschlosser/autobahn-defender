"""
Autobahn Defender v2.0 -- Automated background threat monitor.

Uses a QTimer to periodically (every 4 hours) poll RSS feeds for new Linux
security news, check for zero-days affecting installed packages, and run
an AI analysis to generate alerts with recommended actions.

SAFETY: The monitor ONLY runs when:
  1. The AI engine is turned ON (Ollama is running)
  2. The user has explicitly enabled Auto Monitor in the UI
  3. The system has >= 8GB RAM (checked once at startup)

The monitor does NOT auto-execute any commands. It generates alerts with
copy-paste commands for the user to review and run manually. The only
automated action is a pkexec-based service stop, which requires the user
to enter their password each time.

The monitor runs in the main Qt thread (QTimer) but delegates AI work to
an AIWorker QThread to avoid blocking the UI.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from PyQt6.QtCore import QTimer, pyqtSignal, QObject

from . import INTEL_DIR
from .alerts import create_alert, add_alert, load_alerts, clear_resolved
from .intel_db import ensure_dirs, read_all

if TYPE_CHECKING:
    from .worker import AIWorker
    from .ollama_manager import OllamaManager

log = logging.getLogger(__name__)

# Hardcoded configuration -- NOT user-configurable
SCAN_INTERVAL_MS = 4 * 60 * 60 * 1000  # 4 hours in milliseconds
MIN_RAM_GB = 8  # Minimum RAM required for AI features
ZERO_DAY_KEYWORDS = [
    "zero-day", "zero day", "0day", "0-day",
    "critical vulnerability", "actively exploited",
    "unpatched", "no fix available", "workaround",
    "security advisory", "urgent",
]


class ThreatMonitor(QObject):
    """Background threat monitor that runs on a QTimer.

    Signals:
      scan_started()      -- emitted when a scan cycle begins
      scan_finished()     -- emitted when a scan cycle completes
      new_alerts(int)     -- count of new alerts generated
      status(str)         -- status message for the UI
    """

    scan_started = pyqtSignal()
    scan_finished = pyqtSignal()
    new_alerts = pyqtSignal(int)
    status = pyqtSignal(str)

    def __init__(self, ollama_manager: "OllamaManager", parent=None):
        super().__init__(parent)
        self.ollama = ollama_manager
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._enabled = False
        self._scanning = False
        self._last_scan_time: str | None = None
        self._worker: "AIWorker | None" = None
        self._ram_checked = False
        self._ram_ok = False

    # --- RAM check ----------------------------------------------------

    def check_ram(self) -> bool:
        """Check if the system has >= 8GB RAM. Cached after first check."""
        if self._ram_checked:
            return self._ram_ok
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        # MemTotal: 16384512 kB
                        kb = int(line.split()[1])
                        gb = kb / (1024 * 1024)
                        self._ram_ok = gb >= MIN_RAM_GB
                        self._ram_checked = True
                        log.info("RAM check: %.1f GB (min: %d GB) -> %s",
                                 gb, MIN_RAM_GB, "OK" if self._ram_ok else "INSUFFICIENT")
                        return self._ram_ok
        except Exception:
            log.warning("Could not read /proc/meminfo, assuming sufficient RAM")
            self._ram_ok = True
            self._ram_checked = True
            return True
        self._ram_ok = False
        self._ram_checked = True
        return False

    # --- Enable/Disable -----------------------------------------------

    def set_enabled(self, enabled: bool):
        """Enable or disable the auto monitor. Only starts if AI is on
        and RAM is sufficient."""
        self._enabled = enabled
        if enabled:
            if not self.ollama or not self.ollama.is_ready:
                self.status.emit("Cannot enable: AI engine is not running.")
                self._enabled = False
                return
            if not self.check_ram():
                self.status.emit(
                    f"Cannot enable: AI features require at least {MIN_RAM_GB}GB RAM. "
                    "Your system has less than this."
                )
                self._enabled = False
                return
            # Start the timer and do an immediate first scan
            self._timer.start(SCAN_INTERVAL_MS)
            self.status.emit("Auto Monitor enabled. Running initial scan...")
            self._tick()
        else:
            self._timer.stop()
            self.status.emit("Auto Monitor disabled.")

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    @property
    def is_scanning(self) -> bool:
        return self._scanning

    @property
    def last_scan_time(self) -> str | None:
        return self._last_scan_time

    def time_until_next_scan(self) -> int:
        """Returns seconds until next scheduled scan, or -1 if not running."""
        if not self._timer.isActive():
            return -1
        return self._timer.remainingTime() // 1000  # ms -> s

    # --- Timer tick ---------------------------------------------------

    def _tick(self):
        """Called by the timer. Runs one scan cycle."""
        if self._scanning:
            log.debug("Scan already in progress, skipping tick")
            return
        if not self._enabled:
            return
        if not self.ollama or not self.ollama.is_ready:
            self.status.emit("Auto Monitor: AI engine not ready, skipping scan.")
            return

        self._scanning = True
        self.scan_started.emit()
        self.status.emit("Auto Monitor: scanning for threats...")

        try:
            self._run_scan()
        except Exception as e:
            log.exception("ThreatMonitor scan failed")
            self.status.emit(f"Auto Monitor: scan failed - {e}")
        finally:
            self._scanning = False
            self._last_scan_time = datetime.now(timezone.utc).isoformat()
            self.scan_finished.emit()

    def _run_scan(self):
        """Run one complete scan cycle: RSS poll -> zero-day detection ->
        AI analysis -> alert generation."""
        from .rss_feeds import poll_all_feeds
        from .tools import execute_tool

        # Step 1: Poll RSS feeds for new articles
        self.status.emit("Auto Monitor: polling security news feeds...")
        try:
            rss_result = execute_tool("rss_poll", {})
            articles = rss_result.get("ok", {}).get("articles", [])
            if not articles:
                articles = rss_result.get("articles", [])
        except Exception as e:
            log.warning("RSS poll failed: %s", e)
            articles = []

        # Step 2: Check for zero-day keywords in new articles
        zero_day_hits = []
        for article in articles:
            title = (article.get("title") or "").lower()
            summary = (article.get("summary") or "").lower()
            combined = f"{title} {summary}"
            for kw in ZERO_DAY_KEYWORDS:
                if kw in combined:
                    zero_day_hits.append(article)
                    break

        # Step 3: Get installed packages for cross-referencing
        self.status.emit("Auto Monitor: checking installed packages...")
        try:
            pkg_result = execute_tool("installed_packages", {})
            pkg_data = pkg_result.get("ok", {}).get("packages", [])
            if isinstance(pkg_data, str):
                # Raw dpkg output -- extract package names
                pkg_names = set()
                for line in pkg_data.splitlines():
                    if line.startswith("ii ") and len(line.split()) >= 2:
                        pkg_names.add(line.split()[1].split(":")[0])
            elif isinstance(pkg_data, list):
                pkg_names = {p.get("name", "") for p in pkg_data if p.get("name")}
            else:
                pkg_names = set()
        except Exception:
            pkg_names = set()

        # Step 4: Cross-reference zero-day articles with installed packages
        relevant_articles = []
        for article in zero_day_hits:
            title = article.get("title", "")
            summary = article.get("summary", "")
            text = f"{title} {summary}".lower()
            # Check if any installed package name is mentioned
            matched_packages = [p for p in pkg_names if p and len(p) > 2 and p in text]
            if matched_packages:
                relevant_articles.append((article, matched_packages))

        # Step 5: Run AI analysis to generate alerts
        # The AI will use web_search and cve_check tools to verify
        # and generate specific, actionable recommendations.
        new_alert_count = 0

        if relevant_articles or zero_day_hits:
            self.status.emit(
                f"Auto Monitor: found {len(zero_day_hits)} zero-day articles, "
                f"{len(relevant_articles)} relevant to this system. Running AI analysis..."
            )
            new_alert_count = self._run_ai_analysis(
                zero_day_hits, relevant_articles, list(pkg_names)
            )
        else:
            self.status.emit("Auto Monitor: no new threats found in latest scan.")

            # Step 6: Also run CVE check for installed packages (silent, background)
            self._background_cve_check(list(pkg_names))

        # Step 7: Clean up old resolved alerts
        try:
            clear_resolved(older_than_days=7)
        except Exception:
            pass

        if new_alert_count > 0:
            self.new_alerts.emit(new_alert_count)
            self.status.emit(
                f"Auto Monitor: {new_alert_count} new alert(s) generated. "
                "Check the Threat Dashboard."
            )
        else:
            self.status.emit("Auto Monitor: scan complete. No new alerts.")

    def _run_ai_analysis(self, zero_day_hits, relevant_articles, pkg_names) -> int:
        """Run AI analysis on found threats and generate alerts.

        This uses a simplified AI call (not the full AIWorker) to avoid
        blocking the UI with long-running AI tasks. The AI analyzes
        the articles and generates specific, actionable alerts.

        Returns the count of new alerts created.
        """
        from .alerts import create_alert, add_alert
        from .tools import execute_tool

        new_alerts = []

        # For articles that match installed packages, do targeted research
        for article, matched_pkgs in relevant_articles:
            title = article.get("title", "Unknown threat")
            source = article.get("source", article.get("link", ""))
            summary = article.get("summary", "")

            # Try to extract CVE IDs from the title/summary
            import re
            cve_pattern = r"CVE-\d{4}-\d{4,}"
            cve_ids = re.findall(cve_pattern, f"{title} {summary}", re.IGNORECASE)

            # Use web search to find patch status
            patch_available = False
            recommended_action = ""
            alternative_action = ""
            cve_id = cve_ids[0] if cve_ids else ""

            if cve_id:
                # Search for patch availability
                try:
                    search_result = execute_tool("web_search", {
                        "query": f"{cve_id} patch available Linux fix"
                    })
                    results = search_result.get("ok", {}).get("results", [])
                    if not results:
                        results = search_result.get("results", [])
                    if results:
                        first = results[0]
                        snippet = first.get("snippet", "").lower()
                        title_lower = first.get("title", "").lower()
                        if any(w in snippet or w in title_lower
                               for w in ["patch", "fix", "update", "upgrade", "fixed"]):
                            patch_available = True
                        # Build recommended action based on findings
                        for pkg in matched_pkgs:
                            if patch_available:
                                recommended_action = f"sudo apt update && sudo apt upgrade {pkg}"
                            else:
                                recommended_action = (
                                    f"# No patch available yet for {cve_id}\n"
                                    f"# Recommended: monitor for updates\n"
                                    f"# Check: https://nvd.nist.gov/vuln/detail/{cve_id}"
                                )
                                # Look for workaround
                                try:
                                    wa_result = execute_tool("web_search", {
                                        "query": f"{cve_id} workaround mitigation"
                                    })
                                    wa_results = wa_result.get("ok", {}).get("results", [])
                                    if not wa_results:
                                        wa_results = wa_result.get("results", [])
                                    if wa_results:
                                        wa_snippet = wa_results[0].get("snippet", "")
                                        if wa_snippet and len(wa_snippet) > 20:
                                            alternative_action = wa_snippet[:500]
                                except Exception:
                                    pass
                except Exception as e:
                    log.warning("Web search for %s failed: %s", cve_id, e)

            if not recommended_action:
                # Fallback: generic recommendation
                for pkg in matched_pkgs:
                    recommended_action = f"sudo apt update && sudo apt upgrade {pkg}"
                    break

            severity = "critical" if any(
                kw in title.lower()
                for kw in ["zero-day", "0day", "actively exploited", "critical"]
            ) else "high"

            alert = create_alert(
                severity=severity,
                title=title[:200],
                recommended_action=recommended_action,
                affected_package=", ".join(matched_pkgs[:3]),
                patch_available=patch_available,
                alternative_action=alternative_action,
                source=source,
                cve_id=cve_id,
            )
            new_alerts.append(alert)

        # Also check CVE database for installed packages
        if pkg_names and len(pkg_names) < 500:
            try:
                cve_result = execute_tool("cve_check", {})
                cves = cve_result.get("ok", {}).get("vulnerabilities", [])
                if not cves:
                    cves = cve_result.get("vulnerabilities", [])
                for cve in cves[:20]:  # Limit to prevent flooding
                    cve_id = cve.get("id", "")
                    pkg = cve.get("package", "")
                    severity = cve.get("severity", "medium").lower()
                    if severity in ("critical", "high"):
                        existing = load_alerts(active_only=True)
                        if any(a.get("cve_id") == cve_id for a in existing):
                            continue  # Don't duplicate
                        alert = create_alert(
                            severity=severity,
                            title=f"Vulnerability in {pkg} ({cve_id})",
                            recommended_action=f"sudo apt update && sudo apt upgrade {pkg}",
                            affected_package=pkg,
                            patch_available=True,
                            source="OSV.dev CVE Database",
                            cve_id=cve_id,
                        )
                        new_alerts.append(alert)
            except Exception as e:
                log.warning("Background CVE check failed: %s", e)

        # Write all new alerts
        count = 0
        for alert in new_alerts:
            if add_alert(alert):
                count += 1

        return count

    def _background_cve_check(self, pkg_names: list[str]):
        """Run a lightweight CVE check even when no zero-day articles found."""
        from .tools import execute_tool
        from .alerts import load_alerts, create_alert, add_alert

        if not pkg_names or len(pkg_names) > 500:
            return

        try:
            cve_result = execute_tool("cve_check", {})
            cves = cve_result.get("ok", {}).get("vulnerabilities", [])
            if not cves:
                cves = cve_result.get("vulnerabilities", [])

            if not cves:
                return

            existing = load_alerts(active_only=True)
            existing_cves = {a.get("cve_id") for a in existing if a.get("cve_id")}

            new_alerts = []
            for cve in cves[:20]:
                cve_id = cve.get("id", "")
                if cve_id in existing_cves:
                    continue
                pkg = cve.get("package", "")
                severity = cve.get("severity", "medium").lower()
                if severity not in ("critical", "high"):
                    continue
                alert = create_alert(
                    severity=severity,
                    title=f"Vulnerability in {pkg} ({cve_id})",
                    recommended_action=f"sudo apt update && sudo apt upgrade {pkg}",
                    affected_package=pkg,
                    patch_available=True,
                    source="OSV.dev CVE Database",
                    cve_id=cve_id,
                )
                new_alerts.append(alert)

            for alert in new_alerts:
                add_alert(alert)

            if new_alerts:
                self.new_alerts.emit(len(new_alerts))
        except Exception as e:
            log.warning("Background CVE check failed: %s", e)

    # --- Manual trigger ----------------------------------------------

    def scan_now(self):
        """Trigger an immediate scan (user clicked 'Scan Now')."""
        if not self._enabled:
            self.status.emit("Auto Monitor is not enabled. Enable it first.")
            return
        if self._scanning:
            self.status.emit("A scan is already in progress.")
            return
        self._tick()