"""
Autobahn Defender - YARA Rules Updater
Checks for updated YARA rules on Codeberg and downloads them.
Rules are updated independently of app releases — just push new .yar
files to the yara/ folder on Codeberg and bump VERSION.
"""

import json
import os
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

from PyQt6.QtCore import QThread, pyqtSignal, QTimer

APP_DIR = Path.home() / ".autobahn"
RULES_DIR = APP_DIR / "rules"
OWNER = "donavinschlosser"
REPO = "autobahn-defender"
RAW_BASE = f"https://codeberg.org/{OWNER}/{REPO}/raw/branch/main/yara"
VERSION_URL = f"{RAW_BASE}/VERSION"
STATE_FILE = APP_DIR / "yara_update_state.json"

# Map of rule file names (as stored in the repo) to local filenames
RULE_FILES = {
    "linux-rules.yar": "upstream_linux.yar",
    "windows-rules.yar": "upstream_windows.yar",
    "macos-rules.yar": "upstream_macos.yar",
}


def _load_state():
    """Load YARA update state from disk."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_state(state):
    """Save YARA update state to disk."""
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, indent=2))
        try:
            os.chmod(str(STATE_FILE), 0o600)
        except OSError:
            pass
    except OSError:
        pass


def get_yara_last_updated():
    """Return the last YARA rules update time as a string, or 'Never'."""
    state = _load_state()
    ts = state.get("last_updated", "")
    if ts:
        try:
            dt = datetime.fromisoformat(ts)
            return dt.strftime("%Y-%m-%d %H:%M")
        except (ValueError, TypeError):
            pass
    return "Never"


def get_yara_current_version():
    """Return the current local YARA rules version."""
    state = _load_state()
    return state.get("version", "0")


class YaraUpdateCombinedWorker(QThread):
    """Background worker that checks for AND downloads YARA rule updates in one thread.
    v1.4 fix: Combined check+download into a single thread to avoid signal/chaining issues
    that caused the update to silently fail when the dialog closed between steps.
    """

    progress = pyqtSignal(int)   # 0-100
    status = pyqtSignal(str)
    finished = pyqtSignal(bool, str)  # success, message

    def run(self):
        try:
            # Step 1: Check version
            self.status.emit("Checking for YARA rule updates...")
            self.progress.emit(5)

            req = urllib.request.Request(
                VERSION_URL,
                headers={"User-Agent": "AutobahnDefender/2.0.2"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                remote_version = resp.read().decode().strip()

            if not remote_version:
                self.finished.emit(False, "Empty version response from server")
                return

            local_version = get_yara_current_version()

            if remote_version == local_version:
                self.progress.emit(100)
                self.finished.emit(True, "YARA rules are up to date")
                return

            self.status.emit(f"Updating YARA rules (v{local_version} -> v{remote_version})...")
            self.progress.emit(10)

            # Step 2: Download all rule files
            RULES_DIR.mkdir(parents=True, exist_ok=True)
            total_files = len(RULE_FILES)
            downloaded = 0

            for repo_name, local_name in RULE_FILES.items():
                url = f"{RAW_BASE}/{repo_name}"
                dest = RULES_DIR / local_name
                temp_path = dest.with_suffix(dest.suffix + ".part")

                self.status.emit(f"Downloading {repo_name}...")

                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "AutobahnDefender/2.0.2"},
                )
                with urllib.request.urlopen(req, timeout=120) as resp:
                    with open(temp_path, "wb") as f:
                        while True:
                            chunk = resp.read(65536)
                            if not chunk:
                                break
                            f.write(chunk)

                if temp_path.exists() and temp_path.stat().st_size > 0:
                    if dest.exists():
                        dest.unlink()
                    temp_path.rename(dest)
                    downloaded += 1
                else:
                    try:
                        temp_path.unlink()
                    except OSError:
                        pass

                progress_pct = 10 + int((downloaded / total_files) * 80)
                self.progress.emit(progress_pct)

            if downloaded > 0:
                # Save update state
                state = _load_state()
                state["version"] = remote_version
                state["last_updated"] = datetime.now().isoformat()
                _save_state(state)

                # Delete compiled .yc cache so rules are recompiled on next scan
                compiled_cache = RULES_DIR / "compiled.yc"
                if compiled_cache.exists():
                    try:
                        compiled_cache.unlink()
                    except OSError:
                        pass

                self.progress.emit(100)
                self.finished.emit(
                    True,
                    f"YARA rules updated to v{remote_version} ({downloaded}/{total_files} files)",
                )
            else:
                self.finished.emit(False, "No rule files were downloaded")

        except urllib.error.HTTPError as e:
            self.finished.emit(False, f"HTTP error {e.code}")
        except urllib.error.URLError as e:
            self.finished.emit(False, f"Network unavailable: {e}")
        except Exception as e:
            self.finished.emit(False, f"Error: {e}")


class YaraUpdateCheckWorker(QThread):
    """Background worker that checks for YARA rule updates via Codeberg."""

    finished = pyqtSignal(dict)

    def run(self):
        try:
            req = urllib.request.Request(
                VERSION_URL,
                headers={"User-Agent": "AutobahnDefender/2.0.2"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                remote_version = resp.read().decode().strip()

            if not remote_version:
                self.finished.emit({"available": False, "error": "Empty version response"})
                return

            local_version = get_yara_current_version()

            if remote_version == local_version:
                self.finished.emit({"available": False, "latest": remote_version})
                return

            self.finished.emit({
                "available": True,
                "version": remote_version,
            })
        except urllib.error.HTTPError as e:
            self.finished.emit({"available": False, "error": f"HTTP error {e.code}"})
        except urllib.error.URLError:
            self.finished.emit({"available": False, "error": "Network unavailable"})
        except Exception as e:
            self.finished.emit({"available": False, "error": str(e)})


class YaraRuleDownloadWorker(QThread):
    """Background worker that downloads YARA rule files."""

    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, version):
        super().__init__()
        self.version = version

    def run(self):
        try:
            RULES_DIR.mkdir(parents=True, exist_ok=True)
            total_files = len(RULE_FILES)
            downloaded = 0

            for repo_name, local_name in RULE_FILES.items():
                url = f"{RAW_BASE}/{repo_name}"
                dest = RULES_DIR / local_name
                temp_path = dest.with_suffix(dest.suffix + ".part")

                self.status.emit(f"Downloading {repo_name}...")

                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "AutobahnDefender/2.0.2"},
                )
                with urllib.request.urlopen(req, timeout=60) as resp:
                    with open(temp_path, "wb") as f:
                        while True:
                            chunk = resp.read(65536)
                            if not chunk:
                                break
                            f.write(chunk)

                # Only replace if download succeeded
                if temp_path.exists() and temp_path.stat().st_size > 0:
                    if dest.exists():
                        dest.unlink()
                    temp_path.rename(dest)
                    downloaded += 1
                else:
                    try:
                        temp_path.unlink()
                    except OSError:
                        pass

                progress_pct = int((downloaded / total_files) * 100)
                self.progress.emit(progress_pct)

            if downloaded > 0:
                # Save update state
                state = _load_state()
                state["version"] = self.version
                state["last_updated"] = datetime.now().isoformat()
                _save_state(state)

                # Delete compiled .yc cache so rules are recompiled on next scan
                compiled_cache = RULES_DIR / "compiled.yc"
                if compiled_cache.exists():
                    try:
                        compiled_cache.unlink()
                    except OSError:
                        pass

                self.finished.emit(
                    True,
                    f"Downloaded {downloaded}/{total_files} YARA rule file(s)",
                )
            else:
                self.finished.emit(False, "No rule files were downloaded")

        except Exception as e:
            self.finished.emit(False, f"Download failed: {e}")


class YaraRuleUpdater:
    """Manages checking for YARA rule updates and downloading them."""

    def __init__(self, parent=None):
        self.parent = parent
        self._check_worker = None
        self._download_worker = None
        self._timer = QTimer()
        self._timer.timeout.connect(self.check_for_updates)

    def start_periodic_checks(self):
        """Check for YARA rule updates on launch and every 24 hours."""
        self.check_for_updates()
        self._timer.start(24 * 60 * 60 * 1000)  # 24 hours

    def stop_periodic_checks(self):
        self._timer.stop()

    def check_for_updates(self):
        """Check for YARA rule updates in the background.
        v1.4 fix: Uses the combined worker that does check+download in one thread.
        """
        if self._check_worker and self._check_worker.isRunning():
            return
        # Use the combined worker -- it checks and downloads in one go
        self._check_worker = YaraUpdateCombinedWorker()
        self._check_worker.finished.connect(self._on_silent_update_finished)
        self._check_worker.start()

    def _on_silent_update_finished(self, success, message):
        # Don't set _check_worker = None immediately -- the QThread
        # is still in its run() method. Setting it to None would
        # garbage-collect the QThread while it's still running,
        # causing "QThread: Destroyed while thread is still running" crash.
        # Instead, schedule the cleanup on the next event loop tick
        # so the QThread's run() has fully returned first.
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(100, self._cleanup_check_worker)

    def _cleanup_check_worker(self):
        self._check_worker = None
        # Silent background update -- no user notification needed
