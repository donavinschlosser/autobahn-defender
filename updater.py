"""
Autobahn Defender - Update Checker
Checks for new versions on Codeberg and handles download/installation.
"""

import json
import os
import platform
import re
import shutil
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

from PyQt6.QtCore import QThread, pyqtSignal, QTimer
from PyQt6.QtWidgets import QMessageBox

APP_DIR = Path.home() / ".autobahn"
OWNER = "donavinschlosser"
REPO = "autobahn-defender"
CODEBERG_URL = f"https://codeberg.org/{OWNER}/{REPO}"
API_URL = f"https://codeberg.org/api/v1/repos/{OWNER}/{REPO}"
CURRENT_VERSION = "1.0"
STATE_FILE = APP_DIR / "update_state.json"


def get_current_version():
    """Return the current app version string."""
    return CURRENT_VERSION


def version_tuple(version_str):
    """Parse a version string like '1.0' or '1.2.3' into a comparable tuple."""
    parts = []
    for p in version_str.strip().lstrip("v").split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _load_state():
    """Load update state from disk."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_state(state):
    """Save update state to disk."""
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, indent=2))
    except OSError:
        pass


class UpdateCheckWorker(QThread):
    """Background worker that checks for updates via Codeberg API."""

    finished = pyqtSignal(dict)

    def run(self):
        try:
            url = f"{API_URL}/releases/latest"
            req = urllib.request.Request(url, headers={"User-Agent": "AutobahnDefender/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                release = json.loads(resp.read().decode())

            if not isinstance(release, dict) or not release.get("tag_name"):
                self.finished.emit({"available": False, "error": "No releases found"})
                return
            tag = release.get("tag_name", "").lstrip("v")
            name = release.get("name", tag)
            body = release.get("body", "")
            html_url = release.get("html_url", f"{CODEBERG_URL}/releases")
            assets = release.get("assets", [])

            if not tag:
                self.finished.emit({"available": False, "error": "No version tag found"})
                return

            if version_tuple(tag) <= version_tuple(CURRENT_VERSION):
                self.finished.emit({"available": False, "latest": tag})
                return

            # Find download URLs for each asset type
            appimage_url = ""
            deb_url = ""
            arch_url = ""
            for asset in assets:
                fname = asset.get("name", "").lower()
                url = asset.get("browser_download_url", "")
                if fname.endswith(".appimage"):
                    appimage_url = url
                elif fname.endswith(".deb"):
                    deb_url = url
                elif fname.endswith(".pkg.tar.zst") or fname.endswith(".pkg.tar.xz"):
                    arch_url = url

            self.finished.emit({
                "available": True,
                "version": tag,
                "name": name,
                "changelog": body[:1000] if body else "No changelog available.",
                "release_url": html_url,
                "appimage_url": appimage_url,
                "deb_url": deb_url,
                "arch_url": arch_url,
            })
        except urllib.error.HTTPError as e:
            self.finished.emit({"available": False, "error": f"HTTP error {e.code}"})
        except urllib.error.URLError:
            self.finished.emit({"available": False, "error": "Network unavailable"})
        except Exception as e:
            self.finished.emit({"available": False, "error": str(e)})


class DownloadWorker(QThread):
    """Background worker that downloads a file with progress."""

    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str)

    def __init__(self, url, dest_path):
        super().__init__()
        self.url = url
        self.dest_path = Path(dest_path)

    def run(self):
        try:
            self.dest_path.parent.mkdir(parents=True, exist_ok=True)
            req = urllib.request.Request(self.url, headers={"User-Agent": "AutobahnDefender/1.0"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                with open(self.dest_path, "wb") as f:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total > 0:
                            pct = int(downloaded * 100 / total)
                            self.progress.emit(pct)
            os.chmod(str(self.dest_path), 0o755)
            self.finished.emit(True, str(self.dest_path))
        except Exception as e:
            try:
                if self.dest_path.exists():
                    self.dest_path.unlink()
            except OSError:
                pass
            self.finished.emit(False, str(e))


def detect_distro():
    """Detect the Linux distribution and return (distro_id, package_manager, install_cmd_func)."""
    distro_id = ""
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("ID="):
                    distro_id = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("ID_LIKE=") and not distro_id:
                    distro_id = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass

    if distro_id in ("arch", "cachyos", "manjaro", "endeavouros") or "arch" in distro_id:
        return distro_id, "pacman", "pacman"
    elif distro_id in ("debian", "ubuntu", "linuxmint", "pop", "zorin") or "debian" in distro_id:
        return distro_id, "apt", "dpkg"
    elif distro_id in ("fedora", "rhel", "centos", "rocky", "almalinux") or "fedora" in distro_id:
        return distro_id, "dnf", "dnf"
    return distro_id, "unknown", "unknown"


def choose_package_asset(release_info):
    """Choose the best download asset for the current system."""
    _, pkg_mgr, _ = detect_distro()

    # If running as AppImage, prefer AppImage
    appimage_path = Path("/proc/self/exe").resolve()
    is_appimage = os.environ.get("APPIMAGE") or str(appimage_path).endswith(".AppImage")

    if is_appimage and release_info.get("appimage_url"):
        return "appimage", release_info["appimage_url"]

    if pkg_mgr == "dpkg" and release_info.get("deb_url"):
        return "deb", release_info["deb_url"]
    elif pkg_mgr == "pacman" and release_info.get("arch_url"):
        return "arch", release_info["arch_url"]

    # Fallback to AppImage
    if release_info.get("appimage_url"):
        return "appimage", release_info["appimage_url"]

    return None, None


class AppUpdater:
    """Manages checking for updates and downloading/installing them."""

    def __init__(self, parent=None):
        self.parent = parent
        self._worker = None
        self._download_worker = None
        self._timer = QTimer()
        self._timer.timeout.connect(self.check_for_updates)

    def start_periodic_checks(self):
        """Check for updates on launch and every 24 hours."""
        self.check_for_updates()
        self._timer.start(24 * 60 * 60 * 1000)  # 24 hours

    def stop_periodic_checks(self):
        self._timer.stop()

    def check_for_updates(self, silent=True):
        """Check for updates. If silent=True, only show dialog for new versions."""
        self._silent = silent
        if self._worker and self._worker.isRunning():
            return
        self._worker = UpdateCheckWorker()
        self._worker.finished.connect(self._on_check_result)
        self._worker.start()

    def _on_check_result(self, result):
        if result.get("available"):
            self._show_update_dialog(result)
        elif not self._silent:
            error = result.get("error", "You are already on the latest version.")
            QMessageBox.information(
                self.parent, "No Updates Available",
                f"You are running version {CURRENT_VERSION}.\n{error}",
            )

    def _show_update_dialog(self, release_info):
        version = release_info.get("version", "unknown")
        changelog = release_info.get("changelog", "No changelog available.")
        release_url = release_info.get("release_url", CODEBERG_URL)

        pkg_type, pkg_url = choose_package_asset(release_info)

        msg = QMessageBox(self.parent)
        msg.setWindowTitle("Update Available")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText(f"<h3>Autobahn Defender {version} is available</h3>")
        msg.setInformativeText(
            f"<b>Current version:</b> {CURRENT_VERSION}<br>"
            f"<b>New version:</b> {version}<br><br>"
            f"<b>What's new:</b><br>{changelog}<br><br>"
            f"<a href='{release_url}'>View release on Codeberg</a>"
        )

        download_btn = msg.addButton("Download & Install", QMessageBox.ButtonRole.AcceptRole)
        remind_btn = msg.addButton("Remind Me Later", QMessageBox.ButtonRole.RejectRole)
        close_btn = msg.addButton("Close", QMessageBox.ButtonRole.DestructiveRole)

        msg.exec()

        if msg.clickedButton() == download_btn and pkg_url:
            self._download_and_install(pkg_type, pkg_url, release_info)
        elif msg.clickedButton() == remind_btn:
            state = _load_state()
            state["remind_later"] = datetime.now().isoformat()
            _save_state(state)

    def _download_and_install(self, pkg_type, pkg_url, release_info):
        """Download the package and install it."""
        version = release_info.get("version", "unknown")
        # Sanitize version to prevent path traversal
        safe_version = re.sub(r"[^a-zA-Z0-9._-]", "", version)
        if not safe_version:
            safe_version = "unknown"

        if pkg_type == "appimage":
            dest = APP_DIR / f"autobahn-defender-{safe_version}.AppImage"
        elif pkg_type == "deb":
            dest = APP_DIR / f"autobahn-defender-{safe_version}.deb"
        elif pkg_type == "arch":
            dest = APP_DIR / f"autobahn-defender-{safe_version}.pkg.tar.zst"
        else:
            dest = APP_DIR / f"autobahn-defender-{safe_version}"

        self._download_worker = DownloadWorker(pkg_url, dest)
        self._download_worker.progress.connect(self._on_download_progress)
        self._download_worker.finished.connect(self._on_download_finished)
        self._download_worker.start()

    def _on_download_progress(self, pct):
        pass  # Could emit a signal for UI progress

    def _on_download_finished(self, success, result):
        if not success:
            QMessageBox.warning(
                self.parent, "Download Failed",
                f"Could not download the update:\n{result}",
            )
            return

        dest = Path(result)
        pkg_type = ""
        if dest.suffix == ".AppImage":
            pkg_type = "appimage"
        elif dest.suffix == ".deb":
            pkg_type = "deb"
        elif ".pkg.tar" in dest.name:
            pkg_type = "arch"

        if pkg_type == "appimage":
            self._install_appimage(dest)
        elif pkg_type == "deb":
            self._install_deb(dest)
        elif pkg_type == "arch":
            self._install_arch(dest)
        else:
            QMessageBox.information(
                self.parent, "Download Complete",
                f"Downloaded to:\n{dest}\n\nPlease install manually.",
            )

    def _install_appimage(self, dest):
        """Replace the current AppImage or inform user of new location."""
        current = os.environ.get("APPIMAGE")
        if current and Path(current).exists():
            try:
                Path(current).rename(str(current) + ".bak")
                shutil.move(str(dest), current)
                os.chmod(current, 0o755)
                QMessageBox.information(
                    self.parent, "Update Complete",
                    f"Updated successfully to {dest.name}.\n"
                    f"Please restart the application.",
                )
            except OSError as e:
                # Restore backup
                try:
                    Path(str(current) + ".bak").rename(current)
                except OSError:
                    pass
                QMessageBox.warning(
                    self.parent, "Update Failed",
                    f"Could not replace AppImage: {e}\n\n"
                    f"New version saved to:\n{dest}",
                )
        else:
            os.chmod(str(dest), 0o755)
            QMessageBox.information(
                self.parent, "Download Complete",
                f"New version downloaded to:\n{dest}\n\n"
                f"Please move it to your preferred location and run it.",
            )

    def _install_deb(self, dest):
        """Offer to install .deb package using pkexec."""
        terminal = shutil.which("pkexec")
        if terminal:
            reply = QMessageBox.question(
                self.parent, "Install Update",
                f"Downloaded: {dest.name}\n\nInstall now using dpkg?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    subprocess.Popen(["pkexec", "dpkg", "-i", str(dest)])
                    QMessageBox.information(
                        self.parent, "Installing",
                        "Installing package... Please restart the app after installation completes.",
                    )
                except Exception as e:
                    QMessageBox.warning(self.parent, "Error", f"Failed to install: {e}")
        else:
            QMessageBox.information(
                self.parent, "Download Complete",
                f"Downloaded: {dest}\n\nInstall manually:\n  sudo dpkg -i {dest}",
            )

    def _install_arch(self, dest):
        """Inform user to install Arch package."""
        QMessageBox.information(
            self.parent, "Download Complete",
            f"Downloaded: {dest}\n\nInstall manually:\n  sudo pacman -U {dest}",
        )


# --- YARA Rules Auto-Update ---

YARA_RULES_SOURCES = {
    "default": {
        "name": "Autobahn Defender Default Rules",
        "url": "https://codeberg.org/donavinschlosser/autobahn-defender/raw/branch/main/rules/default.yar",
    },
    "emotet": {
        "name": "Emotet Detection Rules",
        "url": "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/malware_emotet.yar",
    },
    "webshells": {
        "name": "Web Shell Detection Rules",
        "url": "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/exploit_webshell.yar",
    },
}


class YaraRulesDownloadWorker(QThread):
    """Background worker that downloads YARA rules from trusted sources."""

    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, sources=None):
        super().__init__()
        self.sources = sources or list(YARA_RULES_SOURCES.keys())

    def run(self):
        from scanner import RULES_DIR

        RULES_DIR.mkdir(parents=True, exist_ok=True)
        downloaded = 0
        failed = []
        total = len(self.sources)

        for i, key in enumerate(self.sources):
            if key not in YARA_RULES_SOURCES:
                continue
            source = YARA_RULES_SOURCES[key]
            self.status.emit(f"Downloading {source['name']}...")
            self.progress.emit(int((i / total) * 100))

            try:
                req = urllib.request.Request(
                    source["url"],
                    headers={"User-Agent": "AutobahnDefender/1.0"},
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    content = resp.read().decode("utf-8", errors="replace")

                # Validate that content looks like YARA rules before saving
                stripped = content.strip()
                if not stripped or not any(
                    kw in stripped for kw in ("rule ", "import ", "include ", "condition")
                ):
                    failed.append(f"{source['name']}: invalid content (not YARA rules)")
                    continue

                dest = RULES_DIR / f"{key}.yar"
                dest.write_text(content)
                downloaded += 1
            except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
                failed.append(f"{source['name']}: {e}")

        self.progress.emit(100)
        if failed:
            msg = f"Downloaded {downloaded} rule set(s). Failed: {', '.join(failed)}"
            self.finished.emit(downloaded > 0, msg)
        else:
            self.finished.emit(True, f"Successfully downloaded {downloaded} rule set(s)")