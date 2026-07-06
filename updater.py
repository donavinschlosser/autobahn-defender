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

from PyQt6.QtCore import QProcess, QThread, pyqtSignal, QTimer
from PyQt6.QtWidgets import (
    QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QVBoxLayout,
)
from PyQt6.QtGui import QFont, QTextCursor

# Dark theme colors matching ui_tabs.py
BG_DARK = "#121212"
BG_CARD = "#1E1E1E"
BORDER = "#2C2C2C"
ACCENT = "#2962FF"
TEXT_PRIMARY = "#E0E0E0"
TEXT_SECONDARY = "#A0A0A0"
SUCCESS = "#4CAF50"
DANGER = "#CF6679"

APP_DIR = Path.home() / ".autobahn"
OWNER = "donavinschlosser"
REPO = "autobahn-defender"
CODEBERG_URL = f"https://codeberg.org/{OWNER}/{REPO}"
API_URL = f"https://codeberg.org/api/v1/repos/{OWNER}/{REPO}"
CURRENT_VERSION = "1.4"
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
        temp_path = self.dest_path.with_suffix(self.dest_path.suffix + ".part")
        try:
            self.dest_path.parent.mkdir(parents=True, exist_ok=True)
            req = urllib.request.Request(self.url, headers={"User-Agent": "AutobahnDefender/1.0"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                # Store temp file, then rename on success
                with open(temp_path, "wb") as f:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total > 0:
                            pct = int(downloaded * 100 / total)
                            self.progress.emit(pct)
                os.chmod(str(temp_path), 0o755)
                temp_path.rename(self.dest_path)
            self.finished.emit(True, str(self.dest_path))
        except Exception as e:
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except OSError:
                pass
            self.finished.emit(False, str(e))


class InstallProgressDialog(QDialog):
    """Dialog that shows real-time output of a pkexec install command."""

    def __init__(self, title, command, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(680, 420)
        self.setStyleSheet(f"""
            QDialog {{ background-color: {BG_DARK}; }}
            QPlainTextEdit {{
                background-color: {BG_CARD};
                color: {TEXT_PRIMARY};
                border: 1px solid {BORDER};
                border-radius: 6px;
                padding: 8px;
                font-family: monospace;
                font-size: 12px;
            }}
            QPushButton {{
                background-color: #0D47A1;
                color: white;
                border: 1px solid #093680;
                border-radius: 6px;
                padding: 8px 18px;
                font-size: 13px;
                font-weight: bold;
                min-width: 90px;
                min-height: 36px;
            }}
            QPushButton:hover {{ background-color: #0A3D8F; }}
            QPushButton:disabled {{ background-color: #455A64; color: #888; }}
            QLabel {{ color: {TEXT_SECONDARY}; background: transparent; }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Status label
        self.status_label = QLabel("Running installation...")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        # Output text area
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMaximumBlockCount(10000)
        layout.addWidget(self.output, 1)

        # Close button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.close_btn = QPushButton("Close")
        self.close_btn.setEnabled(False)
        self.close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(self.close_btn)
        layout.addLayout(btn_layout)

        # Start the process
        pkexec_path = shutil.which("pkexec")
        full_cmd = None
        use_yay = False
        if not pkexec_path:
            # On Arch-based systems without pkexec (like CachyOS), try yay/sudo
            distro_id, pkg_mgr, _ = detect_distro()
            if pkg_mgr == "pacman" and shutil.which("yay"):
                full_cmd = ["yay", "-S", "--noconfirm"] + command
                use_yay = True
            elif shutil.which("sudo"):
                full_cmd = ["sudo"] + command
            else:
                self.status_label.setText("Cannot install: pkexec, yay, or sudo not found.")
                self.status_label.setStyleSheet(
                    f"color: {DANGER}; background: transparent;"
                )
                self.output.appendPlainText(
                    "No privilege escalation tool found (pkexec, yay, or sudo).\\n\\n"
                    "Please install manually from a terminal:\\n"
                    f"  {' '.join(command)}"
                )
                self.close_btn.setEnabled(True)
                return

        self._process = QProcess(self)
        self._process.setProcessChannelMode(
            QProcess.ProcessChannelMode.MergedChannels
        )
        self._process.readyReadStandardOutput.connect(self._on_output)
        self._process.finished.connect(self._on_finished)
        self._process.errorOccurred.connect(self._on_error)

        if not full_cmd:
            full_cmd = [pkexec_path] + command
        self._process.start(full_cmd[0], full_cmd[1:])

    def _on_output(self):
        data = self._process.readAllStandardOutput()
        text = bytes(data).decode("utf-8", errors="replace")
        for line in text.splitlines():
            if line.strip():
                self.output.appendPlainText(line)
        # Auto-scroll to bottom
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.output.setTextCursor(cursor)

    def _on_finished(self, exit_code, _exit_status):
        self.close_btn.setEnabled(True)
        if exit_code == 0:
            self.status_label.setText("Completed successfully.")
            self.status_label.setStyleSheet(
                f"color: {SUCCESS}; background: transparent; font-weight: bold;"
            )
            self.output.appendPlainText("\n✓ Installation completed successfully.")
        else:
            self.status_label.setText(f"Installation failed (exit code {exit_code}).")
            self.status_label.setStyleSheet(
                f"color: {DANGER}; background: transparent; font-weight: bold;"
            )
            self.output.appendPlainText(
                f"\n✗ Installation failed (exit code {exit_code})."
            )

    def _on_error(self, error):
        self.close_btn.setEnabled(True)
        self.status_label.setText(f"Process error: {error}")
        self.status_label.setStyleSheet(
            f"color: {DANGER}; background: transparent; font-weight: bold;"
        )


class DownloadProgressDialog(QDialog):
    """Modal dialog showing download progress with a progress bar.

    Call show() or exec() after starting the worker.
    Auto-closes when the worker finishes successfully.
    """

    def __init__(self, worker, title="Downloading...", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(480)
        self.setModal(True)
        self.setStyleSheet(f"""
            QDialog {{ background-color: {BG_DARK}; }}
            QLabel {{ color: {TEXT_PRIMARY}; background: transparent; }}
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
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        self.status_label = QLabel("Downloading...")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        worker.progress.connect(self.progress_bar.setValue)
        worker.progress.connect(
            lambda p: self.status_label.setText(f"Downloading... {p}%")
        )
        worker.finished.connect(self._on_finished)

    def _on_finished(self, success, result):
        if success:
            self.accept()
        else:
            self.progress_bar.setValue(0)
            self.status_label.setText(f"Download failed: {result}")
            self.status_label.setStyleSheet(
                f"color: {DANGER}; background: transparent;"
            )
def detect_distro():
    """Detect the Linux distribution and return (distro_id, package_manager, install_cmd_func)."""
    distro_id = ""
    distro_id_like = ""
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("ID="):
                    distro_id = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("ID_LIKE="):
                    distro_id_like = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass

    # Normalize to lowercase for comparison
    distro_id_lower = distro_id.lower()
    distro_id_like_lower = distro_id_like.lower()

    if distro_id_lower in ("arch", "cachyos", "manjaro", "endeavouros") or "arch" in distro_id_lower:
        return distro_id, "pacman", "pacman"
    elif distro_id_lower in ("debian", "ubuntu", "linuxmint", "pop", "zorin") or "debian" in distro_id_lower:
        return distro_id, "apt", "dpkg"
    elif distro_id_lower in ("fedora", "rhel", "centos", "rocky", "almalinux") or "fedora" in distro_id_lower:
        return distro_id, "dnf", "dnf"
    return distro_id, "unknown", "unknown"


def detect_install_method():
    """Detect how Autobahn Defender was installed.

    Returns one of: 'appimage', 'deb', 'arch', 'source', 'unknown'
    """
    appimage_path = Path("/proc/self/exe").resolve()
    is_appimage = os.environ.get("APPIMAGE") or str(appimage_path).endswith(".AppImage")

    if is_appimage:
        return "appimage"

    # Check dpkg database for deb-based installs
    if shutil.which("dpkg"):
        try:
            result = subprocess.run(
                ["dpkg", "-l", "autobahn-defender"],
                capture_output=True, text=True, timeout=5,
            )
            if "autobahn-defender" in result.stdout and "ii" in result.stdout:
                return "deb"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Check for pacman database for Arch-based installs
    if shutil.which("pacman"):
        try:
            result = subprocess.run(
                ["pacman", "-Q", "autobahn-defender"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                return "arch"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Check if the binary is at a system path (deb/arch install path)
    system_binary = Path("/usr/bin/autobahn-defender")
    if system_binary.exists():
        return "deb"  # Most likely deb install via /usr/bin

    return "unknown"


def choose_package_asset(release_info):
    """Choose the best download asset for the current system.

    Detects how the app was installed and picks the matching package type.
    Falls back to AppImage if no matching package is found.
    """
    install_method = detect_install_method()

    if install_method == "appimage" and release_info.get("appimage_url"):
        return "appimage", release_info["appimage_url"]

    if install_method == "deb" and release_info.get("deb_url"):
        return "deb", release_info["deb_url"]

    if install_method == "arch" and release_info.get("arch_url"):
        return "arch", release_info["arch_url"]

    # Fallback: try to match by package manager
    _, pkg_mgr, _ = detect_distro()

    if pkg_mgr == "dpkg" and release_info.get("deb_url"):
        return "deb", release_info["deb_url"]
    elif pkg_mgr == "pacman" and release_info.get("arch_url"):
        return "arch", release_info["arch_url"]
    elif release_info.get("appimage_url"):
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
        """Download the package and install it with progress shown."""
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

        # Show download progress dialog
        self._download_worker = DownloadWorker(pkg_url, dest)
        dialog = DownloadProgressDialog(
            self._download_worker, "Downloading Update...", self.parent,
        )
        self._download_worker.start()
        result = dialog.exec()

        if result != QDialog.DialogCode.Accepted:
            return

        # Install the downloaded package
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
        """Install .deb package using pkexec/sudo with progress shown.
        Detects if we're in a deb-based system and auto-installs.
        """
        if not shutil.which("pkexec") and not shutil.which("sudo"):
            QMessageBox.information(
                self.parent, "Install Update",
                f"Downloaded: {dest.name}\n\nInstall manually:\n  sudo dpkg -i {dest}",
            )
            return

        if shutil.which("pkexec"):
            dialog = InstallProgressDialog(
                "Installing DEB Package",
                ["dpkg", "-i", str(dest)],
                self.parent,
            )
            dialog.exec()
        elif shutil.which("sudo"):
            try:
                subprocess.run(
                    ["sudo", "dpkg", "-i", str(dest)],
                    capture_output=True, text=True, timeout=120,
                )
                QMessageBox.information(
                    self.parent, "Update Complete",
                    "Updated successfully. Please restart the application.",
                )
            except subprocess.TimeoutExpired:
                QMessageBox.warning(
                    self.parent, "Update Failed",
                    f"Installation timed out.\nInstall manually:\n  sudo dpkg -i {dest}",
                )
            except Exception as e:
                QMessageBox.warning(
                    self.parent, "Update Failed",
                    f"Installation failed: {e}\n\nInstall manually:\n  sudo dpkg -i {dest}",
                )

    def _install_arch(self, dest):
        """Install Arch package using sudo pacman -U with progress shown."""
        if not shutil.which("sudo"):
            QMessageBox.information(
                self.parent, "Install Update",
                f"Downloaded: {dest}\n\nInstall manually:\n  sudo pacman -U {dest}",
            )
            return

        try:
            result = subprocess.run(
                ["sudo", "pacman", "-U", "--noconfirm", str(dest)],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                QMessageBox.information(
                    self.parent, "Update Complete",
                    "Updated successfully. Please restart the application.",
                )
            else:
                QMessageBox.warning(
                    self.parent, "Update Failed",
                    f"Installation failed (exit {result.returncode}).\n\n"
                    f"Install manually:\n  sudo pacman -U {dest}\n\n"
                    f"Error: {result.stderr[:300]}",
                )
        except subprocess.TimeoutExpired:
            QMessageBox.warning(
                self.parent, "Update Failed",
                f"Installation timed out.\n\nInstall manually:\n  sudo pacman -U {dest}",
            )
        except Exception as e:
            QMessageBox.warning(
                self.parent, "Update Failed",
                f"Installation failed: {e}\n\nInstall manually:\n  sudo pacman -U {dest}",
            )
