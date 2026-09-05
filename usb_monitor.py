"""
Autobahn Defender - USB Device Monitor
Monitors /media and /mnt for newly mounted USB drives and auto-scans them.
"""

import os
import time
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal


class USBMonitorWorker(QThread):
    """Background worker that polls /media and /mnt for new mounts."""

    new_device = pyqtSignal(str)  # Emits the mount point path

    def __init__(self, poll_interval=3):
        super().__init__()
        self.poll_interval = poll_interval
        self._running = True

    def run(self):
        # Thread guard: an exception escaping QThread.run hard-closes the
        # process in PyQt6 (see scanner.ScanWorker.run).
        try:
            self._run_inner()
        except Exception:
            self._running = False  # die quietly; the UI can restart the poll

    def _run_inner(self):
        known = self._get_mounts()
        while self._running:
            # Use a shorter sleep with check for stop to improve responsiveness
            for _ in range(self.poll_interval * 10):  # Check every 0.1s for up to poll_interval seconds
                if not self._running:
                    break
                time.sleep(0.1)
            if not self._running:
                break
            current = self._get_mounts()
            new_mounts = current - known
            for mount in new_mounts:
                # Small delay to let filesystem settle after mount
                time.sleep(0.5)  # Reduced from 1s to 0.5s
                if os.path.isdir(mount):
                    self.new_device.emit(mount)
            known = current

    def stop(self):
        self._running = False

    def _get_mounts(self):
        """Return set of current mount points under /media and /mnt."""
        mounts = set()
        # Include additional mount patterns: /media/user/ and /media/volume
        for base in ("/media", "/media/user", "/run/media", "/mnt", "/media/volume"):
            base_path = Path(base)
            if not base_path.exists():
                continue
            try:
                for entry in base_path.iterdir():
                    if entry.is_dir():
                        try:
                            for sub in entry.iterdir():
                                norm = os.path.normpath(str(sub))
                                if sub.is_dir() and self._is_mount(norm):
                                    mounts.add(norm)
                        except PermissionError:
                            pass
                        norm = os.path.normpath(str(entry))
                        if self._is_mount(norm):
                            mounts.add(norm)
            except PermissionError:
                pass
        return mounts

    @staticmethod
    def _is_mount(path):
        """Check if a path is an actual mount point."""
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == path:
                        return True
        except OSError:
            pass
        return os.path.ismount(path)