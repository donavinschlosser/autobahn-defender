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
        known = self._get_mounts()
        while self._running:
            time.sleep(self.poll_interval)
            if not self._running:
                break
            current = self._get_mounts()
            new_mounts = current - known
            for mount in new_mounts:
                # Small delay to let filesystem settle after mount
                time.sleep(1)
                if os.path.isdir(mount):
                    self.new_device.emit(mount)
            known = current

    def stop(self):
        self._running = False

    def _get_mounts(self):
        """Return set of current mount points under /media and /mnt."""
        mounts = set()
        for base in ("/media", "/mnt", "/run/media"):
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