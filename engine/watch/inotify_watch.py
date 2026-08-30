"""Active monitor — watch package (Phase 3.4).

Tier A (default): inotify watcher on persistence-critical paths — pure
user-space, ctypes, no new deps. Watches:
  ~/Downloads           → new files (auto-scan queue)
  ~/.config/autostart   → persistence attempts
  ~/.config/systemd/user→ persistence attempts
  /etc/hosts            → tampering
  /etc/cron.d           → persistence attempts
  /etc/ssh              → ssh key/config tampering

Events are deduplicated (debounce 2s) and appended to the watch events log;
Downloads drops enqueue a scan via runner.run_scan (size-capped, budgeted).
Tier B (auditd) and Tier C (clamonacc) are separate optional system services;
Phase 5 ships unit templates. The GUI never gains a non-QThread watcher.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import select
import struct
import threading
import time
from pathlib import Path
from typing import Any, Callable

from ..paths import DATA_DIR

# inotify constants (linux/inotify.h)
IN_CLOEXEC = 0o2000000
IN_NONBLOCK = 0o4000
IN_MODIFY = 0x00000002
IN_CREATE = 0x00000100
IN_MOVED_TO = 0x00000080
IN_CLOSE_WRITE = 0x00000008
IN_DELETE = 0x00000200
IN_ATTRIB = 0x00000004
_WATCH_MASK = (IN_CREATE | IN_MOVED_TO | IN_MODIFY | IN_CLOSE_WRITE | IN_ATTRIB
               | IN_DELETE)
_EVENT_SIZE = 16  # sizeof(struct inotify_event) header
_READ_BUF = 64 * 1024

_libc_name = ctypes.util.find_library("c")
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True) if ctypes.util.find_library("c") else None


def inotify_available() -> bool:
    return _libc is not None and hasattr(_libc, "inotify_init1")


class WatchDaemon:
    """One daemon loop: inotify watchers + optional periodic intel poll.

    Both the GUI (Settings toggle) and the CLI (`watch` verbs) start/stop
    this daemon; the GUI shows its status via the alerts DB.
    """

    def __init__(self, watch_paths: list[str] | None = None,
                 on_event: Callable[[dict], None] | None = None,
                 scan_downloads: bool = True):
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._fd = -1
        self._watch_map: dict[int, str] = {}
        self._debounce: dict[str, float] = {}
        self._scan_downloads = scan_downloads
        home = Path.home()
        self.watch_paths = watch_paths or [
            str(home / "Downloads"),
            str(home / ".config" / "autostart"),
            str(home / ".config" / "systemd" / "user"),
            "/etc/hosts",
            "/etc/cron.d",
            "/etc/ssh",
        ]
        self.on_event = on_event or (lambda ev: None)
        self.last_events: list[dict] = []

    # ── lifecycle ────────────────────────────────────────────────────────
    def start(self) -> bool:
        if not inotify_available():
            return False
        self._fd = _libc.inotify_init1(IN_CLOEXEC | IN_NONBLOCK)
        if self._fd < 0:
            return False
        for path in self.watch_paths:
            self._add_watch(path)
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="autobahn-watch")
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1

    def _add_watch(self, path: str) -> bool:
        wd = _libc.inotify_add_watch(
            self._fd, path.encode(), _WATCH_MASK)
        if wd < 0:
            return False
        self._watch_map[wd] = path
        return True

    # ── event loop ───────────────────────────────────────────────────────
    def _loop(self) -> None:
        poller = select.poll()
        poller.register(self._fd, select.POLLIN)
        while not self._stop.is_set():
            try:
                events = poller.poll(1000)  # milliseconds, positional
            except (OSError, InterruptedError):
                continue
            if not events:
                continue
            try:
                buf = os.read(self._fd, _READ_BUF)
            except (BlockingIOError, OSError):
                continue
            for ev in self._parse_events(buf):
                self._handle_event(ev)

    def _parse_events(self, buf: bytes) -> list[dict]:
        out = []
        i = 0
        while i + _EVENT_HDR <= len(buf):
            wd, mask, cookie, name_len = struct.unpack_from("iIII", buf, i)
            name = buf[i + _EVENT_HDR: i + _EVENT_HDR + name_len]
            name = name.split(b"\x00")[0].decode("utf-8", "replace")
            i += _EVENT_HDR + name_len
            out.append({"wd": wd, "mask": mask, "name": name})
        return out

    def _debounced(self, path: str) -> bool:
        now = time.monotonic()
        last = self._debounce.get(path, 0.0)
        self._debounce[path] = now
        return (now - last) < 2.0

    def _handle_event(self, ev: dict) -> None:
        wd = ev["wd"]
        base = self._watch_map.get(wd)
        if not base:
            return
        name = ev["name"]
        full = os.path.join(base, name) if name else base
        if self._debounced(full):
            return
        event = {
            "ts": time.time(),
            "path": full,
            "kind": self._kind(base, ev["mask"]),
        }
        self.last_events.append(event)
        self.last_events = self.last_events[-200:]
        try:
            self.on_event(event)
        except Exception:
            pass
        # Downloads: enqueue a quick auto-scan of the new file (size-capped,
        # budgeted — the run-time never blocks the watcher thread)
        is_download = "/Downloads/" in full and os.path.isfile(full)
        if (self._scan_downloads and event["kind"] in ("created", "attrib")
                and is_download and 0 < os.path.getsize(full) < 500 * 1024 * 1024):
            threading.Thread(
                target=self._scan_one, args=(full,), daemon=True).start()

    def _scan_one(self, path: str) -> None:
        try:
            from .. import runner
            runner.run_scan([path], quick=True)
        except Exception as e:
            import logging
            logging.getLogger(__name__).debug("watch auto-scan failed: %s", e)

    @staticmethod
    def _kind(_base: str, mask: int) -> str:
        if mask & IN_CREATE or mask & IN_MOVED_TO:
            return "created"
        if mask & IN_MODIFY or mask & IN_CLOSE_WRITE:
            return "modified"
        if mask & IN_ATTRIB:
            return "attrib"
        if mask & IN_DELETE:
            return "deleted"
        return "other"


_EVENT_HDR = struct.calcsize("iIII")