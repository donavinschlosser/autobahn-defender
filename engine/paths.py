"""Neutral path constants — importable headless (no Qt, no scanner import).

audit 2026-08-31 F-6: engine/checks.py used to `from scanner import RULES_DIR`,
dragging PyQt6 + quarantine into every headless import. All shared app paths
live here now; scanner.py keeps its own aliases for backward compatibility.

v2.0.4 — sudo data-dir resolution:
Running the app under sudo used to send ALL app state to /root/.autobahn:
quarantined files landed in /root/.autobahn/quarantine where the user's GUI
could never see or restore them, the detection ledger split in two, and the
history DB diverged. The reporter was running `sudo autobahn-defender`, so
this was live.

Every module now resolves the app data directory through resolve_app_dir(),
which prefers the SUDO-invoking user's home when running as root. Files this
process creates there are handed back to that user (hand_over_if_root) so a
root scan doesn't leave root-owned state in a user directory.
"""
from __future__ import annotations

import os
from pathlib import Path


def _invoking_user():
    """Return (uid, gid, home) of the user who invoked sudo, or None.

    sudo exports SUDO_USER/SUDO_UID/SUDO_GID for the command it runs. When
    this process is NOT root, or was not started via sudo, there is no
    invoking user and callers fall back to the current process's own home.
    """
    if os.geteuid() != 0:
        return None
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user or sudo_user == "root":
        return None
    try:
        import pwd
        entry = pwd.getpwnam(sudo_user)
    except (KeyError, ImportError):
        return None
    # Prefer the numeric ids sudo recorded (they survive renamed accounts).
    try:
        uid = int(os.environ.get("SUDO_UID", entry.pw_uid))
        gid = int(os.environ.get("SUDO_GID", entry.pw_gid))
    except (TypeError, ValueError):
        uid, gid = entry.pw_uid, entry.pw_gid
    return (uid, gid, Path(entry.pw_dir))


def resolve_home() -> Path:
    """Home directory to use for app state.

    The invoking user's home when this process runs as root via sudo,
    otherwise the current user's home.
    """
    invoked = _invoking_user()
    if invoked is not None:
        return invoked[2]
    return Path.home()


def resolve_app_dir() -> Path:
    """~/.autobahn for the user who actually owns this installation."""
    return resolve_home() / ".autobahn"


INVOKING_UID_GID = None  # filled below; helper for hand-over


def hand_over_if_root(path) -> None:
    """Give `path` (and its parent chain up to home) to the invoking user.

    A root-run scan writes quarantined files, a ledger and history rows into
    the user's data dir. Without this they would be root-owned and the GUI
    (running as the user) could not update or restore them.
    """
    invoked = _invoking_user()
    if invoked is None:
        return
    uid, gid, _home = invoked
    try:
        os.chown(str(path), uid, gid)
    except OSError:
        return
    # Directories need to stay traversable/writable by the owner.
    try:
        if os.path.isdir(path):
            os.chmod(str(path), 0o700)
    except OSError:
        pass


# App data (~/.autobahn — scanner definitions, rules, quarantine, history DB)
APP_DIR = resolve_app_dir()
RULES_DIR = APP_DIR / "rules"
DEFS_DIR = APP_DIR / "definitions"
QUARANTINE_DIR = APP_DIR / "quarantine"
HISTORY_DB = APP_DIR / "history.db"

# Machine-readable intel data root. Fixed per audit A-8: the previous code
# used $XDG_DATA_HOME *verbatim* (dropping the app subdir) when the env var
# was set, dumping state into the shared XDG root.
#
# v2.0.4: under sudo, $XDG_DATA_HOME / $HOME belong to root — resolve against
# the invoking user's home instead, for the same reason as APP_DIR above.
if os.environ.get("XDG_DATA_HOME") and _invoking_user() is None:
    _XDG_DATA_ROOT = os.environ["XDG_DATA_HOME"]
else:
    _XDG_DATA_ROOT = str(resolve_home() / ".local" / "share")
DATA_DIR = Path(_XDG_DATA_ROOT) / "autobahn-defender"
INTEL_DIR = DATA_DIR / "intel"
REPORTS_DIR = DATA_DIR / "reports"
BLACKLIST_DIR = DATA_DIR / "blacklist"
