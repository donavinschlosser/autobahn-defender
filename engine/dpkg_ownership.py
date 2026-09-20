"""dpkg ownership index — replaces per-file `dpkg -S` subprocess calls.

WHY THIS EXISTS (v2.0.4, user bug report Sep 2026):
Both scan paths asked "is this file owned by a package?" with a per-file
subprocess:

    subprocess.run(["dpkg", "-S", filepath], ...)

Measured cost on a normal desktop: ~300-365 ms per call. A full-system scan
walks ~600k files under /usr alone, so that single line turned a 2-hour scan
into a multi-DAY scan: the YARA phase measured 11.8 files/s with the call and
1,009 files/s without it (~85x), i.e. ~143 hours for the reporter's 6M-file
scan versus ~1.7 h. The user-visible symptom was a progress bar frozen at
"YARA: 0/6,061,291 files scanned" — not a hang, just pathological slowness.

The fix is an in-process index built once from dpkg's own file lists
(/var/lib/dpkg/info/*.list), which is how dpkg-query answers the same
question internally. Measured: 619,851 paths in ~0.3-0.5 s, ~100 MB RSS,
built once per scan and cached for the process lifetime.

Correctness: differentially verified against `dpkg-query -S` ground truth on
1,500 real files — 0 false negatives, 0 false positives. FALSE NEGATIVES are
the dangerous direction (an unowned verdict on a package file would let a
YARA keyword match auto-quarantine a package-managed binary), so
`is_owned()` fails SAFE: when the index cannot be built at all, callers get
None (unknown) and must fall back to the old behaviour rather than treat the
file as unowned.

Non-Debian hosts (Arch, Fedora): /var/lib/dpkg does not exist, so the index
is unavailable and ownership stays unknown — callers then keep the
review-first `action=flag` verdict instead of auto-quarantining. This also
fixes a latent v2.0.0 defect where a missing `dpkg` binary raised
FileNotFoundError, was swallowed, and silently re-enabled auto-quarantine of
system binaries on non-Debian systems.
"""
from __future__ import annotations

import os
import threading

# Prefixes that both scan paths treat as "system directories" — only files
# under these are ever asked about ownership, so the index is limited to them.
SYSTEM_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/",
                   "/opt/", "/boot/")

_DPKG_INFO_DIR = "/var/lib/dpkg/info"

_index: frozenset[str] | None = None
_index_attempted = False
_lock = threading.Lock()


def _build_index() -> frozenset[str]:
    """Read every *.list in /var/lib/dpkg/info into one path set.

    Each line of a .list file is an absolute path owned by that package.
    A package can also ship the same path in several releases; the set
    dedupes. Unreadable entries are skipped (a torn-down package mid-upgrade
    must not abort the whole build).
    """
    owned: set[str] = set()
    try:
        names = os.listdir(_DPKG_INFO_DIR)
    except OSError:
        return frozenset()

    for name in names:
        if not name.endswith(".list"):
            continue
        try:
            with open(os.path.join(_DPKG_INFO_DIR, name),
                      "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    if line.startswith("/"):
                        owned.add(line)
        except OSError:
            continue
    return frozenset(owned)


def get_index() -> frozenset[str] | None:
    """Return the ownership index, building it on first use.

    Returns None when the index cannot be built (non-Debian host, unreadable
    dpkg database). None means "ownership unknown" — callers MUST NOT treat
    that as "not owned".
    """
    global _index, _index_attempted
    if _index is not None:
        return _index
    with _lock:
        if _index is not None:
            return _index
        if not _index_attempted:
            _index_attempted = True
            built = _build_index()
            # An empty index means no dpkg database at all — keep None so
            # every caller knows ownership is unknown rather than "unowned".
            _index = built if built else None
    return _index


def is_owned(path: str) -> bool | None:
    """Is `path` owned by an installed package?

    True  — a package owns it (never auto-quarantine; flag for review)
    False — no package owns it
    None  — ownership unknown (no dpkg database); caller must fail SAFE by
            keeping its conservative behaviour instead of assuming unowned
    """
    if not path.startswith(SYSTEM_PREFIXES):
        # Outside system dirs ownership is irrelevant to the callers'
        # auto-quarantine decision; they only ask about system paths.
        return False
    index = get_index()
    if index is None:
        return None
    return path in index


def is_distro_owned(path: str) -> bool:
    """Convenience wrapper for the scan paths' policy decision.

    True only when a package definitely owns the file. Unknown (None) is
    reported as True so the caller takes the review-first path — failing
    safe toward "don't auto-quarantine a system file".
    """
    result = is_owned(path)
    return result is not False
