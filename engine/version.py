"""Single source of truth for versions (Phase 1, Task 1.2/1.2b).

Historically three constants drifted (main.py, engine/__init__.py,
updater.py each had their own); all of them read from here now.
USER RULE: do NOT bump APP_VERSION without Donavin's explicit request.
2.0.4 (Sep 20 2026): full-system scan performance + sudo correctness fix.
User report (Linux Mint 22.2, ASUS ZenBook): a Full System scan collected
6,061,291 files and then sat at "YARA: 0/6,061,291 files scanned" at 0%
until abandoned — not a hang, a ~85x slowdown. Root cause: BOTH scan paths
asked "is this file package-owned?" with a per-file subprocess
(`dpkg -S <file>`, ~300 ms measured), executed for every file under /usr,
/bin, /sbin, /lib, /opt, /boot (56% of a real tree). Measured YARA phase:
11.8 files/s with the call vs 1,009 files/s without it. Fixed with an
in-process ownership index built once from /var/lib/dpkg/info/*.list
(619,851 paths in ~0.3 s; differentially verified against dpkg-query on
1,500 real files: 0 false negatives). Also in 2.0.4:
  * The YARA phase submitted EVERY file as a future before consuming any
    result (~10 GB RSS and ~60 s of dead time at 6M files; MemoryError on
    an 8 GB machine) — replaced with a bounded in-flight window.
  * The file list was walked TWICE per GUI scan (~14 min per pass at this
    scale) — now collected once and shared by both phases.
  * /media, /mnt, /run/media, /timeshift, /timeshift-btrfs and container
    stores are skipped by ABSOLUTE PATH during full-system scans (never by
    bare directory name — a user folder named "media" must still be
    scanned). The reporter's 6M count was largely snapshots + attached
    drives re-scanning identical data.
  * `sudo autobahn-defender` (bare) opened a root GUI that held the
    terminal open — users read it as a freeze and tried to kill it. Now
    prints the correct full-scan command instead; `--gui` opts back in.
  * App data resolves to the SUDO_USER's home, so a root scan no longer
    strands quarantined files, the ledger and history in /root/.autobahn
    where the user's GUI could never see them.
  * XDG_RUNTIME_DIR is set before Qt initialises, silencing the
    QStandardPaths warning seen in the report.
  * Latent non-Debian defect fixed: a missing `dpkg` binary raised
    FileNotFoundError that was swallowed, silently re-enabling
    auto-quarantine of package files on Arch/Fedora. Unknown ownership is
    now fail-safe (review-first).
2.0.3 (Sep 16 2026): fix parallel ClamAV scanner defects — the scan
try/except/finally block sat OUTSIDE the batch loop (a sibling of the `while`
instead of its child), so worker threads that found the shared queue already
empty died with UnboundLocalError on 'file_list_path' (user-reported
"Exception in thread Thread-N"); the orphaned block also referenced
'clam_env', which was never bound in that scope, killing every surviving
batch with a NameError — parallel ClamAV scans reported 0 files scanned.
Scan block moved inside the loop; clam_env bound at function scope. YARA
coverage was never affected (separate code path). Structural + runtime
regression tests added.
2.0.2 (Sep 7 2026): self-contained AppImage (bundled ClamAV engine, direct
HTTPS definitions download) + eCryptfs scan-hang fix (stderr pipe deadlock,
skip raw encrypted stores, stall watchdog, queue-based batching). Bumped at
Donavin's explicit request.
"""
APP_VERSION = "2.0.4"

# Bump ONLY when the CLI/JSON output shape changes (additive = minor).
DATA_SCHEMA_VERSION = 1

USER_AGENT = f"AutobahnDefender/{APP_VERSION}"