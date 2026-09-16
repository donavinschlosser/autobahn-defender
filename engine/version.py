"""Single source of truth for versions (Phase 1, Task 1.2/1.2b).

Historically three constants drifted (main.py, engine/__init__.py,
updater.py each had their own); all of them read from here now.
USER RULE: do NOT bump APP_VERSION without Donavin's explicit request.
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
APP_VERSION = "2.0.3"

# Bump ONLY when the CLI/JSON output shape changes (additive = minor).
DATA_SCHEMA_VERSION = 1

USER_AGENT = f"AutobahnDefender/{APP_VERSION}"