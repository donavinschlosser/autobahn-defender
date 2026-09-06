"""Single source of truth for versions (Phase 1, Task 1.2/1.2b).

Historically three constants drifted (main.py, engine/__init__.py,
updater.py each had their own); all of them read from here now.
USER RULE: do NOT bump APP_VERSION without Donavin's explicit request.
2.0.2 (Sep 7 2026): self-contained AppImage (bundled ClamAV engine, direct
HTTPS definitions download) + eCryptfs scan-hang fix (stderr pipe deadlock,
skip raw encrypted stores, stall watchdog, queue-based batching). Bumped at
Donavin's explicit request.
"""
APP_VERSION = "2.0.2"

# Bump ONLY when the CLI/JSON output shape changes (additive = minor).
DATA_SCHEMA_VERSION = 1

USER_AGENT = f"AutobahnDefender/{APP_VERSION}"