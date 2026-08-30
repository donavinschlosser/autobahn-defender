"""Single source of truth for versions (Phase 1, Task 1.2/1.2b).

Historically three constants drifted (main.py, engine/__init__.py,
updater.py each had their own); all of them read from here now.
USER RULE: do NOT bump APP_VERSION without Donavin's explicit request.
The 2.0.0 .deb was never actually released — this IS the 2.0 release build.
"""
APP_VERSION = "2.0.0"

# Bump ONLY when the CLI/JSON output shape changes (additive = minor).
DATA_SCHEMA_VERSION = 1

USER_AGENT = f"AutobahnDefender/{APP_VERSION}"