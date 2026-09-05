"""Single source of truth for versions (Phase 1, Task 1.2/1.2b).

Historically three constants drifted (main.py, engine/__init__.py,
updater.py each had their own); all of them read from here now.
USER RULE: do NOT bump APP_VERSION without Donavin's explicit request.
2.0.1 (Sep 6 2026): hotfix release — AppImage shipped without the three GUI
tabs (ai_agent_tab/security_tab/security_news_tab) and without yara-python
(Rootkit scan force-close); adds the autobahn.scan MCP tool (detached
scan jobs + live feed + wait). Bumped at Donavin's explicit request.
"""
APP_VERSION = "2.0.1"

# Bump ONLY when the CLI/JSON output shape changes (additive = minor).
DATA_SCHEMA_VERSION = 1

USER_AGENT = f"AutobahnDefender/{APP_VERSION}"