"""
Autobahn Defender CLI package (headless front-end over engine.runner).

Three front-ends, one engine:  GUI (main.py) · CLI (this package) · MCP server.
The CLI is stdlib-only (argparse), Python 3.10+, no pip installs.
"""
from engine.version import APP_VERSION as __version__  # noqa: F401