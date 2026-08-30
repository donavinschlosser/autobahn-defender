"""MCP server contract test (Phase 4 acceptance): scripted stdio client."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

REQS = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
     "params": {"name": "autobahn.checks.list", "arguments": {}}},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
     "params": {"name": "autobahn.checks.run",
                "arguments": {"check": "check_check_hosts"}}},
]


def test_mcp_contract():
    proc = subprocess.run(
        [sys.executable, "-m", "cli.mcp_server"],
        input="\n".join(json.dumps(r) for r in REQS) + "\n",
        capture_output=True, text=True, timeout=120,
        cwd=str(PROJECT_ROOT))
    replies = {}
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        msg = json.loads(line)
        if "id" in msg:
            replies[msg["id"]] = msg

    init = replies.get(1, {}).get("result", {})
    assert init.get("serverInfo", {}).get("name") == "autobahn-defender"

    tools = replies.get(2, {}).get("result", {}).get("tools", [])
    assert len(tools) >= 11
    names = {t["name"] for t in tools}
    assert "autobahn.remediate.plan" in names
    assert "autobahn.remediate.execute" in names

    call = replies.get(3, {}).get("result", {})
    content = json.loads(call["content"][0]["text"])
    assert len(content.get("checks", [])) > 20

    hosts = json.loads(replies[4]["result"]["content"][0]["text"])
    assert hosts.get("status") == "ok"