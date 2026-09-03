"""LM Studio 60s MCP-bridge workaround: scan-cache contract tests.

LM Studio's stdio bridge hard-codes DEFAULT_REQUEST_TIMEOUT_MSEC = 0xea60
(60 s) with no override; live OSV scans take minutes. The MCP cve.scan tool
must therefore answer INSTANTLY by default (cache) and never block.
Paths are redirected to tmp_path so tests never touch real user data;
AUTOBAHN_CACHE_NO_SPAWN=1 keeps tests from spawning real scans.
"""
import json
import os
import sys

os.environ.setdefault("AUTOBAHN_CACHE_NO_SPAWN", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import scan_cache  # noqa: E402

FAKE = {"ecosystem": "Ubuntu:24.04", "packages_checked": 2628,
        "vulnerabilities_found": 0, "raw_count": 0, "filtered_out": 0,
        "vulnerabilities": []}


def _redirect(tmp_path):
    scan_cache.CACHE_PATH = tmp_path / "scan-cache.json"
    scan_cache.LOCK_PATH = tmp_path / "scan-cache.lock"
    scan_cache.LASTERR_PATH = tmp_path / "scan-cache.lasterr"


def test_store_load_roundtrip(tmp_path):
    _redirect(tmp_path)
    scan_cache.store(FAKE, completed_in_s=181.0)
    data = scan_cache.load()
    assert data is not None
    assert data["result"]["packages_checked"] == 2628
    age = scan_cache.age_seconds()
    assert age is not None
    assert 0 < age < 5


def test_rejects_malformed_cache(tmp_path):
    _redirect(tmp_path)
    scan_cache.CACHE_PATH.write_text('{"stored_at": 1, "result": {"foo": 1}}')
    assert scan_cache.load() is None
    scan_cache.CACHE_PATH.write_text("not json at all")
    assert scan_cache.load() is None


def test_auto_cache_miss_never_spawns_or_blocks(tmp_path):
    _redirect(tmp_path)
    out = scan_cache.auto()
    assert out["source"] == "unavailable"
    assert out["refresh_started"] is False  # env hook suppresses spawn
    assert out["result"] is None
    assert "again in a few minutes" in out["note"]


def test_auto_cache_hit_instant(tmp_path):
    _redirect(tmp_path)
    scan_cache.store(FAKE)
    out = scan_cache.auto()
    assert out["source"] == "cache"
    assert out["result"]["packages_checked"] == 2628
    assert out["refresh_started"] is False  # fresh cache: no refresh
    assert "warnings" not in out


def test_auto_stale_cache_signals_refresh(tmp_path):
    _redirect(tmp_path)
    scan_cache.store(FAKE)
    data = json.loads(scan_cache.CACHE_PATH.read_text())
    data["stored_at"] -= scan_cache.MAX_AGE_S + 7200
    scan_cache.CACHE_PATH.write_text(json.dumps(data))
    out = scan_cache.auto()
    assert out["source"] == "cache"
    assert "warnings" in out
    assert out["refresh_started"] is False  # spawn suppressed by env hook


def test_stale_pid_lock_is_not_in_flight(tmp_path):
    _redirect(tmp_path)
    scan_cache.LOCK_PATH.write_text("999999")  # pid that cannot exist
    assert scan_cache._refresh_in_flight() is False
    assert not scan_cache.LOCK_PATH.exists()  # stale lock cleaned up


def test_mcp_tool_default_is_cache_first(tmp_path):
    import cli.mcp_server as mcp
    _redirect(tmp_path)
    scan_cache.store(FAKE)
    reply = mcp._handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                         "params": {"name": "autobahn.cve.scan",
                                    "arguments": {}}})
    out = json.loads(reply["result"]["content"][0]["text"])
    assert out["source"] == "cache"
    assert out["result"] is not None
    assert out["result"]["vulnerabilities_found"] == 0


def test_tools_list_declares_refresh_flag():
    import cli.mcp_server as mcp
    tool = next(t for t in mcp.TOOLS if t["name"] == "autobahn.cve.scan")
    assert tool["inputSchema"]["properties"]["refresh"]["type"] == "boolean"
    assert "LM Studio" in tool["description"] or "60s" in tool["description"]