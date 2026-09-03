"""LM Studio 60s bridge, round 2: audit must never block, server must not wedge.

Round-1 fix made autobahn.cve.scan cache-first; the vuln AUDIT profile then
surfaced as a second bypass (live OSV query + network patch check inline,
advisor._run_vulnerability_scan), which — combined with the serial request
loop — domino-timed-out every fast tool behind it (observed Sep 4 2026 on
LM Studio: audit vuln → 60 s abort; alerts/audit/remediate.plan behind it
all died with MCP -32001). These tests pin both fixes:
  1. MCP audit(vuln) with cache present = instant, cve from cache,
     patches skipped, no live scan.
  2. MCP audit(vuln) with no cache = instant honest envelope + refresh kick.
  3. The REAL stdio loop answers a fast request while a slow one is in
     flight (worker pool; fast reply arrives BEFORE the slow reply).
"""
import json
import os
import sys
import threading
import time
import io
from unittest import mock

os.environ["AUTOBAHN_CACHE_NO_SPAWN"] = "1"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import scan_cache  # noqa: E402

FAKE = {"ecosystem": "Ubuntu:24.04", "packages_checked": 2628,
        "vulnerabilities_found": 0, "raw_count": 0, "filtered_out": 0,
        "vulnerabilities": []}


def _redirect(tmp_path):
    scan_cache.CACHE_PATH = tmp_path / "scan-cache.json"
    scan_cache.LOCK_PATH = tmp_path / "scan-cache.lock"
    scan_cache.LASTERR_PATH = tmp_path / "scan-cache.lasterr"


def _call(mcp, name: str, arguments: dict, msg_id: int = 1):
    reply = mcp._handle({"jsonrpc": "2.0", "id": msg_id, "method": "tools/call",
                         "params": {"name": name, "arguments": arguments}})
    assert reply is not None and "result" in reply
    return json.loads(reply["result"]["content"][0]["text"])


def test_audit_vuln_cache_first(tmp_path):
    import cli.mcp_server as mcp
    _redirect(tmp_path)
    scan_cache.store(FAKE)
    t0 = time.time()
    out = _call(mcp, "autobahn.audit", {"profile": "vuln"})
    dt = time.time() - t0
    assert out["cve_source"] == "cache"
    assert out["patches_skipped"] is True
    assert out["refresh_started"] is False
    assert isinstance(out["score"], int)
    assert dt < 10  # local work only — no OSV round-trip


def test_audit_vuln_cache_miss_honest(tmp_path):
    import cli.mcp_server as mcp
    _redirect(tmp_path)
    out = _call(mcp, "autobahn.audit", {"profile": "vuln"})
    assert out["cve_source"] == "unavailable"
    assert out["refresh_started"] is False  # spawn suppressed by env hook
    assert "few minutes" in json.dumps(out)


def test_audit_other_profiles_unchanged(tmp_path):
    import cli.mcp_server as mcp
    _redirect(tmp_path)
    out = _call(mcp, "autobahn.audit", {"profile": "hardening"})
    assert "score" in out and "findings" in out
    assert "cve_source" not in out  # untouched path keeps old shape


def test_audit_schema_keeps_live_flag():
    import cli.mcp_server as mcp
    tool = next(t for t in mcp.TOOLS if t["name"] == "autobahn.audit")
    props = tool["inputSchema"]["properties"]
    assert props["live"]["type"] == "boolean"
    assert "profile" not in tool["inputSchema"].get("required", [])


def test_real_loop_parallel_not_serial():
    """Drive the ACTUAL stdio loop: slow tool in flight, fast tool answers
    before it. Under the old serial loop the fast reply would necessarily
    come after the slow one; with workers, order flips — proof."""
    import cli.mcp_server as mcp

    def _slow(_: dict) -> dict:
        time.sleep(1.5)
        return {"slow": True}

    restored = dict(mcp._DISPATCH)
    mcp._DISPATCH["autobahn.doctor"] = _slow
    arrivals: dict[int, float] = {}
    out_buf = io.StringIO()
    t0 = time.monotonic()

    orig_write = out_buf.write

    def timed_write(s):
        if '"id":' in s:
            try:
                mid = json.loads(s).get("id")
                if mid is not None:
                    arrivals[mid] = time.monotonic() - t0
            except json.JSONDecodeError:
                pass
        return orig_write(s)

    out_buf.write = timed_write  # type: ignore[method-assign]
    stdin = io.StringIO("\n".join([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "autobahn.doctor", "arguments": {}}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "autobahn.alerts", "arguments": {}}}),
    ]) + "\n")
    try:
        with mock.patch.object(mcp.sys, "stdin", stdin), \
             mock.patch.object(mcp.sys, "stdout", out_buf), \
             mock.patch.object(mcp.sys, "stderr", io.StringIO()):
            rc = mcp.run_mcp_server()
        assert rc == 0
    finally:
        mcp._DISPATCH.update(restored)

    assert set(arrivals) == {1, 2}
    # THE assertion: fast (alerts, id=2) landed before slow (doctor, id=1)
    assert arrivals[2] < arrivals[1], (
        f"serial behavior: fast={arrivals[2]:.2f}s slow={arrivals[1]:.2f}s")
    assert arrivals[2] < 1.0  # fast tool answered ~immediately, not blocked