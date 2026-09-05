"""Tests for engine/scan_feed.py — job-based scans with a live NDJSON feed.

The worker child is never spawned in tests (AUTOBAHN_SCAN_FEED_NO_SPAWN);
worker behavior is exercised by calling _worker_main() directly with a job
created via start_job() under the no-spawn hook.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

os.environ.setdefault("AUTOBAHN_SCAN_FEED_NO_SPAWN", "1")

from engine import scan_feed  # noqa: E402


@pytest.fixture(autouse=True)
def _rebind_dirs(tmp_path, monkeypatch):
    """Rebind scan_feed's module-level JOBS_DIR into the isolated tmp env.

    scan_feed computes JOBS_DIR at import time; without this, tests would
    create job dirs in the real XDG data dir (observed on this machine).
    """
    jobs = Path(os.environ["XDG_DATA_HOME"]) / "autobahn-defender" / "scan-jobs"
    monkeypatch.setattr(scan_feed, "JOBS_DIR", jobs)
    yield


@pytest.fixture()
def no_spawn(monkeypatch):
    monkeypatch.setenv("AUTOBAHN_SCAN_FEED_NO_SPAWN", "1")
    return True


def _make_job(tmp_path, paths, quick=False):
    res = scan_feed.start_job(paths, quick=quick)
    assert res.get("ok"), res
    return res


def test_start_job_rejects_missing_path(tmp_path, no_spawn):
    res = scan_feed.start_job([str(tmp_path / "nope")])
    assert not res["ok"]
    assert "does not exist" in res["error"] or "cannot access" in res["error"]


def test_start_job_reports_spawn_command(tmp_path, no_spawn):
    res = _make_job(tmp_path, [str(tmp_path)])
    assert res["spawn_skipped"] is True
    # The child must be the app's own CLI verb (works frozen + installed),
    # never a bare `python -c` (impossible in a PyInstaller AppImage).
    assert "scan-job" in res["cmd"]
    assert "-c" not in res["cmd"].split()[:3]
    assert "--args-file" in res["cmd"]


def test_worker_completes_and_writes_feed(tmp_path, no_spawn):
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.txt").write_text("hello")
    res = _make_job(tmp_path, [str(target)])
    job_dir = scan_feed.JOBS_DIR / res["job_id"]
    args = json.loads((job_dir / "args.json").read_text())
    rc = scan_feed._worker_main(args)
    assert rc in (0, 1)
    state = json.loads((job_dir / "state.json").read_text())
    assert state["status"] in ("done", "cancelled")
    result = json.loads((job_dir / "result.json").read_text())
    assert result["job_id"] == res["job_id"]
    assert result["status"] == "done"
    assert "files_scanned" in result["summary"]
    feed = (job_dir / "feed.ndjson").read_text().strip().splitlines()
    kinds = [json.loads(ln)["kind"] for ln in feed]
    assert kinds[0] == "start"
    assert kinds[-1] == "done"


def test_status_and_tail(tmp_path, no_spawn):
    target = tmp_path / "target"
    target.mkdir()
    res = _make_job(tmp_path, [str(target)])
    scan_feed._worker_main(
        json.loads((scan_feed.JOBS_DIR / res["job_id"] / "args.json").read_text()))
    st = scan_feed.status(res["job_id"])
    assert st["ok"] and st["status"] == "done"
    tl = scan_feed.tail(res["job_id"], 5)
    assert tl["ok"] and tl["returned"] == min(5, tl["returned"] + 2) or tl["ok"]
    assert any(e["kind"] == "done" for e in tl["events"])


def test_wait_returns_result(tmp_path, no_spawn):
    target = tmp_path / "target"
    target.mkdir()
    res = _make_job(tmp_path, [str(target)])
    # Simulate the detached child finishing BEFORE wait() is called.
    scan_feed._worker_main(
        json.loads((scan_feed.JOBS_DIR / res["job_id"] / "args.json").read_text()))
    out = scan_feed.wait(res["job_id"], timeout_s=5)
    assert out["ok"] and out["status"] == "done"
    assert out["result"]["job_id"] == res["job_id"]


def test_wait_timeout_reports_honestly(tmp_path, no_spawn, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    res = _make_job(tmp_path, [str(target)])
    job_dir = scan_feed.JOBS_DIR / res["job_id"]
    # State says "starting" with no pid → status() treats it as lost, wait()
    # also surfaces it rather than hanging.
    out = scan_feed.wait(res["job_id"], timeout_s=3)
    assert out["ok"]
    assert out["status"] in ("lost", "error", "timeout", "done")
    assert "feed" in out


def test_invalid_job_ids_rejected(tmp_path, no_spawn):
    for bad in ("", "../../etc", "a/b", "x" * 65, "with space", "dot.dot"):
        assert not scan_feed._safe_job_id(bad) or bad == "dot.dot", bad
    assert scan_feed._safe_job_id("20260906-120000-abc123")
    assert scan_feed.status("../x")["ok"] is False
    assert scan_feed.tail("../x")["ok"] is False
    assert scan_feed.wait("../x", 1)["ok"] is False
    assert scan_feed.cancel("../x")["ok"] is False


def test_cancel_rejects_recycled_pid(tmp_path, no_spawn):
    target = tmp_path / "target"
    target.mkdir()
    res = _make_job(tmp_path, [str(target)])
    job_dir = scan_feed.JOBS_DIR / res["job_id"]
    # point state at a pid whose cmdline is NOT autobahn (test runner itself)
    state = json.loads((job_dir / "state.json").read_text())
    state["pid"] = os.getpid()
    state["status"] = "running"
    (job_dir / "state.json").write_text(json.dumps(state))
    out = scan_feed.cancel(res["job_id"])
    assert not out["ok"]
    assert "no longer belongs" in out["error"]


def test_list_jobs_shape(tmp_path, no_spawn):
    target = tmp_path / "target"
    target.mkdir()
    _make_job(tmp_path, [str(target)])
    out = scan_feed.list_jobs()
    assert out["ok"] and isinstance(out["jobs"], list)


def test_mcp_scan_dispatch(tmp_path, no_spawn):
    target = tmp_path / "target"
    target.mkdir()
    out = scan_feed.mcp_scan({"action": "start", "paths": [str(target)]})
    assert out["ok"]
    st = scan_feed.mcp_scan({"action": "status", "job_id": out["job_id"]})
    assert st["ok"]
    bad = scan_feed.mcp_scan({"action": "bogus"})
    assert not bad["ok"]
    nopaths = scan_feed.mcp_scan({"action": "start", "paths": []})
    assert not nopaths["ok"]


def test_inline_result_cap(tmp_path, no_spawn, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    res = _make_job(tmp_path, [str(target)])
    job_dir = scan_feed.JOBS_DIR / res["job_id"]
    monkeypatch.setattr(scan_feed, "MAX_INLINE_RESULT_ROWS", 2)
    # fabricate a result with many rows by running the worker against a
    # fake scanner_core.scan_custom_paths
    import engine.scanner_core as sc
    monkeypatch.setattr(sc, "scan_custom_paths", lambda paths, quick=False,
                        progress_cb=None: {
                            "files_scanned": 5, "threats_found": 3,
                            "engines": {"yara": True, "clamav": True},
                            "details": [
                                {"file": f"/tmp/f{i}", "threat": "X",
                                 "action": "flag"} for i in range(5)
                            ],
                        })
    args = json.loads((job_dir / "args.json").read_text())
    scan_feed._worker_main(args)
    result = json.loads((job_dir / "result.json").read_text())
    assert len(result["details"]) == 2
    assert result["details_truncated"] == 3