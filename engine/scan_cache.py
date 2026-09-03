"""Scan-result cache for slow network scans behind short-timeout MCP hosts.

Why this exists (Sep 2026, LM Studio incident): LM Studio's MCP stdio bridge
hard-codes a 60 s request timeout (DEFAULT_REQUEST_TIMEOUT_MSEC = 0xea60 in
mcpbridgeworker.js, app 0.4.21) and the Cursor-style mcp.json format exposes
no timeout field. A live OSV.dev CVE scan takes ~3 minutes on typical
broadband, so autobahn.cve.scan can never answer inside that window — the
bridge raises MCP error -32001 (Request timed out) while the scan keeps
grinding. Strategy: the MCP tool serves the last COMPLETED scan instantly
and, when the cache is missing/stale, kicks a DETACHED background refresh
that survives the MCP server process. Long-timeout hosts (Hermes, CI) can
pass refresh=true to force a live blocking scan.

Constraints: stdlib only; NEVER write to stdout (the MCP stdio protocol owns
stdout); cache writes are atomic (tmp + os.replace); the refresh lock is a
pidfile with liveness check so a crashed refresh doesn't wedge the cache.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .paths import DATA_DIR

CACHE_PATH = DATA_DIR / "scan-cache.json"
LOCK_PATH = DATA_DIR / "scan-cache.lock"
LASTERR_PATH = DATA_DIR / "scan-cache.lasterr"
MAX_AGE_S = 24 * 3600  # "fresh" window; stale cache is still served (with a warning)
_REQUIRED = ("ecosystem", "packages_checked", "vulnerabilities_found")

# Runs in a detached child: sys.path needs the app root (engine's parent).
_REFRESH_SNIPPET = (
    "import sys; sys.path.insert(0, {root!r}); "
    "from engine.scan_cache import refresh_blocking; refresh_blocking()"
)


def _root() -> str:
    """App install root (dir containing engine/), installed or repo."""
    return str(Path(__file__).resolve().parent.parent)


def load() -> dict | None:
    """Return the cache envelope {stored_at, completed_in_s, result} or None."""
    try:
        data = json.loads(CACHE_PATH.read_text())
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    result = data.get("result")
    if not isinstance(result, dict) or not all(k in result for k in _REQUIRED):
        return None
    return data


def store(result: dict, completed_in_s: float | None = None) -> None:
    """Atomically persist a completed scan result."""
    cache = Path(CACHE_PATH)
    payload = {"stored_at": time.time(), "completed_in_s": completed_in_s,
               "result": result}
    tmp = None
    try:
        # Stage NEXT TO the destination: os.replace is only atomic (and only
        # works) within one filesystem — staging in DATA_DIR breaks whenever
        # CACHE_PATH is redirected elsewhere (tests, relocated data dirs).
        cache.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(cache.parent), prefix=".scan-cache-")
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)
        os.replace(tmp, cache)  # atomic on POSIX
        tmp = None
    except OSError:
        pass  # cache is best-effort; never break the caller
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def age_seconds() -> float | None:
    data = load()
    if data is None:
        return None
    return max(0.0, time.time() - float(data.get("stored_at", 0)))


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)  # signal 0 = existence probe
        return True
    except (ProcessLookupError, PermissionError, TypeError, ValueError):
        return False


def _refresh_in_flight() -> bool:
    try:
        pid = int(LOCK_PATH.read_text().strip())
    except Exception:
        return False
    if _pid_alive(pid):
        return True
    try:
        LOCK_PATH.unlink()  # stale lock from a dead refresh
    except OSError:
        pass
    return False


def _spawn_refresh() -> bool:
    """Detached, stdio-free child that runs the live scan and stores it.
    Returns True if a refresh was started (or is already running)."""
    if os.environ.get("AUTOBAHN_CACHE_NO_SPAWN"):
        return False  # test hook: never spawn real scans from test suites
    if _refresh_in_flight():
        return True
    try:
        LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(LOCK_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        with os.fdopen(fd, "w") as f:
            f.write(str(os.getpid()))
    except FileExistsError:
        return True  # lost a race — the winner is refreshing
    except Exception:
        return False
    try:
        subprocess.Popen(
            [sys.executable, "-c", _REFRESH_SNIPPET.format(root=_root())],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True)
        return True
    except Exception:
        try:
            LOCK_PATH.unlink()
        except OSError:
            pass
        return False


def refresh_blocking() -> None:
    """Entry point for the detached child: live scan → store → release lock."""
    started = time.time()
    try:
        from . import runner
        result = runner.run_cve_scan()
        store(result, completed_in_s=round(time.time() - started, 1))
        try:
            LASTERR_PATH.unlink()
        except OSError:
            pass
    except Exception as e:
        try:
            LASTERR_PATH.write_text(
                json.dumps({"at": started, "error": str(e)}))
        except Exception:
            pass
    finally:
        try:
            LOCK_PATH.unlink()
        except OSError:
            pass


def start_refresh() -> bool:
    """Public alias for _spawn_refresh (respects AUTOBAHN_CACHE_NO_SPAWN)."""
    return _spawn_refresh()


def auto() -> dict:
    """Cache-first policy for MCP tools. NEVER blocks: instant cache hit or
    a 'refresh started' envelope; the model retries in a few minutes."""
    data = load()
    if data is not None:
        age = round(time.time() - float(data.get("stored_at", 0)))
        refresh_started = _spawn_refresh() if age > MAX_AGE_S else False
        out = {
            "source": "cache",
            "cache_age_seconds": age,
            "cache_max_age_seconds": MAX_AGE_S,
            "refresh_started": refresh_started,
            "result": data.get("result"),
        }
        if age > MAX_AGE_S:
            out["warnings"] = [
                f"Cached scan is {age // 3600}h old — a background refresh is "
                "running; call again in a few minutes for fresh data."]
        return out
    # Cache miss: kick the refresh, answer honestly, don't block.
    started = _spawn_refresh()
    return {
        "source": "unavailable",
        "refresh_started": started,
        "status": "degraded",
        "note": ("No cached CVE scan yet. A live OSV.dev scan is running in the "
                 "background now (takes minutes); call this tool again in a few "
                 "minutes. Live scans are not run inline by default because "
                 "short-timeout MCP hosts (e.g. LM Studio, 60 s) would kill "
                 "the request mid-scan."),
        "result": None,
    }


def live() -> dict:
    """Blocking live scan (long-timeout hosts only); stores + returns it."""
    started = time.time()
    from . import runner
    result = runner.run_cve_scan()
    store(result, completed_in_s=round(time.time() - started, 1))
    return {"source": "live", "completed_in_s": round(time.time() - started, 1),
            "result": result}