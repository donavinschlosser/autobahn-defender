"""Scan-job engine with a live NDJSON progress feed (v2.0.1).

Lets an AI agent (via MCP) or the CLI launch a YARA+ClamAV scan of any file,
folder, directory tree, or drive and watch it run:

  start   -> job id + feed path (returns immediately; worker is detached)
  status  -> poll a job (progress %, state, threats so far)
  tail    -> last N feed events (live file/folder trail)
  wait    -> BLOCKING completion (optionally with live relay while waiting)
  cancel  -> cooperative cancel (SIGTERM to the verified worker pid)

Why a job instead of a blocking tool call: file/folder scans take anywhere
from seconds (one file) to hours (a full drive). Blocking MCP hosts kill the
request long before that (LM Studio = hard 60 s; even generous hosts assume
seconds, not hours). The job covers every host: short-timeout hosts poll
status/tail and get notified the moment the job flips to done (the feed's
final line is the done event); long-timeout hosts call wait=true and get one
blocking call with the full result envelope.

Design constraints (mirror engine/scan_cache.py):
  - stdlib only; NEVER write to stdout in-process (the MCP stdio protocol
    owns stdout — the feed FILE is the only output channel)
  - the worker runs in a DETACHED child and survives the MCP host
    disconnecting; job state lives in DATA_DIR/scan-jobs/<id>/
  - feed writes are append+flush per line so tail() reads are live
  - the child spawn goes through the `scan-job` CLI verb, NOT `python -c`:
    in a PyInstaller AppImage sys.executable is the frozen binary and
    `python -c "from engine..."` cannot run (the deb's python3 also can't
    import engine/ without PYTHONPATH — the launcher exports it, a bare
    subprocess does not). The CLI verb dispatch already handles both.
  - cancel = SIGTERM to the pidfile-verified pid; the worker converts it
    into a cooperative stop, so a scan always ends in a written state.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .paths import DATA_DIR, APP_DIR

JOBS_DIR = DATA_DIR / "scan-jobs"
JOB_TTL_S = 24 * 3600        # finished job dirs are pruned after this
FEED_TAIL_DEFAULT = 40
FEED_TAIL_MAX = 400
WAIT_DEFAULT_S = 2 * 3600    # wait=true safety cap so a wedged job can't
                             # hold an MCP worker thread forever
_WAIT_POLL_S = 2.0
MAX_INLINE_RESULT_ROWS = 5000

_SPAWN_ENV = "AUTOBAHN_SCAN_FEED_NO_SPAWN"   # test hook: never spawn children


def _root() -> str:
    """App install root (dir containing engine/), installed or repo."""
    return str(Path(__file__).resolve().parent.parent)


def _safe_job_id(job_id: str) -> str:
    """Strict id check — JOBS_DIR is keyed by id, so no path games."""
    if not job_id or len(job_id) > 64:
        return ""
    return job_id if all(c.isalnum() or c in "-_" for c in job_id) else ""


def _job_dir(job_id: str) -> Path:
    return JOBS_DIR / job_id


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)  # signal 0 = existence probe
        return True
    except (ProcessLookupError, PermissionError, TypeError, ValueError):
        return False


# ── feed events ──────────────────────────────────────────────────────────────

def _feed_event(kind: str, **data) -> dict:
    ev = {"ts": time.time(), "kind": kind}
    ev.update(data)
    return ev


def _append(job_dir: Path, event: dict) -> None:
    """Append one event to feed.ndjson (open/append/flush per line)."""
    try:
        with open(job_dir / "feed.ndjson", "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass  # feed is best-effort; never break the scan


def _read_tail(job_dir: Path, n: int) -> list[dict]:
    """Last n events from feed.ndjson (plain reads, no inotify)."""
    path = job_dir / "feed.ndjson"
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 262144))  # 256 KiB window is plenty
            chunk = f.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    lines = chunk.splitlines()[-n:] if n > 0 else []
    if size > 262144 and lines and not lines[0].startswith("{"):
        lines = lines[1:]  # first line is partial — drop it
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out


def _read_state(job_dir: Path) -> dict:
    try:
        return json.loads((job_dir / "state.json").read_text())
    except Exception:
        return {}


# ── worker body (runs inside the detached `scan-job` child) ─────────────────

def _worker_main(args: dict) -> int:
    """Child body: run the scan, stream the feed, always write final state.

    The child's stdio is DEVNULL (the spawner sees to that) and this function
    is also reachable via `autobahn-defender scan-job <args.json>` where stdout
    is visible — so it must print NOTHING to stdout. The feed file is the only
    output channel. Return value is a process exit code (0 clean, 1 scan
    error, 2 preflight failure).
    """
    job_id = str(args.get("job_id", ""))
    if not _safe_job_id(job_id):
        return 2
    job_dir = _job_dir(job_id)
    if not job_dir.is_dir():
        return 2
    paths = [str(p) for p in (args.get("paths") or [])]
    quick = bool(args.get("quick"))

    cancelled = {"flag": False}

    def _on_sigterm(signum, frame):  # noqa: ARG001 (signal handler signature)
        cancelled["flag"] = True

    try:
        signal.signal(signal.SIGTERM, _on_sigterm)
    except Exception:
        pass  # not main thread of a real process — non-fatal

    def _write_state(**upd) -> None:
        state = _read_state(job_dir)
        state.update(upd)
        try:
            (job_dir / "state.json").write_text(json.dumps(state))
        except OSError:
            pass

    def _prog(pct: int, msg: str) -> None:
        _append(job_dir, _feed_event("progress", pct=int(pct), message=str(msg)))

    result: dict[str, Any] = {
        "files_scanned": 0, "threats_found": 0, "details": [],
        "engines": {"yara": False, "clamav": False},
    }
    error_msg: str | None = None
    started = time.time()
    _write_state(status="running")
    _append(job_dir, _feed_event("start", paths=paths, quick=quick))

    try:
        from . import scanner_core
        # Seed user rules from the bundled set (GUI parity): a headless host
        # may never have launched the GUI, and scanner.py's ensure_dirs() is
        # Qt-side only. Without this, RULES_DIR is empty and the scan
        # silently runs YARA-less.
        _seed_bundled_rules(job_dir)
        result = scanner_core.scan_custom_paths(paths, quick=quick,
                                                progress_cb=_prog)
        if not cancelled["flag"]:
            result["threats_found"] = _ledger_and_quarantine(
                job_dir, result)
    except Exception as e:  # the worker must ALWAYS finish its state machine
        error_msg = str(e)[:500]
        _append(job_dir, _feed_event("error", message=error_msg))

    if cancelled["flag"]:
        _append(job_dir, _feed_event("cancelled"))

    finished = time.time()
    summary = {
        "files_scanned": result.get("files_scanned", 0),
        "threats_found": result.get("threats_found", 0),
        "flagged_review": sum(1 for d in result.get("details", [])
                              if d.get("action") == "flag"),
        "errors": sum(1 for d in result.get("details", [])
                      if d.get("action") == "error"),
        "engines": result.get("engines", {}),
        "paths": paths, "quick": quick, "cancelled": cancelled["flag"],
        "completed_in_s": round(finished - started, 1),
    }
    if error_msg:
        summary["error"] = error_msg

    # Inline result envelope: folder/drive scans can return tens of thousands
    # of rows (every ClamAV "OK" line is not kept, but flags/threats add up);
    # cap what result.json carries and point at the feed for the rest.
    details = [d for d in result.get("details", [])
               if isinstance(d, dict) and d.get("action") not in ("info",)]
    truncated = max(0, len(details) - MAX_INLINE_RESULT_ROWS)
    out: dict[str, Any] = {
        "job_id": job_id, "status": "done", "summary": summary,
        "details": details[:MAX_INLINE_RESULT_ROWS],
    }
    if truncated:
        out["details_truncated"] = truncated
        out["note"] = (f"{truncated} more detail rows are in the job feed "
                       f"(autobahn.scan.tail) — inline result capped at "
                       f"{MAX_INLINE_RESULT_ROWS}.")

    try:
        (job_dir / "result.json").write_text(
            json.dumps(out, ensure_ascii=False, default=str))
    except OSError:
        pass
    _append(job_dir, _feed_event("done", summary=summary))
    _write_state(status="cancelled" if cancelled["flag"] else "done",
                 finished_at=finished,
                 threats_found=summary["threats_found"],
                 result_path=str(job_dir / "result.json"))
    return 0 if not error_msg else 1


def _ledger_and_quarantine(job_dir: Path, result: dict) -> int:
    """Detection-ledger record + quarantine pass, GUI-parity.

    The GUI's ScanWorker records every flagged file's SHA256 into the
    detection ledger after scanning and then quarantines real threats.
    scanner_core's YARA pass already applies the distro-owned review policy
    for YARA hits; ClamAV hits arrive as action=quarantine raw, so the same
    dpkg ownership check is applied here before quarantining. Returns the
    corrected threats_found (flag rows count as threats, per GUI contract).
    """
    import hashlib

    details = [d for d in result.get("details", []) if isinstance(d, dict)]
    # v2.0.4: resolve the ledger through engine.paths — under sudo this must
    # be the INVOKING user's ~/.autobahn, not /root/.autobahn, or the GUI
    # would never see the detections this scan recorded.
    ledger_path = APP_DIR / "detection_ledger.json"
    flagged: dict[str, str] = {}
    for d in details:
        if d.get("action") in ("error", "info", ""):
            continue
        fp = str(d.get("file", ""))
        if not fp or fp == "N/A":
            continue
        try:
            p = Path(fp)
            if p.exists() and p.is_file() and not p.is_symlink():
                h = hashlib.sha256(p.read_bytes()).hexdigest()
                flagged[fp] = h
        except (OSError, PermissionError):
            pass
    try:
        data = {}
        if ledger_path.exists():
            data = json.loads(ledger_path.read_text())
        if isinstance(data, dict):
            data.update(flagged)
            tmp = ledger_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data))
            tmp.replace(ledger_path)
    except (OSError, ValueError):
        pass

    # Quarantine non-distro-owned ClamAV hits (YARA hits were already
    # downgraded to flag by scanner_core for distro-owned files).
    q_items = []
    for d in details:
        if d.get("action") != "quarantine":
            continue
        fp = str(d.get("file", ""))
        if not fp or fp == "N/A":
            d["action"] = "error"
            continue
        distro_owned = fp.startswith(("/usr/", "/bin/", "/sbin/", "/lib/",
                                      "/lib64/", "/opt/", "/boot/"))
        if distro_owned:
            try:
                chk = subprocess.run(["dpkg", "-S", fp], capture_output=True,
                                     timeout=10)
                distro_owned = (chk.returncode == 0)
            except Exception:
                distro_owned = False
        if distro_owned:
            d["action"] = "flag"
            d["threat"] = (f"{d.get('threat', '')} "
                           "(distro-owned file — review, no auto-quarantine)")
            continue
        q_items.append((fp, d))
    if not q_items:
        return sum(1 for d in details
                   if d.get("action") in ("quarantine", "flag"))

    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from quarantine import QuarantineManager
        qm = QuarantineManager()
    except Exception as e:
        _append(job_dir, _feed_event(
            "note", message=f"quarantine unavailable: {e}"))
        return sum(1 for d in details
                   if d.get("action") in ("quarantine", "flag"))

    quarantined = 0
    for fp, d in q_items:
        try:
            ok = qm.quarantine_file(fp, threat_name=str(d.get("threat", "")))
        except Exception:
            ok = False
        if ok:
            quarantined += 1
            d["action"] = "quarantined"
            _append(job_dir, _feed_event("quarantined", file=fp))
        else:
            d["action"] = "flag"
            d["threat"] = (f"{d.get('threat', '')} "
                           "(quarantine failed — left in place, review)")
    if quarantined:
        _append(job_dir, _feed_event("quarantine_summary",
                                     count=quarantined))
    return sum(1 for d in details
               if d.get("action") in ("quarantined", "quarantine", "flag"))


# ── bundled rules seeding (GUI parity for headless hosts) ────────────────────

def _bundled_rules_dir() -> Path:
    """Directory containing the app's shipped *.yar rules, frozen or not."""
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            cand = Path(meipass) / "rules"
            if cand.is_dir():
                return cand
    return Path(_root()) / "rules"


def _seed_bundled_rules(job_dir: Path) -> None:
    """Copy bundled *.yar rules into the user RULES_DIR when missing.

    Mirrors scanner.ensure_dirs() so headless MCP scans get real YARA rules
    even if the GUI never ran on this host. Never overwrites upstream_*
    (the auto-updater's newer copies); bundled files are copied only when
    the name is absent.
    """
    try:
        from .paths import RULES_DIR
        bundled = _bundled_rules_dir()
        if not bundled.is_dir():
            return
        RULES_DIR.mkdir(parents=True, exist_ok=True)
        seeded = 0
        for src in sorted(bundled.glob("*.yar")):
            dst = RULES_DIR / src.name
            if dst.exists() or dst.name.startswith("upstream_"):
                continue
            try:
                dst.write_bytes(src.read_bytes())
                seeded += 1
            except OSError:
                pass
        if seeded:
            _append(job_dir, _feed_event("rules_seeded", count=seeded))
    except Exception:
        pass  # seeding is best-effort; scanner_core reports "No YARA rules"


# ── child spawn path ─────────────────────────────────────────────────────────

def _child_cmd(args_path: str) -> list[str]:
    """Command line for the detached worker child.

    Always the app's own CLI verb: installed deb → /usr/bin/autobahn-defender
    (launcher exports PYTHONPATH), AppImage → the frozen binary, repo →
    sys.executable main.py. Never `python -c`: frozen binaries have no usable
    stdlib interpreter and bare python3 lacks the import path.
    """
    try:
        frozen = bool(getattr(sys, "frozen", False))
    except Exception:
        frozen = False
    if frozen:
        # AppImage/PyInstaller: the only interpreter that can import engine/
        # is the frozen binary itself.
        base = [sys.executable]
    else:
        # IMPORTANT: never target /usr/bin/autobahn-defender here — a live
        # MCP host may run a NEWER engine than the installed deb (or none);
        # the old launcher would fall through to the GUI and hang forever.
        # sys.executable + our own main.py is always the same version as
        # the code that spawned it.
        main_py = Path(_root()) / "main.py"
        base = [sys.executable, str(main_py)]
    return base + ["scan-job", "--args-file", args_path]


# ── job lifecycle (parent side) ──────────────────────────────────────────────

def start_job(paths: list, quick: bool = False) -> dict:
    """Create the job, spawn the detached worker, return the manifest."""
    paths = [str(p) for p in (paths or []) if str(p)]
    if not paths:
        return {"ok": False, "error": "no paths given"}
    for p in paths:
        try:
            st = os.stat(p)
        except OSError as e:
            return {"ok": False, "error": f"cannot access path {p}: {e}"}
        import stat as _stat
        if _stat.S_ISDIR(st.st_mode) or _stat.S_ISREG(st.st_mode):
            continue
        return {"ok": False,
                "error": f"path is neither a regular file nor a directory: {p}"}

    import uuid
    job_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    job_dir = JOBS_DIR / job_id
    try:
        job_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return {"ok": False, "error": f"cannot create job dir: {e}"}

    args = {"job_id": job_id, "paths": paths, "quick": bool(quick)}
    state = {
        "job_id": job_id, "status": "starting", "paths": paths,
        "quick": bool(quick), "pid": None, "started_at": time.time(),
        "finished_at": None, "threats_found": None,
        "feed_path": str(job_dir / "feed.ndjson"),
    }
    args_path = job_dir / "args.json"
    try:
        args_path.write_text(json.dumps(args))
        (job_dir / "state.json").write_text(json.dumps(state))
    except OSError as e:
        return {"ok": False, "error": f"cannot write job files: {e}"}

    if os.environ.get(_SPAWN_ENV):
        # Test hook: report the exact command instead of spawning.
        return {"ok": True, "job_id": job_id, "status": "starting",
                "spawn_skipped": True,
                "cmd": " ".join(_child_cmd(str(args_path))),
                "feed_path": str(job_dir / "feed.ndjson")}
    try:
        proc = subprocess.Popen(
            _child_cmd(str(args_path)),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True)
    except Exception as e:
        state["status"] = "error"
        state["error"] = f"cannot spawn worker: {e}"
        try:
            (job_dir / "state.json").write_text(json.dumps(state))
        except OSError:
            pass
        return {"ok": False, "error": f"cannot spawn scan worker: {e}"}

    state["pid"] = proc.pid
    state["status"] = "running"
    try:
        (job_dir / "state.json").write_text(json.dumps(state))
    except OSError:
        pass
    return {
        "ok": True, "job_id": job_id, "pid": proc.pid, "status": "running",
        "feed_path": str(job_dir / "feed.ndjson"),
        "note": ("Scan running detached — it survives host disconnect. "
                 "Poll autobahn.scan.status / autobahn.scan.tail for live "
                 "progress; the feed's last line is the 'done' event, or "
                 "block on autobahn.scan.wait {job_id}."),
    }


def status(job_id: str) -> dict:
    job_id = _safe_job_id(job_id)
    if not job_id:
        return {"ok": False, "error": "invalid job id"}
    job_dir = _job_dir(job_id)
    if not job_dir.is_dir():
        return {"ok": False, "error": "unknown job id (or pruned after 24h)"}
    state = _read_state(job_dir)
    if not state:
        return {"ok": False, "error": "job state unreadable"}
    out = {k: state.get(k) for k in
           ("job_id", "status", "paths", "quick", "pid", "started_at",
            "finished_at", "threats_found", "error")}
    out["ok"] = True
    if state.get("status") in ("running", "starting"):
        pid = state.get("pid")
        if not (isinstance(pid, int) and _pid_alive(pid)):
            out["status"] = "lost"
            out["note"] = ("worker process is gone but no completion state "
                           "was written (killed / OOM) — the feed has the "
                           "last progress; rerun the scan if needed")
    result_path = state.get("result_path")
    if state.get("status") == "done" and result_path and \
            Path(result_path).exists():
        out["result_path"] = result_path
    return out


def tail(job_id: str, n: int = FEED_TAIL_DEFAULT) -> dict:
    """Last n feed events (live file/folder trail + progress)."""
    job_id = _safe_job_id(job_id)
    if not job_id:
        return {"ok": False, "error": "invalid job id"}
    job_dir = _job_dir(job_id)
    if not job_dir.is_dir():
        return {"ok": False, "error": "unknown job id (or pruned after 24h)"}
    try:
        n = max(1, min(int(n), FEED_TAIL_MAX))
    except (TypeError, ValueError):
        n = FEED_TAIL_DEFAULT
    events = _read_tail(job_dir, n)
    state = _read_state(job_dir)
    return {
        "ok": True, "job_id": job_id,
        "job_status": state.get("status", "unknown"),
        "events": events, "returned": len(events),
    }


def wait(job_id: str, timeout_s: float = WAIT_DEFAULT_S) -> dict:
    """Block until the job reaches a terminal state (done/cancelled/lost).

    Returns the completion envelope — result.json if present, else an honest
    timeout report with the feed tail so the agent keeps something useful.
    """
    job_id = _safe_job_id(job_id)
    if not job_id:
        return {"ok": False, "error": "invalid job id"}
    job_dir = _job_dir(job_id)
    if not job_dir.is_dir():
        return {"ok": False, "error": "unknown job id (or pruned after 24h)"}
    try:
        timeout_s = max(1.0, min(float(timeout_s), WAIT_DEFAULT_S))
    except (TypeError, ValueError):
        timeout_s = WAIT_DEFAULT_S

    deadline = time.time() + timeout_s
    last_ages = None
    while time.time() < deadline:
        state = _read_state(job_dir)
        st = state.get("status")
        if st in ("done", "cancelled"):
            out = {"ok": True, "job_id": job_id, "status": st}
            result_path = state.get("result_path")
            if result_path and Path(result_path).exists():
                try:
                    out["result"] = json.loads(Path(result_path).read_text())
                except (OSError, ValueError):
                    out["result_path"] = result_path
            else:
                out["result"] = None
                out["note"] = "job finished but result.json is unreadable"
            return out
        if st == "error":
            return {"ok": True, "job_id": job_id, "status": "error",
                    "error": state.get("error"),
                    "feed": _read_tail(job_dir, 20)}
        if st in ("running", "starting"):
            pid = state.get("pid")
            if not (isinstance(pid, int) and _pid_alive(pid)):
                return {"ok": True, "job_id": job_id, "status": "lost",
                        "error": state.get("error"),
                        "feed": _read_tail(job_dir, 20)}
        ages = _read_tail(job_dir, 1)
        if ages and isinstance(ages[0].get("ts"), (int, float)):
            if last_ages is not None and ages[0]["ts"] == last_ages:
                # feed silent for a long while AND pid gone → stop waiting
                pid = state.get("pid")
                if not (isinstance(pid, int) and _pid_alive(pid)):
                    return {"ok": True, "job_id": job_id, "status": "lost",
                            "feed": _read_tail(job_dir, 20)}
            last_ages = ages[0]["ts"]
        time.sleep(_WAIT_POLL_S)
    return {
        "ok": True, "job_id": job_id, "status": "timeout",
        "waited_s": round(timeout_s, 1),
        "note": ("job still running after the wait window — poll "
                 "autobahn.scan.status / autobahn.scan.tail, or call "
                 "wait again"),
        "feed": _read_tail(job_dir, 20),
    }


def cancel(job_id: str) -> dict:
    job_id = _safe_job_id(job_id)
    if not job_id:
        return {"ok": False, "error": "invalid job id"}
    job_dir = _job_dir(job_id)
    if not job_dir.is_dir():
        return {"ok": False, "error": "unknown job id (or pruned after 24h)"}
    state = _read_state(job_dir)
    pid = state.get("pid")
    if not isinstance(pid, int):
        return {"ok": False, "error": "job has no worker pid"}
    if not _pid_alive(pid):
        return {"ok": False, "error": "worker is not running"}
    # Sanity: the pid must still be running OUR code before we signal it.
    # A recycled pid pointing at another process must never receive SIGTERM.
    comm_ok = False
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace")
        comm_ok = ("autobahn" in cmd.lower()) or ("main.py" in cmd)
    except OSError:
        pass
    if not comm_ok:
        return {"ok": False,
                "error": "pid no longer belongs to autobahn-defender"}
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as e:
        return {"ok": False, "error": f"signal failed: {e}"}
    _append(job_dir, _feed_event("cancel_requested"))
    return {"ok": True, "job_id": job_id, "status": "cancelling",
            "note": "SIGTERM sent — the worker finishes its state machine "
                    "and marks the job cancelled (poll status)"}


def list_jobs(prune: bool = True) -> dict:
    """List recent jobs (finished ones pruned after JOB_TTL_S)."""
    if not JOBS_DIR.is_dir():
        return {"ok": True, "jobs": []}
    if os.environ.get(_SPAWN_ENV):
        return {"ok": True, "jobs": []}
    now = time.time()
    jobs = []
    for d in sorted(JOBS_DIR.iterdir()):
        if not d.is_dir():
            continue
        state = _read_state(d)
        if not state:
            continue
        finished_or_started = float(state.get("finished_at")
                                    or state.get("started_at") or now)
        if now - finished_or_started > JOB_TTL_S:
            import shutil
            shutil.rmtree(d, ignore_errors=True)
            continue
        jobs.append({k: state.get(k) for k in
                     ("job_id", "status", "paths", "started_at",
                      "finished_at", "threats_found")})
    return {"ok": True, "jobs": sorted(
        jobs, key=lambda j: str(j.get("started_at") or ""), reverse=True)}


def run_cli_child(args_path: str) -> int:
    """CLI verb entry (`autobahn-defender scan-job --args-file P`).

    Keeps the child's argv self-describing in `ps` output (vs a bare -c
    blob) and works identically in the deb, the AppImage, and the repo.
    """
    p = Path(args_path)
    try:
        args = json.loads(p.read_text())
    except Exception:
        return 2
    return _worker_main(args)


# ── MCP tool wrappers (engine-internal, called from cli/mcp_server.py) ──────

def _result_text(envelope: dict) -> dict:
    """Wrap a scan envelope into an MCP content payload (text/json)."""
    return {"content": [{"type": "text",
                         "text": json.dumps(envelope, ensure_ascii=False,
                                            default=str)}]}


def mcp_scan(args: dict) -> dict:
    """autobahn.scan dispatcher: action=start|status|tail|wait|cancel|list."""
    action = str(args.get("action", "")).strip().lower()
    job_id = str(args.get("job_id", "") or "")
    if action == "start" or (not action and args.get("paths")):
        if not action:
            action = "start"
        res = start_job(args.get("paths") or [], quick=bool(args.get("quick")))
        return res
    if action == "status":
        return status(job_id)
    if action == "tail":
        return tail(job_id, args.get("lines", FEED_TAIL_DEFAULT))
    if action == "wait":
        return wait(job_id, args.get("timeout_s", WAIT_DEFAULT_S))
    if action == "cancel":
        return cancel(job_id)
    if action == "list":
        return list_jobs()
    return {"ok": False,
            "error": ("action must be one of start|status|tail|wait|cancel|"
                      "list; start needs paths")}