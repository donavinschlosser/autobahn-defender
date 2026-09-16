"""Regression tests: the v2.0.2 parallel ClamAV scanner defects.

Two shipped defects are pinned here (both broke parallel ClamAV scanning
end-to-end; the v2.0.2 .deb and AppImage shipped with them):

1. INDENTATION (reported by a user: UnboundLocalError on 'file_list_path',
   "Exception in thread Thread-N"): the try/except/finally scan block sat at
   the SAME indent as the `while` in run_single_clamscan(), making it a
   sibling of the loop instead of its child. Worker threads that found the
   shared queue already empty fell straight through to the orphaned finally,
   hit `if file_list_path:` with the name unbound, and died. Survivors also
   only ever executed the scan block ONCE, after the loop, on the last chunk.

2. UNDEFINED NAME (found while fixing #1, live-reproduced): the worker's
   Popen call passes env=clam_env, but `clam_env` was never bound in
   _run_clamscan_parallel's scope — every batch that did reach Popen died
   with `NameError: name 'clam_env' is not defined` and the scan reported
   0 files scanned.

The AST tests assert the structural invariant; the runtime tests drive the
REAL _run_clamscan_parallel() through ScanWorker with a stub clamscan and
assert full coverage, no worker-thread deaths, and a single startup emit.
The runtime tests need PyQt6 (scanner.py imports it); they skip cleanly on
interpreters without it, while the AST tests run everywhere.

These tests fail against the shipped v2.0.2 code and pass after the fix.
"""
from __future__ import annotations

import ast
import os
import threading
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCANNER = REPO / "scanner.py"


def _fn(name: str):
    tree = ast.parse(SCANNER.read_text(encoding="utf-8"))
    return next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == name)


class TestStructuralIndentation:
    """Defect #1 was purely structural, so assert on the AST."""

    def test_scan_try_block_is_inside_the_while_loop(self):
        fn = _fn("run_single_clamscan")

        while_loops = [c for c in fn.body if isinstance(c, ast.While)]
        assert len(while_loops) == 1, "expected exactly one while loop"
        loop = while_loops[0]

        loop_tries = [c for c in loop.body if isinstance(c, ast.Try)]
        assert loop_tries, (
            "run_single_clamscan's while loop contains no try block — the scan "
            "block has drifted OUTSIDE the loop again (this is the v2.0.2 bug)"
        )

        # exactly one of the loop's try blocks must carry the cleanup finally
        with_finally = [t for t in loop_tries if t.finalbody]
        assert len(with_finally) == 1, "expected one try/except/finally inside the loop"
        final = with_finally[0]

        cleaned = {
            ast.unparse(s)
            for s in final.finalbody
            if isinstance(s, ast.If)
        }
        assert any("file_list_path" in c for c in cleaned), \
            "cleanup of file_list_path should live in the loop's finally block"

    def test_no_orphaned_try_after_the_while_loop(self):
        fn = _fn("run_single_clamscan")

        # nothing at the function's top level after the loop should be a bare
        # Try that references the loop's locals (the orphaned scan block)
        names = []
        for stmt in fn.body:
            if isinstance(stmt, ast.Try):
                names.append(ast.unparse(stmt))
        assert not names, (
            "found a top-level Try in run_single_clamscan outside the while loop: "
            f"{names[0][:120]!r} — this is the orphaned scan block bug"
        )

    def test_startup_emit_is_outside_the_loop(self):
        """The 'Scanning N files with M processes' message must fire once."""
        fn = _fn("run_single_clamscan")

        def mentions_scanning_emit(node) -> bool:
            return any(
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "emit"
                and "processes" in ast.unparse(n)
                for n in ast.walk(node)
            )

        for stmt in fn.body:
            if isinstance(stmt, ast.While):
                assert not mentions_scanning_emit(stmt), (
                    "the 'Scanning N files with M processes' emit has been pulled "
                    "INSIDE the batch loop and now fires once per batch"
                )

    def test_worker_env_name_is_bound_in_the_enclosing_scope(self):
        """Defect #2: the worker references clam_env; it must resolve.

        Either as a closure variable bound by _run_clamscan_parallel, or as
        something else Python can actually resolve — a NameError here means
        every batch dies the moment it reaches Popen().
        """
        outer = _fn("_run_clamscan_parallel")

        inner = next(n for n in ast.walk(outer)
                     if isinstance(n, ast.FunctionDef)
                     and n.name == "run_single_clamscan")

        uses_env = any(
            isinstance(n, ast.Name) and n.id == "clam_env"
            for n in ast.walk(inner)
        )
        if not uses_env:
            pytest.skip("worker no longer passes clam_env — check what env it uses")

        bound_in_outer = any(
            isinstance(n, ast.Name) and n.id == "clam_env"
            and isinstance(n.ctx, ast.Store)
            for n in ast.walk(outer)
        )
        assert bound_in_outer, (
            "run_single_clamscan references clam_env, but _run_clamscan_parallel "
            "never binds it — every ClamAV batch will die with "
            "NameError: name 'clam_env' is not defined (v2.0.2 defect #2)"
        )


# ── Runtime tests: drive the real parallel runner with a stub clamscan ──────

_STUB_CLAMSCAN = """\
#!/bin/bash
# Stub clamscan: emulates `clamscan -f <list> ... --` output for N files.
list=""
while [ $# -gt 0 ]; do
    if [ "$1" = "-f" ]; then list="$2"; shift 2; continue; fi
    shift
done
[ -z "$list" ] && exit 0
while IFS= read -r line; do
    [ -n "$line" ] && echo "$line: OK"
done < "$list"
exit 0
"""


class _Settings:
    """Minimal settings-manager stand-in for ScanWorker."""

    def __init__(self, threads: int = 4):
        self._threads = threads

    def is_scan_archives(self):
        return True

    def is_scan_hidden(self):
        return True

    def get_scan_threads(self):
        return self._threads

    def is_parallel_clamav(self):
        return True

    def get_scan_engine(self):
        return "clamav"


def _run_parallel_scan(tmp_path, monkeypatch, n_files: int, workers: int):
    """Run ScanWorker('custom') over n_files and return (results, context).

    Context: dict with emitted messages, worker-thread deaths, finished flag.
    """
    scanner = pytest.importorskip("scanner")  # needs PyQt6

    from PyQt6.QtCore import Qt

    # stub clamscan (no real ClamAV needed)
    stub = tmp_path / "stub_clamscan"
    stub.write_text(_STUB_CLAMSCAN)
    stub.chmod(0o755)
    monkeypatch.setattr(scanner, "find_clamscan", lambda: str(stub))

    tree = tmp_path / "scan_tree"
    tree.mkdir()
    for i in range(n_files):
        (tree / f"f_{i:05d}.bin").write_text("hello world\n")

    # capture worker-thread deaths during the run
    deaths = []
    prev_hook = threading.excepthook

    def _hook(args):
        deaths.append((args.thread.name, args.exc_type.__name__,
                       str(args.exc_value)[:160]))

    threading.excepthook = _hook

    events = []
    ctx = {"finished": False}

    try:
        w = scanner.ScanWorker("custom", custom_paths=[str(tree)],
                               settings_mgr=_Settings(threads=workers))
        w._cancelled = False
        w.progress.connect(lambda i: None, Qt.ConnectionType.DirectConnection)
        w.current_file.connect(lambda t: events.append(("file", t)),
                               Qt.ConnectionType.DirectConnection)
        w.finished.connect(lambda d: events.append(("finished", d)),
                           Qt.ConnectionType.DirectConnection)

        t = threading.Thread(target=w.run, name="ad-runtime-test", daemon=True)
        t.start()
        t.join(timeout=120)
        assert not t.is_alive(), "scan did not finish within 120s"
    finally:
        threading.excepthook = prev_hook

    fin = [e[1] for e in events if e[0] == "finished"]
    msgs = [e[1] for e in events if e[0] == "file"]
    ctx["finished"] = bool(fin)
    ctx["scanning_emits"] = sum(
        1 for m in msgs if "Scanning" in m and "processes" in m)
    ctx["messages"] = msgs
    return (fin[0] if fin else None), ctx, deaths


class TestParallelRunnerRuntime:
    """End-to-end through the real _run_clamscan_parallel (stubbed clamscan).

    The shipped v2.0.2 code fails these: files_scanned == 0 (NameError on
    'clam_env') plus worker threads dying with UnboundLocalError.
    """

    def test_every_file_gets_scanned_no_worker_deaths(self, tmp_path, monkeypatch):
        n_files = 600          # > BATCH_SIZE floor 500 => 2 batches, 4 workers
        results, ctx, deaths = _run_parallel_scan(tmp_path, monkeypatch,
                                                  n_files=n_files, workers=4)

        assert ctx["finished"], "scan produced no finished signal"
        assert deaths == [], (
            "worker threads died during the parallel scan: "
            f"{deaths[:4]} — this is the v2.0.2 UnboundLocalError/NameError bug"
        )

        errs = [d for d in results["details"] if d.get("action") == "error"]
        assert errs == [], f"scan produced error rows: {errs[:4]}"
        assert results["files_scanned"] == n_files, (
            f"scanned {results['files_scanned']} of {n_files} files — the "
            "parallel ClamAV runner silently skipped files (v2.0.2 bug)"
        )
        assert results["threats_found"] == 0

    def test_startup_message_emitted_exactly_once(self, tmp_path, monkeypatch):
        results, ctx, deaths = _run_parallel_scan(tmp_path, monkeypatch,
                                                  n_files=600, workers=4)
        assert ctx["finished"]
        assert ctx["scanning_emits"] == 1, (
            "the 'Scanning N files with M processes' status fired "
            f"{ctx['scanning_emits']} times — it must emit exactly once "
            "(regression: emit dragged inside the batch loop)"
        )

    def test_more_workers_than_batches_still_scans_everything(
            self, tmp_path, monkeypatch):
        """Queue-losers (the user's Thread-8 case) must not crash."""
        n_files = 1200         # 3 batches at BATCH_SIZE 500 floor... 1200//(8*4)=37 -> floor 500 => 3 batches
        results, ctx, deaths = _run_parallel_scan(tmp_path, monkeypatch,
                                                  n_files=n_files, workers=8)
        assert ctx["finished"]
        # with 8 workers and only 3 batches, 5 workers find the queue empty —
        # exactly the race that killed Thread-8 with UnboundLocalError
        assert deaths == [], f"queue-loser workers died: {deaths[:4]}"
        assert results["files_scanned"] == n_files
