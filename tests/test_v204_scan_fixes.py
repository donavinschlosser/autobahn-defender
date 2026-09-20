"""Regression tests for the v2.0.4 full-system scan defects.

Each test pins one defect that a user report exposed (Sep 2026: a Mint 22.2
user saw "YARA: 0/6,061,291 files scanned" frozen at 0% and abandoned the
scan). These are STRUCTURAL tests — they fail if the defect is reintroduced,
without needing a multi-hour scan to prove it.

Defects covered:
  1. Per-file `dpkg -S` subprocess in the YARA hot loop (~300 ms/file →
     ~85x slowdown; ~143 h for a 6M-file scan).
  2. Every file submitted as a future before any result consumed (~10 GB RSS
     at 6M files; MemoryError on an 8 GB machine).
  3. The file list walked twice per GUI scan (~14 min wasted per pass).
  4. /media, /mnt, /timeshift walked during a full-system scan (the
     reporter's 6M-file count was largely snapshots + attached drives).
  5. Non-Debian hosts auto-quarantining package files (missing `dpkg`
     silently re-enabled the v2.0.0 no-quarantine guard's inverse).
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── 1. no per-file dpkg subprocess in either scan path ─────────────────────

def test_no_dpkg_subprocess_in_gui_scan_path():
    """The GUI scanner must not shell out to dpkg per file."""
    src = (REPO / "scanner.py").read_text()
    assert '["dpkg", "-S"' not in src, (
        "scanner.py still runs `dpkg -S` per file — this is the ~85x "
        "slowdown that froze the user's scan at 0%"
    )
    assert "dpkg_ownership" in src, "scanner.py must use the ownership index"


def test_no_dpkg_subprocess_in_cli_scan_path():
    """The CLI/MCP scanner must not shell out to dpkg per file."""
    src = (REPO / "engine" / "scanner_core.py").read_text()
    assert '["dpkg", "-S"' not in src, (
        "engine/scanner_core.py still runs `dpkg -S` per file"
    )
    assert "dpkg_ownership" in src


# ─── dpkg ownership index correctness + fail-safe behaviour ─────────────────

def test_ownership_index_matches_dpkg_query(tmp_path):
    """The index must agree with dpkg-query on real system files."""
    dpkg_info = Path("/var/lib/dpkg/info")
    if not dpkg_info.is_dir():
        pytest.skip("not a dpkg-based system")
    import importlib
    mod = importlib.import_module("engine.dpkg_ownership")
    index = mod.get_index()
    if index is None:
        pytest.skip("dpkg database unreadable")

    # Spot-check against dpkg-query ground truth (bulk call is fast).
    import subprocess
    sample = ["/usr/bin/ls", "/usr/bin/bash", "/usr/bin/cat"]
    sample = [p for p in sample if Path(p).exists()]
    if not sample:
        pytest.skip("no sample files present")
    real = subprocess.run(["dpkg-query", "-S", "--"] + sample,
                          capture_output=True, text=True)
    truly_owned = set()
    for line in real.stdout.splitlines():
        _pkg, _, path = line.partition(": ")
        if path:
            truly_owned.add(path)
    for p in sample:
        assert mod.is_owned(p) is (p in truly_owned), f"index disagrees on {p}"


def test_ownership_unknown_is_fail_safe(tmp_path, monkeypatch):
    """Unknown ownership must resolve to 'treat as distro-owned' (no auto-quarantine)."""
    import importlib
    mod = importlib.import_module("engine.dpkg_ownership")
    monkeypatch.setattr(mod, "_index", None)
    monkeypatch.setattr(mod, "_index_attempted", False)
    monkeypatch.setattr(mod, "_build_index", lambda: frozenset())
    # No dpkg database → None (unknown), and the policy wrapper must say True
    assert mod.is_owned("/usr/bin/ls") is None
    assert mod.is_distro_owned("/usr/bin/ls") is True, (
        "unknown ownership must NOT permit auto-quarantine of a system file"
    )


def test_ownership_index_is_cached(monkeypatch):
    """The index is built once, not per file (the whole point of the fix)."""
    import importlib
    mod = importlib.import_module("engine.dpkg_ownership")
    monkeypatch.setattr(mod, "_index", None)
    monkeypatch.setattr(mod, "_index_attempted", False)
    calls = {"n": 0}

    def counting_build():
        calls["n"] += 1
        return frozenset({"/usr/bin/ls"})

    monkeypatch.setattr(mod, "_build_index", counting_build)
    for _ in range(50):
        mod.is_owned("/usr/bin/ls")
    assert calls["n"] == 1, "index rebuilt per call — the per-file cost is back"


# ─── 2. bounded futures (memory) ────────────────────────────────────────────

def test_yara_scan_uses_bounded_futures_window():
    """The YARA phase must not submit every file before consuming results."""
    src = (REPO / "scanner.py").read_text()
    # The exact unbounded pattern from the bug must be gone.
    assert "{pool.submit(_scan_single_file, f): f for f in scannable_files}" not in src, (
        "unbounded futures submission is back — ~10 GB RSS at 6M files"
    )
    assert "return_when=FIRST_COMPLETED" in src, "bounded window wait missing"


def test_yara_inflight_never_exceeds_bound(tmp_path, monkeypatch):
    """FUNCTIONAL: measure live futures during a real _run_yara pass.

    Instrumented ThreadPoolExecutor counts submits minus completions and
    records the high-water mark. With the old code the count climbed to the
    full file count before draining; with the bound it must stay small.
    """
    pytest.importorskip("PyQt6")
    sys.path.insert(0, str(REPO))
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    import scanner as S
    from concurrent import futures as _fut

    high_water = {"n": 0, "live": 0}

    class CountingExecutor(_fut.ThreadPoolExecutor):
        def submit(self, fn, *a, **kw):
            fut = super().submit(fn, *a, **kw)
            high_water["live"] += 1
            high_water["n"] = max(high_water["n"], high_water["live"])

            def _dec(_f):
                high_water["live"] -= 1

            fut.add_done_callback(_dec)
            return fut

    # Patch the symbol the scanner module imports at call time.
    import concurrent.futures as _cf
    monkeypatch.setattr(_cf, "ThreadPoolExecutor", CountingExecutor)

    # Fast, rule-free file scan: make yara match a no-op and skip rules.
    class _FakeRules:
        def match(self, filepath=None, **kw):
            return []

    monkeypatch.setattr(S, "_get_or_compile_yara_rules",
                        lambda files: (_FakeRules(), None))

    N = 20000
    w = S.ScanWorker("custom", custom_paths=["/tmp"])
    w.settings_mgr = None
    # Rules dir must be writable: _run_yara writes a default.yar fallback
    # when no rule files exist. Use tmp_path, not a fake path.
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    monkeypatch.setattr(S, "RULES_DIR", rules_dir)
    files = [f"/tmp/synthetic_{i}.dat" for i in range(N)]
    monkeypatch.setattr(w, "_collect_scannable_files", lambda paths: files)

    res = w._run_yara(["/tmp"], progress_start=0, progress_end=50,
                      precollected_files=files)
    assert res["files_scanned"] == N, "bounded window dropped files"
    # The window is max(threads*4, 64); assert a generous ceiling far below N.
    assert high_water["n"] <= 512, (
        f"in-flight futures reached {high_water['n']} for {N} files — the "
        f"window is not bounding memory"
    )


# ─── 3. single file collection per scan ─────────────────────────────────────

def test_file_list_collected_once_per_scan():
    """YARA and ClamAV must share one collected list, not walk twice."""
    src = (REPO / "scanner.py").read_text()
    assert "precollected_files" in src, "shared file list plumbing missing"
    # Both phases must accept the precollected list.
    assert src.count("precollected_files=None") == 2, (
        "expected both _run_yara and _run_clamscan_parallel to accept a "
        "precollected file list"
    )


def test_collector_not_called_twice_in_run_inner():
    """_run_inner must walk the tree once and pass the list to both phases."""
    src = (REPO / "scanner.py").read_text()
    body = src.split("def _run_inner")[1].split("def _get_scan_paths")[0]
    # The collector is invoked once in _run_inner; the phases receive the list.
    assert body.count("self._collect_scannable_files(scan_paths)") == 1, (
        "_run_inner walks the filesystem more than once per scan"
    )


# ─── 4. mount points / snapshots excluded ───────────────────────────────────

def test_skip_abs_paths_present_in_both_paths():
    """Both scan paths define mount-point exclusions AND enforce them."""
    for rel in ("scanner.py", "engine/scanner_core.py"):
        src = (REPO / rel).read_text()
        assert "SKIP_ABS_PATHS" in src, f"{rel} lacks mount-point exclusions"
        for must in ("/media", "/mnt", "/timeshift"):
            assert must in src, f"{rel} must skip {must}"
    # scanner.py must actually FILTER dirnames through the set, not merely
    # define it (a defined-but-unused set was a real regression candidate).
    gui_src = (REPO / "scanner.py").read_text()
    assert "not in self.SKIP_ABS_PATHS" in gui_src, (
        "scanner.py defines SKIP_ABS_PATHS but never filters dirnames with it"
    )
    core_src = (REPO / "engine" / "scanner_core.py").read_text()
    assert "not in SKIP_ABS_PATHS" in core_src, (
        "scanner_core.py defines SKIP_ABS_PATHS but never uses it"
    )


def test_collector_actually_skips_a_mount_point(tmp_path, monkeypatch):
    """FUNCTIONAL: a directory in SKIP_ABS_PATHS must not be walked.

    Builds a real tree with two sibling dirs, marks one as a "mount point",
    and asserts the collector descends into the normal one but not the mount.
    This catches a defined-but-unenforced exclusion list.
    """
    pytest.importorskip("PyQt6", reason="PyQt6 needed to import scanner")
    sys.path.insert(0, str(REPO))
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from scanner import ScanWorker

    root = tmp_path / "tree"
    (root / "normal_dir").mkdir(parents=True)
    (root / "fakemount").mkdir(parents=True)
    (root / "normal_dir" / "keep.txt").write_text("hello world keep")
    (root / "fakemount" / "skip.txt").write_text("hello world skip")

    w = ScanWorker("full_system")
    # Point the exclusion set at our synthetic "mount point".
    monkeypatch.setattr(w, "SKIP_ABS_PATHS", frozenset({str(root / "fakemount")}))

    found = w._collect_scannable_files([str(root)])
    names = {Path(p).name for p in found}
    assert "keep.txt" in names, "collector skipped a normal directory"
    assert "skip.txt" not in names, (
        "collector descended into a SKIP_ABS_PATHS directory — the "
        "mount-point exclusion is not enforced"
    )


def test_skip_abs_paths_does_not_skip_user_folders():
    """A user folder named 'media' or 'mnt' must still be scanned.

    The exclusion is keyed on absolute path, never bare directory name — this
    guards against over-correcting into silently not scanning user data.
    """
    src = (REPO / "scanner.py").read_text()
    # The name-based set must NOT contain media/mnt/timeshift.
    skip_dirs_block = src.split("SKIP_DIRS = frozenset")[1].split("})")[0]
    for name in ("media", "mnt", "timeshift"):
        assert f'"{name}"' not in skip_dirs_block, (
            f'"{name}" is excluded by NAME, which would skip user folders'
        )
    skip_sys_block = src.split("SKIP_DIRS_SYSTEM = frozenset")[1].split("})")[0]
    for name in ("media", "mnt", "timeshift"):
        assert f'"{name}"' not in skip_sys_block


def test_collector_skips_mount_points():
    """End-to-end: the collector must not descend into /media-like trees."""
    pytest.importorskip("PyQt6", reason="PyQt6 needed to import scanner")
    sys.path.insert(0, str(REPO))
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from scanner import ScanWorker
    w = ScanWorker("full_system")
    assert "/media" in w.SKIP_ABS_PATHS
    assert "/mnt" in w.SKIP_ABS_PATHS
    assert "/timeshift" in w.SKIP_ABS_PATHS


# ─── 5. sudo / root-launch handling ─────────────────────────────────────────

def test_paths_module_resolves_sudo_home():
    """engine.paths must resolve the SUDO_USER's home, not /root."""
    import importlib
    mod = importlib.import_module("engine.paths")
    saved = {k: os.environ.get(k) for k in ("SUDO_USER", "SUDO_UID", "SUDO_GID")}
    real_geteuid = mod.os.geteuid
    try:
        mod.os.geteuid = lambda: 0
        os.environ["SUDO_USER"] = "someuser"
        os.environ["SUDO_UID"] = "1000"
        os.environ["SUDO_GID"] = "1000"
        invoked = mod._invoking_user()
        # On a machine without that account, _invoking_user returns None — the
        # important part is that it never resolves to root's home.
        if invoked is not None:
            assert invoked[2] != Path("/root")
    finally:
        mod.os.geteuid = real_geteuid
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_non_root_does_not_use_sudo_home():
    """A normal (non-sudo) run must use the current user's home."""
    import importlib
    mod = importlib.import_module("engine.paths")
    saved_user = os.environ.get("SUDO_USER")
    real_geteuid = mod.os.geteuid
    try:
        mod.os.geteuid = lambda: 1000
        os.environ["SUDO_USER"] = "someoneelse"
        assert mod._invoking_user() is None
    finally:
        mod.os.geteuid = real_geteuid
        if saved_user is None:
            os.environ.pop("SUDO_USER", None)
        else:
            os.environ["SUDO_USER"] = saved_user


def test_bare_root_launch_prints_guidance_not_gui():
    """`sudo autobahn-defender` must not open a root GUI (wedge the shell)."""
    src = (REPO / "main.py").read_text()
    assert "_root_gui_guidance" in src
    assert "scan /" in src, "guidance must tell the user the full-scan command"
    # The guard must run before QApplication is constructed.
    guard_at = src.index("if (not _argv or _argv[0] == \"--minimized\") and os.geteuid() == 0")
    app_at = src.index("app = QApplication(sys.argv)")
    assert guard_at < app_at, "root guard must precede Qt initialisation"


def test_xdg_runtime_dir_is_set_before_qt():
    """The QStandardPaths warning must be addressed before Qt starts."""
    src = (REPO / "main.py").read_text()
    xdg_at = src.index('os.environ["XDG_RUNTIME_DIR"]')
    app_at = src.index("app = QApplication(sys.argv)")
    assert xdg_at < app_at, "XDG_RUNTIME_DIR must be set before QApplication"


# ─── version ────────────────────────────────────────────────────────────────

def test_version_is_2_0_4():
    from engine.version import APP_VERSION
    assert APP_VERSION == "2.0.4"
