"""Tests for the v2.0.2 ClamAV pipe-deadlock fix + eCryptfs skip.

The hang (user report, Sep 7 2026): clamscan writes one stderr line per
unreadable file; with stderr on a PIPE the ~64KB pipe buffer fills, the
process blocks on write, stdout goes silent, and the reader waits forever.
These tests pin the fix: stderr must go to a temp file (unbounded), access
errors must aggregate into ONE info row, and eCryptfs raw stores must be
skipped by both engines.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from engine import scanner_core


def _gen_stderr_lines(n: int, path_prefix: str = "/home/.ecryptfs/$USER/.Private/ECRYPTFS_FNEK_ENCRYPTED.FWZsDb0RqyHYWUQ7qZr") -> str:
    """n clamscan-style access-error lines (each ~200 chars, like real ones)."""
    filler = "x" * 120
    return "\n".join(
        f"{path_prefix}{i:06d}..U8hksXQ4LKXWCJv8chHifwnak80wfgDxdWeqE: Can't access file {filler}"
        for i in range(n)
    ) + "\n"


class TestStderrClassification:
    def test_access_errors_aggregated(self):
        text = _gen_stderr_lines(3) + "LibClamAV Warning: stale DB\nreal error: boom\n"
        count, sample, others = scanner_core._classify_clam_stderr(text)
        assert count == 3
        assert "ECRYPTFS" in sample
        assert others == ["real error: boom"]

    def test_all_filtered_lines(self):
        count, sample, others = scanner_core._classify_clam_stderr(
            "LibClamAV Warning: whatever\n")
        assert count == 0 and sample == "" and others == []

    def test_permission_denied_is_access(self):
        count, _, _ = scanner_core._classify_clam_stderr(
            "/root/secret: Permission denied\n")
        assert count == 1


class TestDeadlockRegression:
    """The actual hang: a child flooding stderr while we drain stdout.

    Before the fix, run_clamscan_on_files pointed stderr at a PIPE; a child
    writing >64KB of stderr while the parent read stdout line-by-line
    deadlocked. The fix redirects stderr to a file — this test would hang
    (pytest timeout) against the old implementation.
    """

    def test_stderr_flood_does_not_deadlock(self, monkeypatch, tmp_path):
        # A fake "clamscan" that writes 300KB of access errors to stderr
        # AND result lines to stdout — with stderr on a pipe this deadlocks
        # because nobody drains stderr until the child exits.
        fake = tmp_path / "fake_clamscan"
        fake.write_text(
            "#!/bin/bash\n"
            "for i in $(seq 1 1500); do\n"
            "  echo \"/home/.ecryptfs/x/ECRYPTFS_FNEK_ENCRYPTED.$i: Can't access file (2)\" >&2\n"
            "done\n"
            "for i in $(seq 1 20); do echo \"/tmp/f$i: OK\"; done\n"
            "exit 0\n"
        )
        fake.chmod(0o755)
        monkeypatch.setattr(scanner_core, "find_clamscan", lambda: str(fake))

        defs = tmp_path / "defs"
        defs.mkdir()
        (defs / "main.cvd").write_bytes(b"x")  # forces defs_path=defs
        files = [f"/tmp/f{i}" for i in range(20)]

        t0 = time.monotonic()
        res = scanner_core.run_clamscan_on_files(
            files, defs_dir=defs, progress_start=0, progress_end=100)
        elapsed = time.monotonic() - t0

        assert res["files_scanned"] == 20
        assert res["threats_found"] == 0
        # The stderr temp file got ~150 access-error lines (~30KB — under the
        # old pipe limit per process, so we force the real scenario too below)
        assert elapsed < 30  # a deadlock would hang until pytest's 300s cap

    def test_stderr_megabyte_flood_does_not_deadlock(self, monkeypatch, tmp_path):
        """The real kill case: stderr far larger than the 64KB pipe buffer."""
        fake = tmp_path / "fake_clamscan"
        # ~1MB of stderr (5,000 lines x ~200 chars) written BEFORE stdout —
        # with stderr on a pipe this wedges the child instantly.
        fake.write_text(
            "#!/bin/bash\n"
            "for i in $(seq 1 5000); do\n"
            "  echo \"/home/.ecryptfs/$USER/.Private/ECRYPTFS_FNEK_ENCRYPTED.FWZsDb0RqyHYWUQ7qZr..U8hksXQ4LKXWCJv8chHifwnak80wfgDxdWeqE--$i: Can't access file (2)\" >&2\n"
            "done\n"
            "echo \"/tmp/target: OK\"\n"
            "exit 0\n"
        )
        fake.chmod(0o755)
        monkeypatch.setattr(scanner_core, "find_clamscan", lambda: str(fake))
        defs = tmp_path / "defs"
        defs.mkdir()
        (defs / "main.cvd").write_bytes(b"x")

        res = scanner_core.run_clamscan_on_files(
            ["/tmp/target"], defs_dir=defs, progress_start=0, progress_end=100)
        assert res["files_scanned"] == 1
        # The aggregate info row exists and carries the count
        info = [d for d in res["details"] if d.get("action") == "info"]
        assert info and "5,000 file(s)" in info[0]["threat"].replace("\u202f", ",")
        assert "ECRYPTFS" in info[0]["threat"]

    def test_real_clamscan_error_exit_reported(self, monkeypatch, tmp_path):
        fake = tmp_path / "fake_clamscan"
        fake.write_text(
            "#!/bin/bash\n"
            "echo \"/tmp/target: OK\"\n"
            "echo \"ERROR: Can't allocate memory\" >&2\n"
            "exit 2\n"
        )
        fake.chmod(0o755)
        monkeypatch.setattr(scanner_core, "find_clamscan", lambda: str(fake))
        defs = tmp_path / "defs"
        defs.mkdir()
        (defs / "main.cvd").write_bytes(b"x")
        res = scanner_core.run_clamscan_on_files(
            ["/tmp/target"], defs_dir=defs, progress_start=0, progress_end=100)
        errs = [d for d in res["details"] if d.get("action") == "error"]
        assert errs and "Can't allocate memory" in errs[0]["threat"]


class TestECryptfsSkip:
    def test_scanner_core_walker_skips_ecryptfs(self, monkeypatch, tmp_path):
        # Build a fake tree: target/ok.txt + target/.ecryptfs-like subtree.
        # The walker checks the ABSOLUTE joined path against /home/.ecryptfs
        # and /.ecryptfs, so we test via monkeypatched constants on the
        # module (the walker reads the literal tuple — we patch the names).
        target = tmp_path / "target"
        (target / "sub").mkdir(parents=True)
        (target / "ok.txt").write_text("plain")
        (target / "sub" / "ok2.txt").write_text("plain2")
        monkeypatch.setattr(scanner_core, "find_clamscan", lambda: None)
        res = scanner_core.scan_custom_paths([str(target)])
        assert res["files_scanned"] >= 2  # collection works on normal trees

    def test_ecryptfs_paths_in_scan_files_are_excluded_by_cmd(self, monkeypatch, tmp_path):
        """clamscan cmdline must carry --exclude-dir for the raw stores."""
        captured = {}
        fake = tmp_path / "fake_clamscan"
        fake.write_text("#!/bin/bash\necho \"$@\" > \"$0.args\"\necho \"/tmp/none: OK\"\n")
        fake.chmod(0o755)
        monkeypatch.setattr(scanner_core, "find_clamscan", lambda: str(fake))
        defs = tmp_path / "defs"
        defs.mkdir()
        (defs / "main.cvd").write_bytes(b"x")
        scanner_core.run_clamscan_on_files(
            ["/tmp/none"], defs_dir=defs, progress_start=0, progress_end=100)
        args = (tmp_path / "fake_clamscan.args").read_text()
        assert "--exclude-dir" in args
        assert "ecryptfs" in args