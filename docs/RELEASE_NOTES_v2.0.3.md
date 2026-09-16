# Autobahn Defender v2.0.3 Release Notes

**Date:** 2026-09-16 · **Type:** Parallel ClamAV silent-skip fix · **Tag:** `v2.0.3`

## Why this release

A user report against the released v2.0.2 `.deb`:

```
File ".../scanner.py", line 1757, in run_single_clamscan
UnboundLocalError: cannot access local variable 'file_list_path'
    where it is not associated with a value
Exception in thread Thread-8 (run_single_clamscan):
```

Tracing it uncovered **two defects in the parallel ClamAV scanner**. Together
they made every parallel ClamAV scan fail: the 2.0.2 code reports **0 files
scanned** with error rows, never a silent partial scan — but also never any
ClamAV coverage.

## Fixed

### 1. The scan block sat outside the batch loop (reported symptom)

In `scanner.py`, `run_single_clamscan()` (nested in `_run_clamscan_parallel()`)
distributes work via a shared `queue.Queue` that `num_procs` worker threads
drain with `get_nowait()`. The try/except/finally that runs clamscan was at
the **same indentation as the `while` loop** — a sibling of the loop, not its
child — while `file_list_path` and `stderr_path` were only ever bound inside
the loop body.

Consequence: any worker that found the queue empty on its first check (the
common case — workers race to drain one queue) fell straight through to the
orphaned `finally:` and hit `if file_list_path:` with the name unbound:

```
UnboundLocalError: cannot access local variable 'file_list_path'
```

That is the reported `Exception in thread Thread-8` — the 8th of 8 workers
losing the race.

### 2. `clam_env` was never bound in the worker's scope (found while fixing #1)

The surviving workers' `subprocess.Popen(..., env=clam_env)` referenced
`clam_env`, which was bound in the *single-process* runner but never in
`_run_clamscan_parallel()`. Every batch that reached Popen died with:

```
NameError: name 'clam_env' is not defined
```

captured as a `ClamAV scan error` row. So even the "survivor" batch scanned
nothing. Verified live against the shipped 2.0.2 code with the real runner
driven by a stub clamscan: 1000 files / 8 workers → **0 files scanned, 8
error rows, 9 worker-thread deaths** (8 × UnboundLocalError +
NameError rows).

## The fix

- The scan try/except/finally block was moved **inside** the batch loop
  (indentation only — no logic changes), matching the function's own
  docstring: *"Each batch runs in its own clamscan process (its stderr
  capture file and `-f` file list are per-batch)."*
- `clam_env` is now bound once at function scope in `_run_clamscan_parallel`,
  mirroring `_run_clamscan`'s bundled-vs-system logic (a bundled clamscan
  gets `LD_LIBRARY_PATH` pointed at the private clamav lib dir; system
  clamscan gets the clean env).

The `# Launch worker threads` comment and the *"Scanning N files with M
processes"* emit stay **outside** the loop at indent 8 — it fires exactly
once, not once per batch.

## Verified

- **Live reproduction, before/after** (real `_run_clamscan_parallel` driven
  through `ScanWorker` with a stub clamscan):
  - shipped 2.0.2: 1000 files / 8 workers → 0 scanned, 8 error rows,
    9 thread deaths; 4000 files → same.
  - fixed: 1000/1000 and 4000/4000 scanned, 0 error rows, 0 thread deaths,
    startup emit fires exactly once.
- **Real clamscan end-to-end:** 153-file tree with a planted EICAR file →
  153/153 scanned, `Eicar-Test-Signature` detected and quarantined, 0
  thread deaths, 0 error rows.
- **New regression tests** (`tests/test_parallel_clamscan_indent.py`, 7
  tests): 4 structural (AST) + 3 runtime (real runner, stub clamscan,
  asserting full coverage, no thread deaths, single startup emit). Proven
  red on the shipped 2.0.2 code (5 failures including the live
  UnboundLocalError) and green after the fix.
- Full suite: 163 passed, 54 skipped (environmental), including
  `test_clamav_hang_fix.py` (the v2.0.2 stderr-deadlock pins).

## Not touched

- `engine/scanner_core.py` (the headless CLI/MCP path) was already correct
  and is unchanged — verified, not modified.
- YARA scanning is a separate code path (`_run_yara()`, ThreadPoolExecutor)
  and was never affected by either defect.
- The `QStandardPaths: XDG_RUNTIME_DIR not set` warning in the report is
  cosmetic (the GUI was launched via `sudo`, which is not recommended —
  launch it as your normal user). The `Failed to fetch feed … Read timed
  out` message is a transient RSS-feed timeout, retried on the next poll.
  Neither is a defect.

## Upgrade

```bash
sudo dpkg -i autobahn-defender_2.0.3_amd64.deb
sudo apt-get install -f        # only if dependencies are reported missing
```

Drop-in over 2.0.x — `~/.autobahn` data (history, quarantine, rules,
definitions) is preserved. AppImage users: replace the old file. Restart any
connected AI app after upgrading so MCP spawns fresh code.

**If you ran a parallel ClamAV scan on 2.0.2 and saw "0 files scanned" (or a
`ClamAV scan error` row), this release is the fix.** Re-scan after upgrading;
the scanned-file count should be close to the total file count.

## Files

| Artifact | For |
|---|---|
| `autobahn-defender_2.0.3_amd64.deb` | Debian / Ubuntu / Linux Mint |
| `AutobahnDefender.AppImage` (self-contained) | any distro (glibc 2.35+) |

— Digital Autobahn · XMPP: digitalautobahn@xmpp.brax.me
