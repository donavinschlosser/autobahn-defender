# Autobahn Defender v2.0.4 Release Notes

**Date:** 2026-09-20 · **Type:** Full-system scan performance + sudo/root correctness · **Tag:** `v2.0.4`

---

## The report that started this

A user on Linux Mint 22.2 (ASUS ZenBook, i7, 15 GB RAM) installed the v2.0.3
hotfix and ran a **Full System scan** from the GUI. It collected **6,061,291
files** (a 30–45 minute wait in itself), then displayed:

```
YARA: 0/6,061,291 files scanned
```

…and the progress bar **never moved off 0%**. He let it run, theorised the VPN
or its kill switch was throttling it, retried with both disabled, then tried
`sudo autobahn-defender` in a terminal — where the process appeared to hang, he
could not get a shell prompt back, and his terminal warned that closing it
"will kill the process".

It was not a hang and it was not the VPN.

---

## Root cause 1 — a subprocess per file (~85x slowdown)

**This was the whole reported symptom.**

Both scan paths answered one question — *"is this file owned by a package?"* —
with a **separate subprocess per file**:

```python
subprocess.run(["dpkg", "-S", filepath], ...)
```

Measured on a normal desktop: **~300–365 ms per call**. It runs for every file
under `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/opt` and `/boot` — about
**56% of a real file tree**.

Measured YARA-phase throughput over real `/usr/bin` files:

| | files/s | 6,061,291 files would take |
|---|---|---|
| v2.0.3 (per-file `dpkg -S`) | **11.8** | **~143 hours** |
| v2.0.4 (ownership index) | **602** | **~2.8 hours** |

**Why the bar read a frozen 0%:** the bar is 0–100 for the whole scan and YARA
owns 0–50, with a floor that pins it to **1%** until the phase is 4% done.
Reaching 2% required **242,452 files** — about 5.7 hours at the old rate. The
counter label also refreshes only every 2,000 files, i.e. once every ~169
seconds at that speed. It was crawling, not stalled.

### The fix

A user reported a frozen bar; the fix is to stop asking dpkg one file at a
time. An **in-process ownership index** (`engine/dpkg_ownership.py`) is built
once per scan from dpkg's own file lists (`/var/lib/dpkg/info/*.list`):

- 619,851 paths built in **~0.3–0.6 s**, ~100 MB RSS, cached for the process
  lifetime (verified: not rebuilt per call).
- **Differentially verified against `dpkg-query -S` ground truth on 1,500 real
  files: 0 false negatives, 0 false positives.**
- **Fails safe.** If the index cannot be built (non-Debian host, unreadable
  database), ownership returns *unknown* and the caller keeps the
  review-first `action=flag` verdict — it never treats "unknown" as "safe to
  auto-quarantine".

### Latent defect found and fixed alongside

On Arch/Fedora the missing `dpkg` binary raised `FileNotFoundError`, which was
swallowed by a bare `except`, silently setting `is_distro_file = False` — which
**re-enabled auto-quarantine of package-owned system binaries**. Both paths now
fail safe.

---

## Root cause 2 — the scan ate ~10 GB of RAM before scanning anything

The YARA phase submitted **every file as a future before consuming a single
result**:

```python
futures = {pool.submit(_scan_single_file, f): f for f in scannable_files}
```

Measured:

| files | submit time | peak RSS |
|---|---|---|
| 250,000 | 2.2 s | 441 MB |
| 1,000,000 | 9.3 s | 1,729 MB |
| 6,061,291 | **58–72 s** | **~10.2 GB** |

That is ~10 GB of a 15 GB laptop spent on bookkeeping, plus a minute of dead
time before the first file is scanned. Under an 8 GB cap the same pattern
raises **MemoryError** — and the user had already said he was moving to an
**8 GB** laptop next.

**Fix:** a bounded in-flight window (`max(threads*4, 64)` futures, refilled as
results drain). Measured: **peak 64 in-flight futures for 20,000 files**, and
peak RSS stayed flat at **170 MB across 600,000 scans** where the old code
would have added ~500 MB of pure overhead.

---

## Root cause 3 — the file list was walked twice per scan

YARA and ClamAV each built their own file list. At this scale a single walk is
**~14 minutes**, so every scan wasted ~28 minutes re-discovering the same
files. The list is now collected once and shared by both phases.

---

## Root cause 4 — Why 6,061,291 files?

The count was inflated by duplicate data. A full-system scan of `/` walked
straight into:

- **`/media`, `/mnt`, `/run/media`** — every attached drive, rescanned as if it
  were part of the system.
- **`/timeshift`, `/timeshift-btrfs`** — Linux Mint enables Timeshift snapshots
  by default, and each snapshot is a full copy of the system tree.

These are now skipped **by absolute path** — deliberately *not* by directory
name, so a user folder called `media` or `mnt` is still scanned. Regression
tests pin both directions.

---

## Root cause 5 — `sudo autobahn-defender` opened a root GUI

With no command argument the app falls through to the **graphical interface**.
Run under `sudo` that means:

- The terminal blocks on the GUI forever — which is exactly why the user
  thought it had frozen and could not get his prompt back.
- `QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-root'`
  (the harmless warning in his log, now avoided by setting the variable before
  Qt initialises).
- **App data went to `/root/.autobahn`.** Quarantined files, the detection
  ledger and history landed in root's home where the user's GUI could never
  see or restore them.

**Fixes:**

- A bare launch as root now **prints the correct command** —
  `sudo autobahn-defender scan /` for a real full-system scan — instead of
  opening a GUI that wedges the terminal. `--gui` deliberately opts back in.
- App data now resolves to the **SUDO_USER's home**, and directories created by
  a root run are **handed back** to that user so the GUI can still manage them.

---

## Also in this release

- **Progress reporting**: the YARA counter now updates on a time basis rather
  than every 2,000 files, so a large scan shows movement promptly.
- **AppImage bundle gate**: `engine/dpkg_ownership` added to
  `tools/verify_bundle.py` — the build fails if the module is missing, rather
  than shipping an AppImage that crashes on its first scan.

---

## Verification performed

Every fix has regression tests that were **proven to fail when the defect is
reintroduced** (mutation-tested in both directions):

| Fix | Test evidence |
|---|---|
| Ownership index | 0 FN / 0 FP vs `dpkg-query` on 1,500 real files; index built once, not per call |
| Unknown ownership fails safe | forced-empty index → still review-first |
| Bounded futures | measured 64 in-flight for 20k files; unbounded code measured 1,699 → test fails |
| Single collection | `_run_inner` walks exactly once |
| Mount skipping | functional test: sibling dir skipped, normal dir scanned |
| Root guard | guard runs before `QApplication`; guidance mentions `scan /` |
| XDG_RUNTIME_DIR | set before Qt initialises |
| Version | all five constants report 2.0.4 |

**End-to-end throughput, real code over real `/usr/bin` files:**
**11.8 → 602 files/s (51x).** Estimated full-system scan: **143 h → ~2.8 h.**

Test suite: **174 passed, 61 skipped, 0 failed** (plus 18 functional tests that
require PyQt6, all passing under the system interpreter).

---

## Upgrading

**Debian / Ubuntu / Linux Mint:**

```bash
sudo dpkg -i autobahn-defender_2.0.4_amd64.deb
```

Installing over 2.0.3 preserves your data — definitions, YARA rules, history,
quarantine and whitelist all stay in `~/.autobahn`.

**AppImage:**

```bash
chmod +x AutobahnDefender.AppImage
./AutobahnDefender.AppImage
```

---

## If you hit the frozen progress bar on 2.0.3

You were not doing anything wrong, and it was not your VPN. The scan was
running — just roughly 50x slower than it should have been. Update to 2.0.4 and
run the same scan; a full-system pass completes in a few hours rather than
days, and the progress bar moves from the start.

For a full-system scan from the terminal, use:

```bash
sudo autobahn-defender scan /
```
