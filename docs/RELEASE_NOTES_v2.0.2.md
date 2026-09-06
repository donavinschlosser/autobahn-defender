# Autobahn Defender v2.0.2 Release Notes

**Date:** 2026-09-07 · **Type:** Self-contained AppImage + scan-hang fix · **Tag:** `v2.0.2`

## Why this release

Two things: a scan hang reported on an eCryptfs-encrypted system, and the
AppImage's "no system installs" promise — users who deliberately chose the
AppImage to avoid touching their system were still prompted to `apt-get
install` ClamAV. Both fixed, plus the AppImage is now fully self-contained.

## Fixed

### Scan hang on eCryptfs-encrypted systems (stderr pipe deadlock)

**Symptom** (user report): a full scan spawned processes equal to core count,
some finished and closed, the rest idled at 0% CPU / 0% disk forever, and the
progress bar hung. The one visible error row was a truncated mid-path
eCryptfs filename.

**Root cause:** clamscan writes one error line to stderr per unreadable
file, and the app read stderr only *after* the process exited. Linux pipes
buffer ~64KB of unread data. On an eCryptfs home, a full scan walks the raw
encrypted store (thousands of `ECRYPTFS_FNEK_ENCRYPTED.…` files, ~190-char
paths each, all unreadable ciphertext), so stderr filled the pipe buffer,
clamscan blocked on its next write, stdout went silent, and the reader
waited forever. Chunks with few unreadable files finished; the rest wedged.

**Fix (four layers):**
1. All three ClamAV runners (GUI single, GUI parallel, headless engine) now
   capture stderr to a temp file — unbounded, read after exit. The deadlock
   is structurally impossible now.
2. Raw eCryptfs stores (`/home/.ecryptfs`, `/.ecryptfs`) are skipped by both
   engines — ciphertext can't match signatures, and the decrypted files at
   the real mount point are already scanned.
3. Unreadable files aggregate into ONE honest row ("ClamAV could not read
   N file(s) — encrypted (eCryptfs), permission-denied, or missing. First: …")
   instead of a truncated path posing as the whole error.
4. Stall watchdog: any clamscan process producing no output for 900 s is
   killed and reported. Worst case is now a completed scan with a reported
   error, never an eternal spinner.

**Work distribution:** fixed equal chunks (equal file counts, wildly unequal
scan times) left stragglers idling while a few chunks ground on. Replaced
with queue-based batching — each worker pulls its next batch from a shared
queue, so all workers stay busy until the very end.

**Regression proof:** a 1 MB stderr-flood test deadlocked against the old
code (hit the test timeout) and completes in ~0.1 s with the fix.

### CPU-load note (from the same report)

One process per logical core with HT counted, each single-threaded and
signature-DB/memory bound — ~50% aggregate load on a hyperthreaded CPU is
expected, not a bug.

## Added

### Fully self-contained AppImage

The AppImage now bundles the complete ClamAV engine (clamscan 1.5.3 + its
full shared-library closure, RPATH-isolated so bundled OpenSSL never leaks to
the host and host libraries never conflict with the bundle):

- **Zero system installs.** The "install dependencies?" prompt is gone for
  the AppImage — everything the scanner needs travels inside the AppImage.
- **Virus definitions download on first run** directly over HTTPS (official
  database.clamav.net) into `~/.autobahn/definitions` — atomic, verified
  (CVD magic), resumable, no root, no freshclam system service. The
  "Update Definitions" button uses the same path when freshclam is absent.
- The .deb is *unchanged* in behavior — it keeps proper apt dependencies,
  which is the deb's job.
- The build gate now **runs the bundled clamscan inside the bundle** and
  fails the build if it can't execute, so a broken engine can't ship.

**Size:** 56 MB → 76 MB (the difference is the bundled engine).

## Also in this release

- Efficiency: the per-scan-line watchdog timestamp no longer takes the
  shared lock (GIL-atomic float store) — previously all scan workers
  serialized on one lock per stdout line.

## Upgrade

```bash
sudo dpkg -i autobahn-defender_2.0.1_amd64.deb   # → use 2.0.2 file
```

Drop-in over 2.0.1/2.0.0 — `~/.autobahn` data and
`~/.local/share/autobahn-defender` are preserved. Restart any connected AI
app after upgrading so MCP spawns fresh code. AppImage users: replace the
old file; on first launch it downloads definitions to your user folder
(~300 MB, one-time, no root).

**eCryptfs users:** scans now skip the raw encrypted store automatically —
no whitelist entry needed anymore.

## Files

| Artifact | For |
|---|---|
| `autobahn-defender_2.0.2_amd64.deb` | Debian / Ubuntu / Linux Mint |
| `AutobahnDefender.AppImage` (self-contained) | any distro (glibc 2.35+) |

— Digital Autobahn · XMPP: digitalautobahn@xmpp.brax.me