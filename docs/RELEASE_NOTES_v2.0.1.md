# Autobahn Defender v2.0.1 Release Notes

**Date:** 2026-09-06 · **Type:** Hotfix + AI scan engine · **Tag:** `v2.0.1`

## Why this release

Two bugs shipped in the v2.0.0 AppImage (the .deb was unaffected), plus the
MCP scan-engine feature that rounds out the AI-agent integration.

## Fixed

### AppImage: missing AI Agent / Security Center / Security News tabs

The v2.0.0 AppImage build script had a stale file-copy list: the three v2 GUI
tab modules never reached the packaging step, and the packaging tool only
**warns** (does not fail) when a listed module can't be found — so the
release shipped without them and users saw no AI Agent tab.

**Fix:** the build copies the three tab modules explicitly and hard-fails if
any is missing; a new `tools/verify_bundle.py` gate parses the packaged
module archive (PYZ TOC) and verifies every required module, the `yara`
extension, and the bundled YARA rules before the AppImage is created.

### AppImage: Rootkit scan (and all YARA-phase scans) force-closed the app

The v2.0.0 AppImage bundle was also missing `yara-python`. When the import
failed, the scanner's error handler referenced the `yara` module in an
`except yara.SyntaxError` clause — raising `NameError` *before the import
error could be handled*. The exception escaped the scan thread, and PyQt6
treats an exception escaping `QThread.run` as a hard abort of the entire
process. That's the instant force-close.

**Fix (three layers):**
1. `yara-python` is bundled (build fails without it).
2. The YARA rule compiler imports `yara` under its own guard and reports
   "yara-python is not available (YARA engine disabled)" as a normal error.
3. Every GUI background worker (scan, definitions, firewall apply, hardening
   check, USB monitor, file monitor) now has a last-resort crash guard:
   unexpected exceptions surface as UI error messages instead of killing the
   process.

## Added

### `autobahn.scan` — MCP file/folder/drive scanning with a live feed (12th tool)

AI agents can now run real YARA + ClamAV malware scans themselves:

| Action | What it does |
|--------|--------------|
| `start {paths:[...], quick?}` | start a scan; returns `job_id` immediately |
| `status {job_id}` | live progress: percent, state, threats so far |
| `tail {job_id, lines?}` | last N feed events — the live file trail |
| `wait {job_id, timeout_s?}` | block until done → full result envelope |
| `cancel {job_id}` | cooperative cancel (SIGTERM to the verified worker pid) |
| `list` | recent jobs |

Design points:

- The scan worker runs **detached** — it survives the MCP host disconnecting
  (proven: parent process exited, child completed and wrote its result).
- The feed is an NDJSON file under `~/.local/share/autobahn-defender/scan-jobs/<id>/`:
  `start → progress* → quarantined* → done`. The last event is always the
  final state — a crashed worker is reported as `lost`, never silently hung.
- Quarantine behaves exactly like GUI scans: detection-ledger binding with
  SHA256 content hashes, distro-owned files (`dpkg -S`) flagged for review
  instead of auto-quarantined.
- Short-timeout hosts (LM Studio's hard 60 s bridge) use `start` +
  `status`/`tail` polling; long-timeout hosts (Hermes, CI) call `wait`.
- Works from the deb, the AppImage, and source checkouts — the worker child
  always runs through the app's own `scan-job` CLI verb, never a raw
  `python -c` (impossible inside frozen bundles).
- Headless hosts get bundled YARA rules seeded automatically (GUI parity:
  previously the rules only appeared after first GUI launch).
- 11 new tests; live-verified end-to-end with an EICAR test file through the
  MCP protocol (detected by both engines, quarantined, ledger-recorded).

## Also in this release

- `engine/scanner_core.py`: `files_scanned` is now the sum of both engine
  phases — previously the ClamAV phase overwrote the YARA count, reporting
  0 files scanned on hosts without clamscan.
- Headless MCP scans seed bundled YARA rules into `~/.autobahn/rules` when
  missing (previously they silently scanned with no rules).
- The Sep 4 MCP improvements are included for real this time (they were
  local-only since Sep 4): cache-first `autobahn.cve.scan` and the parallel
  request loop for short-timeout MCP hosts (LM Studio -32001 fix).
- `docs/AGENTS.md` documents the `scan-job` verb and the `autobahn.scan`
  contract.

## Upgrade

```bash
sudo dpkg -i autobahn-defender_2.0.1_amd64.deb
```

Drop-in over 2.0.0 — `~/.autobahn` data (history, quarantine, rules,
definitions) and `~/.local/share/autobahn-defender` (intel, caches) are
preserved. **Tip:** if you had the MCP server running, restart your AI app
after upgrading so it spawns the new code (or `pkill -f 'main.py mcp'`).

AppImage: replace the old file, `chmod +x AutobahnDefender.AppImage`.

## Files

| Artifact | For |
|---|---|
| `autobahn-defender_2.0.1_amd64.deb` | Debian / Ubuntu / Linux Mint |
| `AutobahnDefender.AppImage` | any distro (glibc 2.35+) |

— Digital Autobahn · XMPP: digitalautobahn@xmpp.brax.me