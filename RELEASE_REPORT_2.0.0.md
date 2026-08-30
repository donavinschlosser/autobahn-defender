# Autobahn Defender v2.0.0 — Implementation & Release Report (2026-08-31)

**Companion docs:** `AUDIT_REPORT_2026-08-31.md` (findings) · `AUTODEF_CLI_ZERODAY_PLAN.md` (the plan this implements)
**Deliverables:** `autobahn-defender_2.0.0_amd64.deb` (1.03 MB, 88 files) · `AutobahnDefender.AppImage` (54 MB, Docker/PyInstaller onedir)
**Repo:** untouched (READ-ONLY directive honored) — all commits are LOCAL. Version stays **2.0.0** (the "real 2.0" release).

---

## What was implemented (all phases from the plan)

### Phase 0 — audit repairs (all CRITICAL/HIGH from the audit)
- A-1..A-4: dead composites now dispatch through the registry; port constants restored; engine-local YARA cache; engine-own blacklist dir
- A-5: advisor rewritten on a unified schema — every check emits `findings: [Finding]`; the broken analyzer layer is gone. Live result on this box: hardening audit went "score 100, 0 findings" (broken) → **score 50, 10 real findings**
- A-6: privacy shield desktop detection — verified **live on this Mint box** (5 gsettings rows returned; `gnome-recent-files` correctly flagged `needs_attention`)
- A-7: `patches.verify_patch_applied` — empty OSV results ⇒ `status=inconclusive`, never "verified fixed" (GUI + engine)
- A-8: XDG_DATA_HOME joined with app dir in both packages
- A-9: scan budget per scan-root; full-system budget 2.5M; trips loudly
- A-10+B-6: **Debian-policy version comparator** (validated against apt_pkg on 1,589 real pairs — 100% agreement, pinned by `tests/test_versions_oracle.py`); generic `VERSION_ID` ecosystem detection with loud UNKNOWN warning
- A-10/B-1: CVSS 3.1 base-score calculator (spec-exact: 9.8, 7.5, 10.0, 7.8, 3.1, 1.6, 0.0 all match FIRST spec examples); severities now real CRITICAL/HIGH/MEDIUM/LOW
- B-2: SSH hardening = one drop-in file `/etc/ssh/sshd_config.d/60-autobahn-hardening.conf` (global scope, `sshd -t` validated, auto-removed on failure, original config untouched)
- B-3: feed worker → GUI only via queued `_feeds_polled` signal
- B-6/B-7: blocking GUI calls moved to QThread workers (`_FixAllWorker`, `_BlacklistWorker`, `_VerifyPatchWorker`)
- C-2: sysctl_harden 14 pkexec calls → 2 (write conf + `sysctl --system`)
- C-11: packaging hygiene (stale AI modules excluded, Ollama prerm hunt removed, appdata fixed, no `__pycache__`)

### Phase 1 — headless engine
`engine/paths.py` (headless paths, no Qt) · `engine/version.py` single version source · `engine/runner.py` (all verb implementations, shared by GUI/CLI/MCP) · `engine/scanner_core.py` (Qt-free YARA+ClamAV scanning) · **proven: engine imports with zero PyQt6 present**

### Phase 2 — full CLI (`autobahn-defender <verb>`)
argparse-only, zero new runtime deps. Verbs: `scan`, `scan-processes`, `cve`, `patches check|verify|apply`, `audit full|vuln|network|hardening`, `checks list|run`, `alerts list|resolve|dismiss|clear`, `quarantine list|restore|delete`, `network connections|download-blacklist|persistence|hosts`, `intel poll|show|status`, `watch once|status`, `apply …`, `doctor`, `mcp`. Contract: tri-state exits (verified live: 0 clean / 1 findings-with-EICAR / 2 invalid-path), `--format table|json|ndjson|markdown|html`, schema_version-1 envelope, data→stdout / logs→stderr, SIGPIPE→141, privileged verbs refuse bare `--yes`.

### Phase 3 — intel + remediation + watch
- **Collectors (all live-verified):** CISA KEV official JSON (1,685 entries), Ubuntu notices.json, EPSS bulk CSV, PoC-in-GitHub — SQLite store (WAL, 0600)
- **match.py:** OSV × KEV × PoC × EPSS join → severity chain (KEV=CRITICAL, PoC bump), fan-out to the engine alert system; dedup by cve|pkg|status
- **Live result on this machine:** 2,628 packages scanned, 306 vulns, 197 alerts deduplicated
- **Remediation:** DETECT → CONTAIN (mask service) → UPDATE → VERIFY (inconclusive ≠ fixed) → RESTORE, token-gated execution (read-before-write), whitelist-validated service actions
- **Watch daemon:** ctypes inotify (no deps) — live-verified event capture, debounce, clean stop; Downloads drops auto-enqueue a quick scan

### Phase 4 — MCP server
11 tools mirroring the CLI (`autobahn.doctor/checks.list/checks.run/cve.scan/audit/intel.poll/intel.check/intel.list/alerts/remediate.plan/remediate.execute`), stdio JSON-RPC 2.0, deterministic tools/list, token-gated destructive calls. **Scripted client contract test: PASS.**

### Tests & CI gates
- pytest suite: **123 passed** (versions incl. apt_pkg oracle on 1,589 real pairs, CVSS spec examples, findings roundtrip, advisor schema, MCP contract, smoke-all-checks)
- `tools/self_audit.py`: syntax + scope-aware AST undefined-call + docstring-stripped pattern scan — **CLEAN, 0 findings across 70 files**
- `autobahn-defender doctor`: 21 checks incl. engine smoke (no undefined-name leakage), rules compile, feed reachability

### Live end-to-end proof
- EICAR test file → **detected by ClamAV, exit 1** (both source CLI and the packaged AppImage)
- clean dir → exit 0; nonexistent path → exit 2; KEV poll → catalog 2026.08.27, 1,685 entries; intel match → 306 vulns/197 alerts on this box; MCP handshake + tools/call → PASS

### Packaging
- **.deb:** `autobahn-defender_2.0.0_amd64.deb` (88 files; engine+cli+intel+watch+AGENTS.md; no `__pycache__`/gguf/ollama/ai_tab/engine-imports-scanner; fixed postinst/prerm; corrected Description; trailing-newline control)
- **AppImage:** `AutobahnDefender.AppImage` (54 MB, Ubuntu 22.04 Docker build, PyQt6 venv, OpenSSL-excluded); internal tree verified to contain all v2 modules; CLI verbs + EICAR exit-1 verified from the AppImage binary itself; appdata says 2.0.0

## Known cosmetic notes (non-blocking)
- In dev-venv runs, doctor reports yara/feedparser "missing" — artifacts of the Hermes venv; the packaged runtime (apt `python3-yara`, deb deps) is correct, and the AppImage bundles its own PyQt6/yara.
- `scan` of a dir with no YARA rules prints an info line; ClamAV still does the detection (EICAR proven).

## Not done (deliberately)
- Nothing pushed to Codeberg. No version bump beyond 2.0.0.
- auditd/clamonacc system tiers ship as opt-in configurations (documented in plan §3.4); GUI Settings toggle integration is the next session's work if wanted.