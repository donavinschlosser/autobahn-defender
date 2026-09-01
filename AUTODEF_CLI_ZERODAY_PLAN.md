# Autobahn Defender — CLI Surface + Active Zero-Day/Vulnerability Monitor — Technical Plan

> **Date:** 2026-08-31 · **Companion doc:** `AUDIT_REPORT_2026-08-31.md` (must be read first — Phase 0 fixes its findings)
> **Repo (READ-ONLY):** `https://codeberg.org/donavinschlosser/autobahn-defender` — nothing in this plan is pushed/uploaded; all work is local
> **Working copy:** repository root
> **Research digests (verified live, with cited URLs):** §R1 zero-day/monitoring digest at `docs/RESEARCH_zero_day_monitoring_digest_2026-08-31.md` (in-repo copy) · CLI digest at `docs/RESEARCH_cli_design_digest_2026-08-31.md` (in-repo copy) (copy both into the project — done at end of this session)
> **Standing directives honored:** no Codeberg pushes, no version bump, no permanent system changes without explicit confirmation, adapt-not-copy for ports, contact = XMPP digitalautobahn@xmpp.brax.me

**Goal:** (1) A complete CLI (`autobahn-defender <verb>`) that drives *every* capability of the app — scans, CVEs, audits, alerts, patch tracking, hardening, network watch, quarantine, updates, reports — for humans, scripts, and AI agents; (2) an always-on **exploited-vulnerability & behavior monitor** that watches the installed PC for actively-exploited CVEs ("zero-days" in the colloquial sense) and post-exploitation behavior, with a review-first remediation loop (disable feature → update → verify → re-enable); (3) efficiency, honesty-of-output, and architecture fixes surfaced by the 2026-08-31 audit.

**Architecture in one paragraph:** The existing `engine/` package becomes the single headless core (it already is 90% headless — three import fixes required). A new `cli/` package (argparse, zero deps) and an optional MCP stdio server (`cli/mcp_server.py`) both call the same engine functions the GUI calls — one codebase, three front-ends. The "zero-day monitor" is a **daily threat-intel pipeline** (CISA KEV + Ubuntu OSV export + EPSS + PoC feeds, all keyless and live-verified) joined against the installed package list, plus **tiered runtime watchers** (inotify = default, auditd = opt-in root helper, fanotify/clamonacc = opt-in on-access, Falco = optional adapter if installed). Remediation is a lifecycle engine (alert → contain → update → verify → re-enable) that always flows through `engine/apply.py`'s pkexec review-first gate. No eBPF, no kernel modules, no daemons that scan as the GUI user — stability first.

---

## 0. Ground rules for every task

- Every file path below is relative to the repository root unless absolute.
- **Never** bump `APP_VERSION`/`CURRENT_VERSION` (stays 2.0.0 until Donavin says otherwise). Version unification in P1.1 is *consolidation* (one constant, all files read it), not a number change.
- Every privileged action: pkexec, argv-only, review-first, logged to `actions.log` with rollback. The CLI adds `--yes` but `apply`-class verbs **refuse `--yes` unless `--i-know-this-is-privileged` is also passed** (agent-safety friction is intentional).
- The GUI never gains a new thread that isn't a QThread. The CLI never spawns Qt.
- TDD: write the failing test first for every Task marked **[T]**. Run `python3 -m pytest tests/ -x` gates per task; `python3 -m py_compile` everywhere.
- Docker VM test (Ubuntu 24.04) before any install on the real machine (preference #4 in the v2 bugfix notes). CI contract = the exact commands in §9.2.

---

## PHASE 0 — Repair the engine (audit findings; blocks everything else)

Order matters: 0.1 first (it makes every later bug visible forever). Effort total ≈ 3–4 days.

### Task 0.1 — Test harness + smoke gate **[THE single highest-leverage fix]** **[TDD]**
**Files:** create `tests/__init__.py`, `tests/conftest.py`, `tests/test_smoke_all_checks.py`, `tests/test_versions.py`, `tests/test_cve_filter.py`, `tests/test_advisor_schemas.py`, `tests/fixtures/ss_established.txt`, `tests/fixtures/apt-s-upgrade.txt`

`tests/test_smoke_all_checks.py` — the harness that would have caught audit findings A-1…A-5:

```python
import pytest
from engine import checks

EXCLUDE = {"check_yara_scan_file"}  # needs rules dir; tested separately in rules test

@pytest.mark.parametrize("name", sorted(set(checks.CHECKS) - EXCLUDE))
def test_check_runs_and_returns_known_shape(name):
    res = checks.run_check(name, {})
    assert res["status"] in ("ok", "error"), f"{name}: malformed result"
    if res["status"] == "error":
        # NameError/ImportError here = the A-1..A-4 bug class. Never acceptable.
        msg = res.get("error", "")
        assert "NameError" not in msg and "defined" not in msg, f"{name}: undefined name leaked: {msg}"
```

`tests/conftest.py` sets `HOME`/`XDG_DATA_HOME` to a `tmp_path` so tests never touch real `~/.autobahn` or `~/.local/share`. Add `pytest -q tests/` as a documented gate; pytest is a **dev-only** dep (in ` requirements-dev.txt`, never in `Depends:`).

- **Step 1:** write tests → run → expect failures exactly matching A-1..A-4, A-10 (red).
- **Step 2:** fix per 0.2–0.6 → green. Commit "test: engine smoke harness + fix dead composite checks".
- **Verify:** `python3 -m pytest tests/ -q` → all pass; each `check_*` returns `status=ok` on this machine (known-skip list for hardware-absent checks).

### Task 0.2 — Fix the undefined-name bugs (A-1..A-4) **[P0, hours]**
**File:** `engine/checks.py`
1. Replace the 10 `_t_*` calls in `check_network_security` (2130–2151) and `check_hardening_audit` (2218–2248) with `check_mod.run_check("check_<name>", {})` equivalents. For `_t_mac_status`: add a real `check_mac_status()` that runs `aa-status`/`getenforce` + profile counts (Kudu `security.ts` port, credit header) — it's the only missing check.
2. Add module-level constants (port from `ai/tools.py:1411,1437`, which is being deleted in P1.5 anyway):

```python
SUSPICIOUS_REMOTE_PORTS = frozenset({
    "4444", "5555", "31337", "6667", "6668", "6669", "12345", "54321",
    "6666", "1337", "1338", "31338", "4712", "6912",
})
HIGH_RISK_PORTS = frozenset({"22", "23", "445", "3389", "4444", "8080", "8443", "1337"})
```
   (values ported from `ai/tools.py:1411–1437`; keep identical to avoid behavior drift)
3. `check_yara_scan_file`: local `import threading` + `_yara_cache: dict = {}`, `_yara_cache_lock = threading.Lock()` at module scope (engine must not import scanner — see P1.1 for how `RULES_DIR` gets resolved without PyQt).
4. Line 1087: `from . import AI_DATA_DIR` → use `BLACKLIST_DIR` from `. import` (engine's own constant), and delete the duplicate downloader in favor of `network_watch.download_blacklist` (de-dup with E-2 of the audit).
5. **Verify:** the audit buttons "Network Audit" and "Hardening Audit" return real findings (run in VM); `pytest tests/test_smoke_all_checks.py` green.

### Task 0.3 — Unify findings schema; delete the analyzer layer **[P0]**
Create `engine/findings.py`:

```python
from dataclasses import dataclass, field

@dataclass
class Finding:
    severity: str            # CRITICAL|HIGH|MEDIUM|LOW|INFO  (fixed enum; CLI output depends on it)
    check_id: str            # "AD-SSH-001" style stable id — CLI/MCP contract (see P2)
    title: str
    what: str
    why: str
    fix: str = ""
    fix_command: str = ""    # argv-shown, never auto-run
    source: str = ""         # module that produced it
    cve_id: str = ""
    raw: dict = field(default_factory=dict)
```

Conversion work:
- Each `check_*` additionally emits `findings: list[Finding-dict]` (keep legacy keys for one release; GUI uses new key; advisor consumes new key only).
- `engine/advisor.py`: delete 8 of 9 `_analyze_*` heuristic bodies; the remaining logic is: collect `Finding`s → dedup by `(severity,title)` → sort → score (`100 − 20·crit − 10·high − 5·med − 2·low`, perm-error cap 89 — unchanged) → render. `_analyze_vulnerability_scan` survives but consumes the new typed CVE dicts (P0.5).
- `check_hardening_audit`/`check_network_security` composites return `{"findings": [...], "sub_checks": {...}}` (one schema everywhere; kills the `dir()` hacks at checks.py:1410/1481/1751).
- **Verify:** `pytest tests/test_advisor_schema.py` — fixture check-outputs → expected findings/score; run audit vs fixture dirs.

### Task 0.4 — The four small silent-failure fixes **[10 min each]**
- **A-6** `engine/privacy.py:109-112`: replace subprocess-echo with `os.environ.get("XDG_CURRENT_DESKTOP","").lower()`; treat `current is None` as `status="not_applicable"`, not `needs_attention`.
- **A-8** `engine/__init__.py:37-40` + `ai/__init__.py:15-18`: `Path(os.environ.get("XDG_DATA_HOME", str(Path.home()/".local/share"))) / "autobahn-defender"`.
- **A-10** `engine/versions.py:48`: `re.sub(r"[+~].*$", "", really.group(1))`. Then (P4) swap comparator to `apt_pkg` via `/usr/bin/python3` (apt_pkg 2.8.3 verified present; pure-Python fallback stays).
- **A-9** `scanner.py`: reset `count = 0` per walked directory (`count` becomes `per_dir` counter inside the walk loop; the scan-root cap for `full_system` becomes `settings.full_system_max_files`, default 2,000,000; quick-scan keeps 100k) + `current_file.emit("File budget reached at …")` when tripped; `_estimate_file_count` cap raised to match (fixes C-13).

### Task 0.5 — CVE correctness trio **[half day]**
- **A-7** `engine/patches.py:verify_patch_applied`: return `{"all_resolved": None, "status": "unknown"}` when `results == []` while open tracked entries exist; `security_tab._verify_patch` renders "verification inconclusive (OSV unreachable / no data)" and the Alert Center keeps the alert open. Only `results non-empty and all(resolved)` ⇒ "verified fixed".
- **B-1** CVSS: add `engine/findings.py::parse_cvss31(vector) -> (score, label)` (base-metric table ~40 lines, standard CVSS 3.1 formula) applied in `cve._normalize_osv_vuln`; keep raw vector in `raw_cvss`. Severity enum `CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN` everywhere (advisor, security_tab, and the future CLI contract).
- **B-6** `cve.py:detect_ecosystem`: parse `VERSION_ID` → `Ubuntu:{major[}.{minor]}` / `Debian:{n}`; Mint override map (22→Ubuntu 24.04, 21→22.04, 20→20.04, LMDE→Debian:12); unknown ⇒ `"UNKNOWN"` + a visible `[WARN] ecosystem unknown — results may be wrong` line in every output (never silently default). Note OSV accepts `Ubuntu:22.04:LTS` and plain `Ubuntu:24.04` — normalize with the `:LTS` suffix when release is LTS (verified live in research; add both to tests).

### Task 0.6 — Threading discipline in the GUI **[1 day]**
- **B-3**: `MainWindow` gets `feeds_polled = pyqtSignal(dict)`; `_poll_feeds_background._do_poll` emits; the GUI-thread slot updates the tab. No widget call from the worker.
- **B-7**: convert `_fix_all_patches`, `_download_blacklist`, `_scan_network`, `_verify_patch`, `_check_privacy`, `_scan_persistence` to small QThread workers (pattern already used by `_CVEWorker`); each emits `finished(dict)`; status label updated in slot. The heavy logic moves into engine functions so P2's CLI reuses them verbatim:
  - `engine/apply.py::apply_batch(packages) -> dict` (loops `apt_upgrade_package`, aggregated result — GUI *and* CLI call this)
  - `engine/network_watch.py::download_and_cache(source) -> dict`
- Long-term the GUI *is* a thin client over `cli/engine` calls; that's what makes "run literally everything from terminal" truthful.

### Task 0.7 — SSH hardening via drop-in **[B-2 fix, 1h]**
`engine/apply.py::ssh_harden` rewritten: write `/etc/ssh/sshd_config.d/60-autobahn-hardening.conf` (content = the 5 settings) via pkexec temp-file copy; **do not touch `sshd_config` at all**; keep `sshd -t` validation and rollback (delete the drop-in); confirm dialog shows the exact file content + that removal = `rm /etc/ssh/sshd_config.d/60-autobahn-hardening.conf && systemctl reload ssh`. Top-of-file Include in Ubuntu/Mint makes drop-ins global-scope (no Match-block trap).

### Task 0.8 — Loud-failure sweep **[C-3, half day]**
The 38 `except: pass/continue` sites (list in AUDIT_REPORT §C-3) get `log.debug(...)`. `run_check` gains `"degraded": bool` (True when any sub-check errored); advisor markdown prints a `⚠ DEGRADED — N checks returned errors` banner; security_tab shows the same as a status line. An audit that silently hides a dead engine is the failure mode we just paid for.

### Task 0.9 — Packaging hygiene **[C-11, 1h]**
Strip `__pycache__` in the build script (`find … -name __pycache__ -exec rm -rf`); delete Ollama hunt from `prerm`; `ai/` in deb ships only `__init__.py, rss_feeds.py, intel_db.py`; fix Description ("4 audit profiles"); drop pip `requirements.txt` from the deb; verify appdata XML exists or remove the empty dir; launcher stays `/usr/bin/autobahn-defender` but gains CLI dispatch (P2).

**Phase 0 exit criteria:** `pytest -q` green; all 4 audit buttons produce real findings in the VM; no `_t_` / undefined names (AST check in CI P6); score for a deliberately-broken fixture drops (regression guards against "secure by bug").

---

## PHASE 1 — Headless foundation (one engine, three front-ends)

### Task 1.1 — `engine/paths.py` (kill the scanner import)
`engine/checks.py:390` does `from scanner import RULES_DIR` — drags PyQt6+quarantine into any CLI import. New `engine/paths.py`:

```python
"""Neutral path constants — importable headless (no Qt, no scanner)."""
import os
from pathlib import Path

APP_DIR      = Path.home() / ".autobahn"
RULES_DIR    = APP_DIR / "rules"
DEFS_DIR     = APP_DIR / "definitions"
QUARANTINE_DIR = APP_DIR / "quarantine"
# engine data dir (fixed per audit A-8)
DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", str(Path.home()/".local/share"))) / "autobahn-defender"
```
`scanner.py` and `engine/*` both import from here (scanner keeps its own alias re-exports so nothing else breaks). `engine/checks.py` drops the scanner import, reads `paths.RULES_DIR`.

### Task 1.2 — `engine/version.py` single source of truth
`APP_VERSION = "2.0.0"` and `DATA_SCHEMA_VERSION = 1` live here; `main.py`, `engine/__init__.py`, `updater.py`, `ai/__init__.py` import it (kills the three divergent constants and the `AutobahnDefender/1.0` User-Agents — D-10).

### Task 1.2b — `engine/runner.py` — the verb implementations
One module with the *actions* both front-ends call. Each returns a plain dict (JSON-serializable, `schema_version` stamped):

```python
def run_scan(scan_type, custom_paths=None, settings_getter=None, progress_cb=None) -> dict
def run_scan_processes() -> dict
def run_cve_scan(ecosystem=None, offline=False) -> dict          # wraps cve.scan_cves + cache read
def run_patch_check() -> dict                                    # patches.check_for_fixes
def run_verify_patch(package, cve_id="") -> dict
def run_audit(task_id) -> dict                                   # wraps advisor.run_audit → .to_dict()
def run_check_by_id(check_id, args=None) -> dict
def run_network_scan(blacklist_refresh=False) -> dict            # connections + threats + persistence
def run_quarantine_list() / restore(name) / delete(name)         # quarantine mgr
def run_intel_poll() -> dict                                     # P4 monitor poll-on-demand
def run_defs_update() / run_yara_update()                        # wraps _DefsUpdateWorker logic
```
GUI threads call these; CLI calls these; MCP tools call these. **That single indirection is the whole CLI plan.** Scan/QThread-only code (ScanWorker) gets a QThread-free twin: `scanner_core.py` with the same `_run_yara/_run_clamscan*` bodies minus pyqtSignal — GUI worker and CLI both drive it with a callback. (Refactor, not rewrite: keep the ScanWorker signatures and feed it a callback adapter.)

---

## PHASE 2 — CLI (`autobahn-defender <verb>`), argparse, zero new deps

Conventions below are distilled from the research digest (`docs/RESEARCH_cli_design_digest_2026-08-31.md` (in-repo copy)): ClamAV/osv-scanner tri-state exits, `--format` choice flag, schema_version'd JSON, argparse-only, stdout=data/stderr=logs, NO_COLOR/isatty, BrokenPipeError→141, `--no-input`, stable check IDs. **Binary name stays `autobahn-defender`** (agents type one thing; `scan`-with-args is never a GUI launch).

### Task 2.1 — `cli/__init__.py`, `cli/exit_codes.py`, `cli/envelope.py` **[TDD]**

```python
# cli/exitcodes.py  (documented in --help; tested in CI)
EXIT_CLEAN      = 0    # completed, no findings
EXIT_FINDINGS   = 1    # completed, findings present
EXIT_ERROR      = 2    # did not complete (I/O, network, engine failure)
EX_USAGE        = 64   # bad args (sysexits; keeps 2 free)
EX_DATAERR      = 65
EXIT_INTERRUPT  = 130  # SIGINT; never catch-and-exit-0
```
`cli/envelope.py` — every JSON document: `{"schema_version": 1, "tool": "autobahn-defender", "version": APP_VERSION, "created": "<UTC ISO8601>", "command": "...", "summary": {...}, "results": [...] , "degraded": bool}`. NDJSON mode emits one line per finding + final `{"event":"summary",...}` line. Severity enum fixed `CRITICAL|HIGH|MEDIUM|LOW|INFO|UNKNOWN`.

### Task 2.2 — Verb tree (argparse parents pattern)

```
autobahn-defender [--format table|json|ndjson|markdown|html|sarif] [-o FILE]
                  [-q|-vv] [--color=auto|always|never] [--timeout S] [--yes] [--version|-V]

  scan    quick|home|system|external|processes [--path P …] [--fail-on SEV] [--timeout S]
  scan-file PATH [--yara-only|--clam-only]
  cve     [--offline] [--package NAME=VER …] [--fail-on CRITICAL|HIGH] [--track]
  patches check [--yes]        → lists fixes; `--yes` runs apply_batch (still pkexec)
  patches verify <pkg> [CVE]  → prints verified_fixed|still_vulnerable|inconclusive
  audit    full|vuln|network|hardening [--format markdown|html] [-o FILE]
  checks list|run <ID…> [--severity …]         # stable AD-XXX registry
  watch    start|stop|status|once [--interval S] [--json-lines]
  intel    poll|check|show [--since ISO] [--feed kev,ubuntu-osv,epss,poc]
  quarantine list|restore|delete [--id] [--yes]
  ignore   list|add <path|rule> |remove <id>   # scanner whitelist
  defs     update|status;  rules update|status
  news     list|zero-day [--since ISO]
  report   [--last N] [--since ISO] [--format html|md|json]   # history DB + last audits
  config   show|set <k> <v>;  doctor                # deps, perms, rule-compile, API reachability
  mcp                              # P7: stdio JSON-RPC server
```

Global: `-h/-V/--format/-o/-q/-v/--timeout/--color/--yes/--no-input`. Defaults per clig.dev: color auto (NO_COLOR + per-fd isatty honored), progress/logs ⇒ stderr, data ⇒ stdout, `BrokenPipeError → exit 141`, SIGINT → 130 (after KeyboardInterrupt cleanup).

**Exit-code rule (documented everywhere):** `0` clean, `1` findings (count>0 after severity filter), `2` operational failure, `64` usage. `--fail-on CRITICAL` sets exit 1 only if that severity present (trivy-style opt-in for CI). JSON `status` field is the AI ground truth; exit code is a coarse signal (help + `AUDIT-CONTRACT` section spell this out).

### Task 2.2b — Command-by-command mapping to engine (the "literally everything" table)

| GUI surface | CLI | Engine call |
|---|---|---|
| Scan tab (all buttons) | `scan …` | scanner_core.run_scan (callback for progress→stderr) |
| Process Scan | `scan processes` | scanner_core.scan_processes |
| Quarantine actions | `quarantine …` | QuarantineManager methods |
| CVE Scan / Track / Fix-All / Verify | `cve`, `track`, `patches check/verify`, `apply` | cve.scan_cves, patches.*, apply.apt_* |
| 4 Audit buttons | `audit network|hardening|vuln|full` | advisor.run_audit |
| Hardening apply buttons | `apply apparmor|fw-enable|fw-disable|sysctl|ssh|privacy` | apply.py/privacy.py |
| Network Watch (conns, blacklist, persistence) | `watch connections --check-blacklist`, `intel poll` | network_watch, persistence |
| Check for Patches/Fix All/Verify | `patches …` | patches.py + apply_batch |
| Security News refresh | `intel poll --rss-only` | rss_feeds.poll_all_feeds |
| Defs/YARA update | `defs update`, `rules update` | scanner._DefsUpdateWorker core / yara_updater |
| App self-update | `selfupdate check|download|install [--yes]` | updater.py core fns |
| History | `history scans|quarantine|audit [-n N]` | history_db getters |
| Alerts resolve/dismiss | `alerts list|resolve|dismiss` | engine alerts |
| (none — new) | `doctor` | P6 |

CLI dispatch: `main()` checks `len(sys.argv)>1` and `sys.argv[1]` is a known verb (and no `--gui`) → run CLI, else GUI. Only one launcher to document; AIs call `autobahn-defender scan ~/ --format json`.

### Task 2.3 — Human formats: `table` (ANSI, NO_COLOR honored, per-fd isatty), `markdown` (= advisor report), `html` (existing template), `json`, `ndjson`. jq examples shipped in `--help`:
```bash
autobahn-defender cve --format json | jq -r '.results[] | select(.severity=="CRITICAL") | .cve_id'
autobahn-defender watch once --format ndjson | jq -c 'select(.event=="threat")'
```

### Task 2.4 — Man page `autobahn-defender.1` (exit codes + format section — the agent contract), `docs/AGENTS.md` for AI users (schema_version, IDs, jq recipes, MCP), README CLI section, and the `AUDIT_CONTRACT.md` (§R1 digests distilled, ~1 page).

### Task 2.5 — `sudo`-free privileged path for CLI: all privileged verbs route through `run_privileged` (pkexec); non-interactive mode (`--no-input` or not a TTY) **refuses** pkexec prompts with exit 2 + "re-run in a GUI session or configure polkit rule X" — agents must never hang (clig.dev interactive rule).

---

## PHASE 3 — The Active Monitor: zero-days, exploited CVEs, runtime behavior

**Naming honesty (research-consensus):** call it the **Exploited-Vulnerability & Behavior Monitor**. A local, feed-driven tool detects *n-days* (disclosed-and-exploited) with high value, and *post-exploitation behavior* of true 0-days; it cannot see a true 0-day before disclosure — the UI/docs must not promise "zero-day protection" (copy updated accordingly, feature labeled "Zero-Day Radar" only in marketing sense with the caveat inline).

### 3.1 Intel collectors (`engine/intel/`) — all keyless, all verified live on 2026-08-30:

| Collector | Source (verified) | Cadence | Output |
|---|---|---|---|
| **KEV** (primary) | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (1,685 entries; mirror `github.com/cisagov/kev-data`) | daily + on GUI start | `vulns[cveID, dateAdded, dueDate, knownRansomwareCampaignUse, requiredAction…]` |
| **Ubuntu OSV export** | `https://security-metadata.canonical.com/osv/osv-all.tar.xz` (41.7MB, refreshed ~daily — verified) | daily | authoritative Ubuntu fixed-versions per release; *replaces fuzzy OSV heuristics for Ubuntu* |
| **Ubuntu notices JSON** | `https://ubuntu.com/security/notices.json` (paginated) + existing USN RSS | daily | USN ids per CVE |
| **Debian** (Mint/LMDE) | `https://security-tracker.debian.org/tracker/data/json` (87MB — cache 7 days) or dsa.rdf | weekly | DSA ids per CVE |
| **EPSS** | bulk CSV `https://epss.cyentia.com/epss_scores-current.csv.gz` (366k rows, ~2.5MB gz) | daily | epss+percentile per CVE |
| **PoC signals** | `https://github.com/nomi-sec/PoC-in-GitHub` (per-year JSON) + `https://github.com/trickest/cve` `hot_cves.csv` | weekly | public-PoC flag per CVE |
| **RSS** (existing `ai/rss_feeds.py`, 14+KEV) | keeps working; adds `zero_day_alerts.jsonl` | daily | candidate-flag layer |

Design: `engine/intel/` package — `kev.py`, `epss.py`, `ubuntu_osv.py`, `poc.py`, `store.py` (SQLite `~/.local/share/autobahn-defender/intel/intel.db`, WAL, 0600), `match.py`, `poll.py` (orchestrator; one `run_poll()` returns `{new_kev, new_usn, poc_hits, matches:[…]}`). All HTTP via `requests` with `Accept-Encoding: gzip`, timeouts, `Retry-After` respect (KEV/OSV are keyless; NVD **not** used as primary — 5 req/30s unauth and Apr-2026 triage-only; GitHub advisories only if PAT present in settings, else skipped).

### 3.2 Matching engine (`intel/match.py`)
Join chain, cheap and deterministic:
1. Installed pkg+version (dpkg-query; reuse `cve.get_installed_packages`).
2. **KEV hit** for installed product (match on CPE/product text + CVE id) → severity **CRITICAL** + `exploited=true` + `ransomware` flag when `knownRansomwareCampaignUse: Known`.
3. **USN/OSV hit** with installed < fixed → HIGH (was: MEDIUM).
4. **PoC exists** (PoC-in-GitHub weekly diff) ⇒ bump one level + tag `public_poc: true`.
5. **EPSS ≥ 0.5** ⇒ tag `epss_high` (score shown, never sole criterion).
Output: normalized `Match` records → `alerts.create_alert(...)` (lifecycle free) + `zero_day_alerts.jsonl` stays feed-only. Alert dedup key `cve_id|package|status`; re-alert only on state change (vuln→fix_available→verified / new KEV entry).

### 3.3 Remediation lifecycle ("fix it, disable it, verify, re-enable")
Extend the patch tracker into an alert→action machine (`engine/remediate.py`), **every transition review-first**:

```
DETECTED ──▶ user reviews ──▶ CONTAIN(optional) ──▶ UPDATE ──▶ VERIFY ──▶ RESTORE
  (open)                    (disable service/   (apt upgrade  (verify_patch_   (undo contain)
                             feature, snapshot    specific pkg)  applied; alert
                             pre-state)           via pkexec)    closes only on
                                                                 concrete proof)
```
- `engine/remediate.py::plan(alert_id) -> {steps:[{action, argv, rollback, risk}]}`; steps only from a whitelist: `stop_service|mask_service|firewall_block_ip|apt_install_version|sysctl_harden|remove_autostart` — each maps to existing `apply.py` actions (service whitelist, argv-only, action log) — *no new privilege surface*.
- CONTAIN executes only after confirm (GUI dialog / CLI `remediate apply <alert-id> --confirm-file <path>`; refuses bare `--yes`).
- VERIFY reuses `patches.verify_patch_applied` with the A-7 fix (`inconclusive` ≠ fixed).
- RESTORE reverts CONTAIN (unmask/start) once the CVE flips `applied` (with date + command in the alert history).
- Optional (opt-in, default **off**) unattended-upgrades integration: `remediate auto-security` writes `/etc/apt/apt.conf.d/02autobahn-unattended` enabling `Unattended-Upgrade::Automatic-Reboot false` + security origin only, after preview + confirm; single-file uninstall. This is the C-2 consistency point: sysctl/registry actions persist identically regardless of entry point.
- "Feature/ability to disable the application or feature until patch" = CONTAIN: `mask_service`, `ufw deny out <ip>` and `disable_kernel_module` (module blacklist write) added to `ALLOWED_SERVICES` pattern of apply.py — each with snapshot+rollback.

### 3.4 Runtime watchers — tiered, stability-first (user's #1 rule)

| Tier | Mechanism | Priv | Default | Watches | Implementation |
|---|---|---|---|---|---|
| A (default ON) | **inotify** (ctypes, no new deps) | user | ON when active-monitoring enabled | `~/Downloads`, `~/.config/autostart`, `~/.config/systemd/user`, `/etc/hosts`, `/etc/cron.d`, `/etc/ssh` | `engine/watch/inotify_watch.py` — `inotify_init1(IN_NONBLOCK)` + epoll in a worker thread (kernel ≥2.6.13 guaranteed; verified `inotify_init1` callable on this box). new/modified file → debounce 2s → enqueue **quarantine-safe** auto-scan (existing pipeline, size-capped, budgeted) |
| B (opt-in) | **auditd rules** | root service only | OFF (prompted with exact rules) | `/etc/ld.so.preload` write, exec from `/tmp|/dev/shm`, ssh key/cron/hosts writes, hidden-module insmod | ship `/etc/audit/rules.d/50-autobahn.rules` + `audisp-af_unix` plugin conf (`args = 0640 /var/run/audisp-events`) — app reads the socket in Python (jhb/auditd_tools pattern). **No kernel code; distro-supported** (research digest §2). |
| C (optional) | **clamonacc/fanotify on-access** | root daemons | OFF (Settings toggle) | on-access AV on Downloads/tmp/mounts | Ship `clamd.conf` snippet + systemd unit templates (OnAccessIncludePath ~/Downloads, OnAccessExcludeUname clamav, OnAccessPrevention **off** by default; notify-only first; access-permission blocking after a soak test). Verified: box has `CONFIG_FANOTIFY=y` + ACCESS_PERMISSIONS=y, clamav-daemon installed. GUI surfaces events by tailing `clamonacc` log → alerts. |
| D (never) | own eBPF/kmods | — | never | — | REJECTED: BTF/caps matrix across Mint/Ubuntu kernels + stability mandate (digest §5). Falco, *if user installed it*, gets an optional gRPC-unix-socket adapter (P6 stretch) — we consume, never ship, kernel tech. |

Polling tier (already exists, keep + tune): NetworkWatch QTimer → move into `engine/watch/daemon.py` so CLI `watch start` (systemd user unit `autobahn-watch.service`) and the GUI both drive the same loop; GUI subscribes via the alerts DB (already JSONL+atomic). `watch once` runs one pass and exits (scriptable).
Honest limit (docs + README): "detects exploited-known (n-day) and post-exploitation behavior; no local tool sees a pre-disclosure 0-day exploit itself" — with the TAG/P0 citations from the digest.

### 3.5 Scheduler & lifecycle
- GUI mode: existing QTimer (24h intel poll; N-minute network watch) unchanged.
- Headless/CI mode: `systemd` user units `autobahn-intel.timer` (daily) + `autobahn-watch.timer` (N min); system tier for clamonacc/auditd ships as separate opt-in units with `WantedBy=multi-user.target`, `After=network-online.target`, `Restart=on-failure`, plus `ConditionPathExists` guards; everything idempotent, disable = `systemctl --user disable autobahn-intel.timer` (no permanent system change without explicit enabling — matches user preference).
- Battery/AC + metered-network guard (via `upower -i` / NetworkManager connectivity) so the monitor doesn't thrash laptops — poller defers unless charging or unmetered, configurable off.

---

## PHASE 3′ — Efficiency upgrades (existing code, concrete wins)

1. **network_watch download**: replace `content += chunk` (O(n²)) with `io.BytesIO`/list-join (C-1); precompile `ip_network` list + `set` for exact IPs at load (C-1b). 
2. **sysctl_harden**: 14 pkexec calls → 2 (write conf via one pkexec `cp`, one `pkexec sysctl --system`) (C-2); privacy apply gets same persist semantics.
3. **Scanner cap fix** (A-9) + `_estimate_file_count` unified (C-13).
4. **OSV cache**: `intel/state.py` 24h per-`(pkg,ver,ecosystem)` cache dir so `cve` re-runs cost 0 network when nothing changed (osv docs: no limits, but courtesy + offline flag need it); ETag/If-Modified-Since on KEV + Ubuntu tar.xz (both return `Last-Modified` — verified).
5. **Version compare**: `apt_pkg` via `/usr/bin/python3` (verified 2.8.3) with pure-Python fallback → removes the A-10 class forever; keep Kudu tests as regression guards.
6. **C-6 UI fill/sort race**, **C-4 dead `is_affected` + first-fixed-event bug**, **C-5 zero-day keyword years** (KEV cross-ref instead), **D-1 three hosts-checkers → one** `engine/hosts_check.py`, **D-3 dead assignment**, D-10 UA version — all in Phase 0/1 PRs.
7. **Deb size/build**: dedupe `python3-yara` (already in `Depends`) with in-process yara (already used) — drop the `yara` CLI binary from `Depends` to `Recommends`; strip `__pycache__` in build script (C-11a). AppImage build script gets the same strip.

---

## PHASE 4 — MCP + AI-agent surface (the "AIs can invoke it" requirement)

### Task 4.1 — `cli/mcp_server.py` (stdlib-only JSON-RPC 2.0 over stdio, newline-delimited; ~250 lines)
- Tools mirror verbs 1:1, deterministic order in `tools/list`: `autobahn.scan`, `autobahn.cve`, `autobahn.audit`, `autobahn.checks.list`, `autobahn.checks.run`, `autobahn.watch.status`, `autobahn.watch.once`, `autobahn.intel.poll`, `autobahn.intel.check`, `autobahn.alerts.list|resolve|dismiss`, `autobahn.quarantine.list|restore|delete`, `autobahn.remediate.plan|apply(confirm_token)`, `autobahn.report`, `autobahn.doctor`.
- stdout carries **only** JSON-RPC; everything else → stderr (spec MUST).
- Destructive ops (`quarantine delete`, `remediate apply`, `apply.*`) require an 8-char `confirm_token` the `plan` call returned — an agent must read-before-write; matches user's review-first philosophy without human confirmation for read-only flows.
- Registering in Claude/Hermes = one config stanza; verify with a scripted MCP client in `tests/test_mcp.py` (initialize → tools/list ≥ N → tools/call check.run).

### Task 4.2 — `docs/AGENTS.md` (agent-facing contract):
- exit-code table, envelope schema, `schema_version` promise (additive-only majors),
- every verb's jq recipe,
- guidance: "don't parse human tables; use `--format json`; treat exit 2 as rerun-with-fix",
- `--timeout` defaults per verb (scan 1800, cve 60, audit 120),
- sandbox-safe examples (scan `tests/fixtures/`, never `/` in CI).

---

## PHASE 5 — Packaging, daemon units, docs

1. New files tree (`build_deb_v2.0` updated in place, version untouched):
   - `usr/share/autobahn-defender/cli/` (cli package), `engine/intel/`, `engine/watch/`
   - `usr/bin/autobahn-defender` dispatch (GUI iff no recognized verb)
   - `usr/share/man/man1/autobahn-defender.1.gz`
   - systemd **user** units (`autobahn-intel.{service,timer}`, `autobahn-watch.{service,timer}` in `usr/lib/systemd/user/`) — **postinst does NOT enable**; prints how-to. System tier (clamonacc/auditd) only via explicit `--system-services on` toggle that runs a guided pkexec script with preview (user approval).
   - `control`: add `Recommends: auditd` (optional), keep everything else; Suggests: falco (optional adapter), clamav-daemon (on-access tier).
2. `polkit` action file for `run_privileged` so repeated actions prompt fewer times (policy `auth_admin_keep` for read-only collectors, `auth_admin` for mutations) — new file `usr/share/polkit-1/actions/com.digitalautobahn.autobahn.policy`.
3. Headless/server mode: same engine, `--no-gui` implied; `watch` runs fine without Qt (engine has zero Qt imports after P1.1 — assert in CI with `pytest --qt-none`).

---

## PHASE 6 — Tests, CI, doctor (the recurrence killer)

1. `tests/` (pytest, fixtures over network by default, live-marked extra):
   - `test_versions.py` (Kudu cases + `apt_pkg` oracle: compare 500 real dpkg versions vs pure-python impl in CI)
   - `test_cve_filter.py`, `test_cve_normalize.py` (OSV fixtures incl. UBUNTU-CVE aliases, last_affected, multi-range)
   - `test_patches.py` (apt-s fixture → state machine; **inconclusive-not-fixed** regression for A-7)
   - `test_checks_registry.py` (smoke all checks, degraded-flag assertions)
   - `test_advisor_schema.py` (Finding schema round-trip; scores; markdown sections)
   - `test_intel_match.py` (KEV/USN/EPSS fixture joins; dedupe; severity matrix)
   - `test_cli_contract.py`: subprocess runs of `scan fixtures/clean` (exit 0), `scan fixtures/infected` (exit 1, EICAR), `scan /nonexistent` (exit 2), `--format json | jq -e '.schema_version'` (fixtures via tempfile, no sudo)
   - `test_mcp.py` (stdio RPC round-trip)
2. `autobahn-defender doctor`: deps present, rules compile, disk perms, API reachability (KEV/OSV/EPSS 1-byte HEADs), auditd presence, fanotify kernel support, blacklist age, service status — one JSON blob; also the CI entry point.
3. CI (local git hooks + optional Codeberg Actions later, read-only): py_compile all, AST undefined-name check (the audit's method, automated), pytest, `--format json | jq` contract tests, flake8-rules ("no bare except-pass", "no subprocess f-strings").

---

## Milestones / acceptance

| M | Content | Acceptance |
|---|---------|-----------|
| M0 (≈3d) | Phase 0 all | pytest green; audit buttons yield findings; verify-patch can't lie; 100k cap gone |
| M1 (≈2d) | engine/paths+runner, version unify | engine imports with **no PyQt6**; every GUI verb has an engine call |
| M2 (≈3d) | CLI verbs table complete | every GUI button has an argv equivalent; contract tests pass in VM |
| M3 (≈3d) | Intel collectors + matching + alerts | `intel check` on this box: KEV+USN+EPSS join produces correct alert for a vulnerable installed pkg (fixture-verifiable); zero-day keywords cleanup landed |
| M4 (≈4d) | Watch tiers A/B + remediation lifecycle | inotify Downloads → auto-scan e2e in VM; contain→update→verify→restore e2e on a dummy CVE; **no auto-action without confirm** |
| M5 (≈2d) | MCP + AGENTS.md + doctor | MCP handshake from a real agent session; doctor green |
| M6 (≈2d) | Packaging | deb builds clean (no pycache/no threat_monitor), VM install + CLI + GUI + services pass |

## Risks / tradeoffs
- **argparse boilerplate** — accepted (zero-dep constraint; parent-parser pattern).
- **auditd tier needs root service** — mitigated: opt-in, distro package, GUI stays unprivileged; document `auditctl` rules on screen before apply.
- **fanotify blocking mode** can lock up if misconfigured (ClamAV docs) — notify-only default; prevention behind double-confirm; never `OnAccessIncludePath /`.
- **Feed churn** (KEV JSON ok today; kev-data Git mirror as fallback; osv-all.tar.xz validated by catalogVersion) — collectors are pluggable ` collectors[]` with per-source staleness alerts, offline caches ≥7d, so a dead feed degrades visibly (C-lesson applied).
- **Scope control** — no eBPF, no Vulners, no NVD-primary, no cleaner/breach-monitor (unchanged from 3.0 plan out-of-scope list).

## Open questions for Donavin (answers don't block Phase 0/1)
1. CLI binary name: single `autobahn-defender` dispatch (recommended) vs separate `autobahn-cli`?
2. Remediation auto-pilot (security-updates-only unattended upgrades) — offer as opt-in?
3. clamonacc/auditd tiers default state in the deb (recommend: both OFF, one-click enable)?
4. SARIF output for GitHub code-scanning wanted? (free, small)
5. Any appetite to ship the KEV/EPSS poller results to your Security News tab as a new sub-tab (zero-day radar) vs CLI-only first?