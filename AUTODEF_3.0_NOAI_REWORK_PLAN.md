# Autobahn Defender 3.0 — "No-AI" Active Security Rework — Full Technical Plan

> **Date:** 2026-08-23 · **Target version:** 3.0.0 (replaces 2.1.0)
> **Repo (READ-ONLY):** `https://codeberg.org/donavinschlosser/autobahn-defender`
> **Working copy:** `/home/kristopher/Projects/Autobahn Defender/`
> **Kudu reference clone (MIT, AdventDevInc):** `/tmp/kudu-research` @ `ec86b4c` (v2.3.0)

**Goal:** Remove the local-AI (Ollama/LFM2.5) brain from Autobahn Defender v2.x and replace it with a deterministic, local, always-on security engine that (1) keeps all the scan-engine work (ClamAV/YARA + Kudu ports), (2) actively tracks CVEs affecting *installed* packages, (3) tells the user when a fix is available and verifies when the update actually fixed it, (4) can *take action* on AppArmor, firewall, sysctl, and service hardening through sudo-prompt-gated apply buttons, (5) ports more Kudu security/privacy features, and (6) runs **without any AI model, Ollama sidecar, GGUF file, or cloud LLM** — 100% deterministic.

**Architecture:** The v2 "AI brain" (model + prompt + tool-calling loop) is replaced by a **rule engine** (`engine/` package): every existing AI tool becomes a plain local *check*; the worker thread's job becomes a *runbook* that executes checks in order, scores findings deterministically, and renders the same `[SEVERITY] … / Why / How to fix` reports the AI produced. CVE intelligence comes from OSV.dev batch queries (already working in v2.1), distro security-advisory RSS, and an offline **patch-status tracker** that resolves alerts when the installed version reaches `fixedIn`. The AI tab is rebuilt from scratch as the **Security Center** tab (fixing the broken UI along the way).

**Tech stack:** Python 3.10+ / PyQt6 / `yara-python` / ClamAV · new deps: `ipaddress` (stdlib), `packaging` or hand-rolled Debian version compare (port Kudu's) · pkexec for privileged actions · no new heavy deps.

**Attribution (MIT):** All code ported from AdventDevInc/kudu keeps a header comment `# Ported from AdventDev/kudu (MIT) — https://github.com/AdventDevInc/kudu`; add an `ATTRIBUTION.md` and README section crediting AdventDev.

---

## 0. Inventory — what exists today vs what we're building

### 0.1 Autobahn Defender current state (verified 2026-08-23)

| Component | File(s) | Status |
|---|---|---|
| Scan engine: ClamAV chunks + YARA compile | `scanner.py` (2635 l.) | **KEEP AS-IS** (user directive) |
| Detection ledger, content-hash binding, SKIP_DIRS, quick-scan budgets | `scanner.py` (`get_detection_ledger`, SKIP_DIRS @1663, 1736) | **KEEP** (Kudu ports already landed) |
| Quarantine + 2-pass overwrite | `quarantine.py` | KEEP — audit overwrite completeness (Task P0-2) |
| App self-update | `updater.py` | KEEP — fix version drift (Task P0-3) |
| RSS feed poller (NO AI) + Security News tab | `ai/rss_feeds.py`, `security_news_tab.py`, `ai/feed_poller` | **KEEP** — already non-AI |
| Intel JSONL store | `ai/intel_db.py` | KEEP (mode 0700) |
| Alerts JSONL | `ai/alerts.py` | **REFACTOR** → `engine/alerts.py` (no AI assumptions) |
| AI tools (38 functions) | `ai/tools.py` (3487 lines) | **PORT** every `_t_*` → deterministic `engine/checks.py` |
| AI worker (Ollama, streaming, prompts) | `ai/worker.py`, `ai/ollama_manager.py` | **DELETE** (replaced by `engine/advisor.py`) |
| Background threat monitor (requires AI ON) | `ai/threat_monitor.py` | **REWRITE** → `engine/network_watch.py` (AI-free, no 8GB gate) |
| AI tab UI (broken layout) | `ai_tab.py` | **REBUILD** → `security_tab.py` |
| Kernel/firewall/hardening probes | `kernel_checker.py`, `firewall.py`, `hardening.py` | KEEP; extend with apply actions |
| Intel knowledge base (static text) | `ai/knowledge_base.py` | **REUSE** as remediation map for the advisor |

### 0.2 Kudu v2.3.0 — steal list (fresh inspection of `/tmp/kudu-research`)

| Kudu file | What we take | Effort |
|---|---|---|
| `src/main/services/cve-filter.ts` (351 l.) | **THE** crown jewel: Debian/Ubuntu version parser (epoch/upstream/revision), `+dfsg`/`+really` handling, `isVersionAtLeast()`, MISATTRIBUTED_PACKAGES regex list (php-pear, bash-completion, git-doc, python3-*, lib*-perl, ruby-*, node-*, linux-headers, r-cran, lua-*, elpa, libghc, golang-*-dev, texlive), SUPPRESSED_PAIRS (glibc 2019-1010022-25, 2016-20013, 2010-4756), ancient-CVE (>7y, no fix) rule, cross-version-branch detection, DEBIAN-CVE/USN dedupe, -dev/-dbg/-doc collapse. Philosophy: *prefer silence over a false alert.* | **Direct Python port** |
| `src/main/platform/linux/privacy.ts` | Privacy Shield: GNOME/KDE gsettings (usage stats, recent files, location, crash reporting, connectivity check, Baloo) + **SYSCTL hardening set** (aslr=2, kptr_restrict=2, dmesg_restrict=1, ptrace_scope=1, unprivileged_bpf=1, syncookies, icmp_echo_ignore_broadcasts, rp_filter, accept_redirects=0, source_route=0, log_martians, ipv6 redirects, suid_dumpable=0) | High value, direct port |
| `src/main/ipc/startup-manager.ipc.ts` + `src/main/platform/linux/startup.ts` | Systemd **user service** list/enable/disable (validated paths), XDG autostart list/toggle, @reboot cron parse | Port the *list + toggle* surface |
| `src/main/services/threat-blacklist-store.ts` | Blacklist JSON with **size caps + schema validation** (500k entries/array, 50 MB, atomic tmp+rename) | Port validation caps into our downloader |
| `src/main/platform/linux/security.ts` | AppArmor/SELinux status, UFW/nft/iptables probing, fail2ban jails, SSH hardening collector | Reuse pattern; we already have probes — port the **SSH hardening + f2b** extras |
| `src/main/rules/loader.ts` + `validate.ts` | JSON rules infra + validation script (schema, ${VAR} allowlist) | Optional; adopt only the validation concept for our own `checks.json` |
| `src/main/services/software-updater.ts` | distro package update detection | **We already have** `_t_update_status` — port remaining logic |
| `breach-monitor.ipc.ts` | Email breach watch | **SKIP** (cloud account; privacy conflict with Autobahn ethos) — note as out-of-scope |

### 0.3 What we are NOT touching (stability-first)

- `scanner.py` scan pipeline (ClamAV chunked + YARA), whitelist, ledger, quick-scan budgets
- `quarantine.py` behavior (only the overwrite audit in P0)
- `updater.py` app-update mechanics (only version constants)
- `settings.py`, `kernel_checker.py`, `firewall.py`, `hardening.py` core probes
- The Codeberg repo itself (still READ-ONLY; local build only)

---

## 1. Target module layout

```
~/Projects/Autobahn Defender/
  engine/                      ← NEW (replaces ai/ for all logic)
    __init__.py               version consts, data-dir helpers
    checks.py                 ~38 deterministic checks (ported from ai/tools.py)
    advisor.py                deterministic runbook: order, scoring, report render
    cve.py                    OSV batch query + Kudu cve-filter port + severity parse
    patches.py                patch-availability + "did the update fix it" tracker
    alerts.py                 adapted from ai/alerts.py (no AI wording)
    network_watch.py          threat monitor rewrite (ss parser + CIDR + blacklist)
    apply.py                  pkexec-gated hardening/firewall/apparmor/service actions
    privacy.py                Kudu privacy-shield port (gsettings + sysctl checks/apply)
    startup.py                Kudu startup-manager port (systemd user + autostart + cron)
    persistence.py            scan_persistence + hosts-integrity (standalone, runnable)
    knowledge_map.py          static remediation map (from ai/knowledge_base.py)
  security_tab.py            ← NEW tab (replaces ai_tab.py)
  ai/                        ← KEPT ONLY as archive; main.py stops importing it
  rules/  (unchanged)
  tests/                     NEW pytest suite
  build_deb_v3.0/            NEW packaging (NO ollama, NO GGUF — package shrinks ~4GB)
  ATTRIBUTION.md             NEW (AdventDev Kudu MIT credit)
```

`main.py` wiring changes: `_create_ai_tab()` → `_create_security_tab()`; remove `_start_ollama*`, `_OllamaBridge`; add `SecurityEngine` singleton that the tab and the tray/monitor both talk to.

---

## 2. Implementation tasks (bite-sized, TDD where practical)

> **Implementer note:** run every `python3 -m py_compile` gate after each task; run `pytest tests/ -x` after each task that adds a test. Commit after every task (local repo only).

### PHASE 0 — Paving (small, safe)

**Task 0.1 — Add test harness + engine package skeleton**
- Create: `engine/__init__.py` (exports `VERSION = "3.0.0"`, `DATA_DIR = ~/.local/share/autobahn-defender`), `tests/__init__.py`, `tests/conftest.py` (tmp paths).
- Verify: `python3 -m pytest tests/ -x` → 0 collected, exit 0 (pytest present; add `pytest` to dev reqs only, not runtime).

**Task 0.2 — Audit quarantine 2-pass overwrite**
- Read `quarantine.py` (482 l). Confirm the wipe loop writes random pass then zero pass to the *full file size* before unlink; if only 1 pass or no re-read, port Kudu `file-utils.ts` 2-pass (see `/tmp/kudu-research/src/main/services/file-utils.ts`). Add test `tests/test_quarantine_wipe.py` that creates a temp file with known content, wipes, asserts bytes are zeroed and `os.stat().st_size == 0` after unlink.
- Verify: pytest passes; no functional change to quarantine flow.

**Task 0.3 — Version drift fix**
- `updater.py:39` `CURRENT_VERSION = "2.0.0"` → `"3.0.0"`; build `build_deb_v3.0/.../DEBIAN/control` `Version: 3.0.0`.
- Verify: `grep CURRENT_VERSION updater.py` shows 3.0.0; `dpkg-deb --info` on new build shows 3.0.0 (build at end of phase 5).

---

### PHASE 1 — Deterministic core: `engine/cve.py` + `engine/patch.py`

**Task 1.1 — Port Kudu Debian-version compare (pure Python, tested)**
- File: `engine/versions.py` (new). Port `parseDebianVersion`, `normaliseUpstream` (`+really`, `+dfsg`, `+ds`, `~beta`), `compareNumericVersion`, `compareRevision`, `isVersionAtLeast`.
- Tests `tests/test_versions.py` (port the cases from Kudu's `cve-filter` + edge cases):
  - `("2:1.2.3-4", "1:9.9")` → epoch wins
  - `("1.2.3-0ubuntu8.2", "1.2.3-0ubuntu8.1")` → True (revision compare)
  - `("8:7.0.2+dfsg-2", "8:7.0.3")` → False; `("8:7.0.3+really7.0.2", …)` → +really semantics
  - `("1.0~beta1", "1.0")` → False
- Verify: `pytest tests/test_versions.py -v` → all pass.

**Task 1.2 — Port `isLikelyFalsePositive` + `deduplicateCves`**
- File: `engine/cve_filter.py` (new) — regex list copied verbatim (MIT), `SUPPRESSED_PAIRS`, `isCrossVersionBranch`, `normalizeCveId`, `getBasePackageName`, `deduplicateCves`.
- Tests `tests/test_cve_filter.py` — use the Kudu test expectations: `bash-completion`+CVE → FP; `php-pear` → FP; `linux-headers-6.8` → FP; installed>=fixedIn → FP; 2019 glibc pairs suppressed; DEBIAN-CVE dupes removed; `openssl` vs `libssl3` NOT suppressed; `foo-dev` dropped when `foo` present.

**Task 1.3 — OSV batch query (production-grade)**
- File: `engine/cve.py` — move `_t_cve_check` logic out of `ai/tools.py` into `query_osv(packages, ecosystem)` with: auto-detect ecosystem from `/etc/os-release` (Ubuntu 22.04/24.04/24.10, Debian 11/12, Mint 22/21.x), 1000/batch, 3 retries/backoff, per-batch `requests.Session`, result normalization `{cve_id, package, installed_version, fixedIn, summary, severity}`.
- Apply `isLikelyFalsePositive` + `deduplicateCves` to the merged result → **`vulnerabilities: cleaned[]`**.
- Test with live call (mark `@pytest.mark.live`): query `openssl 3.0.13` against `Ubuntu:24.04` → expect non-empty `vulns`; and a patched one (`openssl 3.0.13-0ubuntu3.4`) → expect FP-filtered empty.
- Verify: script prints count + top 5 with/without filter.

**Task 1.4 — Patch tracker (`engine/patches.py`)**
- Data (per package+version): `alerts.jsonl`-adjacent `patches.jsonl` with `{pkg, installed, fixed_in, cve_id, status: open|fix_available|applied|patched_external, first_seen, last_seen, resolved_at}`.
- `check_for_fixes()`: run `apt-get -s upgrade` (NO `apt upgrade` — simulate only), parse `Inst pkg [old] -> (new)` lines; for each open alert, if `new_version >= fixed_in` → status `fix_available` (emit user alert); `apply()` runs `sudo`/`pkexec apt-get install -y <pkg>` after user confirms; after apply, re-run OSV for that pkg and flip status `applied`/`patched_external` with the *verified version* — **this is the "did the update fix it" loop**.
- Also parse `apt-get changelog <pkg>` (when network available) to attach the advisory/URGENCY line to the alert.
- Tests: fake apt output fixtures; assert state transitions.

---

### PHASE 2 — Checks engine: `engine/checks.py` (port of `ai/tools.py`)

**Task 2.1 — Port the 38 tools → `CHECK_REGISTRY`**
- One file `engine/checks.py`; each `_t_*` becomes `check_*(args) -> dict` with identical output JSON shapes (UI/report compatibility!). Registry `CHECKS: dict[str, Check]` where `Check = (name, title, group, run(args))`.
- **Do NOT port:** `_t_web_search`, `_t_fetch_url` (replaced by local parsing), `_t_rss_poll` (stays in `rss_feeds.py`), `_t_write_intel_db`/`_t_read_intel_db` (becomes `engine/state.py`), `_t_knowledge_lookup` (becomes static map import).
- Tests `tests/test_checks.py`: each check runs in <5s on this machine; returns `{status: ok|error}` and stable schema keys.
- Verification: `python -c "from engine.checks import CHECKS; print(len(CHECKS), sorted(CHECKS))"` → ~34 checks listed.

**Task 2.2 — Deterministic advisor (`engine/advisor.py`)**
- `run_audit(tasks: list[str]) -> AuditResult`: executes the checks a task names, aggregates findings.
- Scoring (identical to the v2 prompt rules so users see the same numbers):
  `score = 100 − 20·critical − 10·high − 5·medium − 2·low; never < 0; any permission-error finding caps at ≤ 89`.
- Finding object: `{severity, title, what, why, fix (command), source_check}`.
- `render_markdown()` reproduces the old `[SEVERITY] Title / What this means / Why it matters / How to fix it` layout. `render_html()` for the report template.
- `TASK_DEFS` maps the 6 UI buttons → ordered check lists (port the prompts' tool order from `ai_tab.py` `TASKS`).
- Tests: fixture with fake findings → assert score math; assert markdown sections order.

**Task 2.3 — `engine/state.py` + `engine/alerts.py`**
- Move intel JSONL read/write (atomic, 0700) from `ai/intel_db.py` into `engine/state.py`; `engine/alerts.py` re-export of `ai/alerts.py` with docstring updates (remove "AI generates…" phrasing).
- `engine/reader.py`: one entry point to build "system state digest" (packages, kernel, firewall status) used by both advisor and cve scans.

---

### PHASE 3 — Active security: apply + network watch + privacy

**Task 3.1 — `engine/apply.py` (pkexec wrapper)**
- Generic `run_privileged(argv, detail)` using `pkexec` (falls back to `sudo` if absent) — no shell interpolation (list argv only), 60s timeout, sanitized error surfacing.
- `ACTIONS` registry — each action is a **review-first** dialog (description + exact command displayed; user clicks Apply; password prompt): 
  - `apparmor_enforce <profile>` (list from `aa-status --json`; default: current kernel profiles)
  - `ufw_enable` (with default deny list if user picks), `ufw_allow <port>`
  - `sysctl_harden` (the Kudu 13-item set via `sysctl -w` *and* writes `/etc/sysctl.d/99-autobahn.conf` with backup + `sysctl --system` reload)
  - `ssh_harden` (backup `sshd_config`, apply Perm itRootLogin no / password auth off, validate with `sshd -t`, rollback on failure)
  - `service_start/stop <svc>` (systemctl, only whitelisted services: fail2ban, ufw, snapd is NOT)
  - `apt_upgrade_security` (dry-run preview → user confirm → `pkexec apt-get upgrade`).
- **Safety rule (user's stated preference):** NO permanent change without explicit confirmation; every apply writes an `actions.log` (append-only, 0600); rollback = reverse entry.
- Tests: `tests/test_apply.py` (mocked pkexec), verification that registry contains no shell string concatenation (injection-safe by construction — argv lists).

**Task 3.2 — `engine/network_watch.py` (AI-free threat monitor)**
- Port from Kudu `threat-monitor.ts` + `network.ts`:
  - `ss -tunap state established` parse → `{remote_ip, remote_port, pid, proc}`
  - Blacklist downloader: versioned JSON, **validation caps from Kudu** (500k entries/array, 50MB, atomic tmp+rename); sources: abuse.ch blocklist.ipset / `https://raw.githubusercontent.com/firehol/blocklist-ipsets` (choose `firehol_level1`), domain list from someonewhocares.org + Spamhaus DROP via ipdeny? — configurable list in settings, **disabled by default** (privacy: no cloud sends; downloads happen only when enabled).
  - `cidr_match(ip, cidrs)` with IPv4/IPv6 (port `ip_address` + `ip_network`), dedup TTL 60s, severity high if pid==0 (kernel) else medium.
- Runs on a QTimer every 15 min (configurable) with **no RAM gate**; results → dashboard; matched connections → alert with pid/process name.
- Tests: synthetic `ss` output fixture; CIDR tests (10.0.0.5 ∈ 10.0.0.0/8 etc).

**Task 3.3 — `engine/privacy.py` (Kudu privacy-shield port)**
- `PRIVACY_CHECKS`: gsettings get/set (org.gnome.desktop.privacy usage stats/recent files, org.gnome.system.location, com.ubuntu.update-notifier show-apport-crashes, org.gnome.system connectivity-check) + sysctl runtime values + `/etc/sysctl.d/99-autobahn.conf` presence.
- `PRIVACY_ACTIONS`: apply via gsettings (no admin) or pkexec (sysctl). All optional toggles in Settings.
- Tests: read-only checks run on this box (assert they don't crash); apply tests use `--dry-run` flag.

**Task 3.4 — `engine/startup.py` (Kudu startup-manager port)**
- List: XDG autostart `.desktop` (+ `.disabled`), `systemctl --user list-unit-files --type=service`, `crontab -l` entries.
- Security scan: reuse v2 `_t_scan_persistence` logic (curl|wget→bash, /tmp ExecStart, base64 exec) — **fold into advisor's `persistence_audit` task** and into the scheduled background job.
- Actions (review-first): disable autostart entry (rename `.disabled`), disable user service (`systemctl --user disable --now`), comment crontab line.

---

### PHASE 4 — UI: `security_tab.py` (replaces broken `ai_tab.py`)

**Task 4.1 — Tab skeleton + header**
- `QTabWidget`-child (kept in `ui_tabs.py` tab order — verify how `main.py` adds it; likely `tabs.addTab(SecurityTab(), "Security")`).
- Header: status pill (Monitoring ON/OFF, last check), **no Ollama/engine toggle**; "Enable Active Monitoring" toggle (replaces "Auto Monitor", no RAM gate).
- Restore `setUpdatesEnabled(False)` build pattern (the v2 UI bug).

**Task 4.2 — Dashboard**
- Threat Dashboard → **Alert Center**: table of `engine/alerts.py` entries (severity badge, title, package, patch status, timestamp) + filters (All/Active/Resolved) + buttons: "Mark Resolved", "Copy fix command", "Open Security News", "Refresh".
- "Patch Status" sub-panel: list `patches.jsonl` rows with **Verified Fixed** checkmark when `installed >= fixed_in` (ties to `engine/patches.py`).

**Task 4.3 — CVE report view**
- On-demand "Scan for Vulnerabilities" button → runs `engine/cve.py` scan in a QThread (progress bar), renders table: CVE | Package | Installed | Fixed in | Severity | Status (New/Updated/Fixed). Click row → expand panel with summary + "Show fix command" + "Track" (writes `patches.jsonl`).
- Live status line: "N packages · M open CVEs · K patches available · J verified fixed".

**Task 4.4 — Hardening / Apply panel**
- Tabs: **AppArmor** (profiles: enforcing/complain + Enforce button), **Firewall** (ufw state, rules list, Enable + Add-port), **Kernel** (sysctl table, "Apply 13 hardening defaults"), **Privacy** (Kudu list with checkboxes → Apply), **Startup** (list + toggles), **Services** (fail2ban etc. start/stop).
- Every action routes through `engine/apply.py` review dialog.

**Task 4.5 — Advisor output view**
- "Run Audit" buttons (the 6 task IDs) → `engine/advisor.run_audit()` in a QThread; rendered in the SAME `[SEVERITY] Title / What / Why / Fix` format; "Copy report" + "Save report" (HTML via existing `templates/report_template.html`).
- Chat window **removed** (no model to chat with) — replaced by "Ask a question about this system" → opens search of the knowledge base + local docs (deterministic).

**Task 4.6 — Wire main.py**
- Remove: `_start_ollama`, `_stop_ollama`, `_OllamaBridge`, `ollama_manager` imports, ai-tab enable toggle plumbing.
- Add: `self.security_engine = SecurityEngine()` (owns network_watch timer, patch checker timer, feed poller already exists); close handlers cancel timers.
- `main.py` `_create_security_tab()` returns `security_tab.SecurityTab(engine=...)`.

---

### PHASE 5 — YARA/scanner extras + packaging

**Task 5.1 — YARA compile hardening (Kudu `yara-engine.ts` port, final touches)**
- In `scanner.py`: per-file validation fallback — on bulk compile exception, compile each rules file individually and keep only the valid ones (log warnings); (platform-tag filtering: our rules are already split linux/mac/windows — skip macos + windows rules at compile time when `platform.system() !=`).
- Compile-progress UI: emit `signature_compile_progress(step, total)` into the scan status label (0-100 before scanning starts).
- Tests: temp dir with 1 broken `.yar` + 1 valid → compile succeeds with warning.

**Task 5.2 — Persistence + hosts integrity into scheduled scans**
- `scanner.py` gains a post-scan hook: after YARA/Clam finish, run `engine/persistence.run()` and `engine/hosts.run()` (Kudu `scanLinuxPersistence` + `checkHostsFile`); findings appended to the scan result with `source=persistence|hosts` tags (Kudu tagging model).
- Settings checkbox: "Include persistence & hosts checks" default ON.

**Task 5.3 — Packaging `build_deb_v3.0`**
- New dir `build_deb_v3.0/autobahn-defender_3.0.0_amd64/` (copy from v2.1 layout):
  - REMOVE: `usr/share/autobahn-defender/bin/ollama*`, `models/*.gguf`, `lib/ollama/` → package size drops ~4 GB.
  - ADD: `engine/` + `security_tab.py`; keep `ai/` out of the deb (or keep only `rss_feeds.py` + `feed_poller.py` — actually move those into `engine/`; the deb ships only `engine/`).
  - `DEBIAN/control`: Version 3.0.0; Depends: python3-yara, clamav, clamav-freshclam, python3-bs4, python3-feedparser, python3-requests, policykit-1; Suggests: fail2ban, ufw.
  - `postinst`: on upgrade, `rm -rf /usr/share/autobahn-defender/ai` leftovers; never touch user data.
  - `usr/bin/autobahn-defender` launcher unchanged.
- Rebuild + install in a **clean VM test** first (user preference: test before permanent).

---

## 3. Verification plan

1. Unit: `pytest tests/ -x -v` → all green (target ≥ 40 tests).
2. Smoke: `python3 -m autobahn_defender` (source run) — Security tab loads; each of the 6 audit buttons produces a report in < 30s on this machine.
3. CVE end-to-end: run "Vulnerability Scan" → expect N OSV results, zero false positives from the filter (compare unfiltered vs filtered counts in log).
4. Patch flow: pick one open CVE → "Track" → `pkexec apt-get upgrade` in a VM → rerun → status flips to **Verified fixed**.
5. Active Security: in VM, AppArmor enforce (a harmless profile), UFW enable with allow-port, sysctl dry-run — confirm review dialog + pkexec prompt + undo works.
6. No-AI proof: `ps aux | grep -E 'ollama|llama'` empty after 10 min of use; `~/.local/share/autobahn-defender/ollama/` unused; UI has no "AI" text.
7. Update channel: `updater.py` reports 3.0.0.
8. Memory: app runs 24h with monitoring ON — RSS stable (±50 MB), no thread leak (log count of QThreads in a status debug).

---

## 4. Risks & tradeoffs

| Risk | Mitigation |
|---|---|
| OSV.dev rate limits on 2500-pkg scans | batch 1000 + backoff (already), cache per (pkg,version,ecosystem) 24h in `engine/state.py` |
| Distro feed death (NVD retired April 2026) | multi-source: ubuntu.com, debian dsa, cvefeed.io, linuxsecurity, RHSA; poller already tolerant (silent skip + log) |
| `apt-get -s` needs no root — but `apt-get update` does | patch scan does `pkexec apt-get update` only when user clicks "Check patches" (review-first), or reads `/var/lib/apt/lists` state if fresh |
| Version-compare edge cases (epoch, +really) | full port of Kudu tested suite; we own the tests |
| pkexec prompts on Wayland vs X11 | use `pkexec` (policy-utils-1); fallback `sudo -A` if pkexec missing; both argv-based (no shell) |
| Removed chat = less "AI feel" | the Security Center IS the product; document that the AI was a prototype — v3 is deterministic & auditable |
| Keeping `ai/` dir around | source-only; excluded from .deb; main.py never imports it (guarantee via grep in CI/test) |
| Kudu MIT license | ATTRIBUTION.md + per-file header comments |

## 5. Files changed (summary)

**New:** `engine/` (10 modules), `security_tab.py`, `tests/` (≈8 files), `ATTRIBUTION.md`, `build_deb_v3.0/`
**Modified:** `main.py` (wiring), `ui_tabs.py` (tab registration, small), `scanner.py` (YARA fallback + hooks), `updater.py` (version), `requirements.txt`, `DEBIAN/control`, `postinst`
**Deleted from package:** `ai/` (whole), `bin/ollama`, `models/`, `lib/ollama`
**Kept:** scanner engine, quarantine+ledger, settings, kernel/firewall/hardening probes, security news tab, feed poller, update checker.

## 6. Out of scope (explicit)

- Kudu's **cleaner** half (disk cleaner, registry, browser cleaner, AppImage — Autobahn is a *security* app)
- Kudu **breach monitor** (cloud email = privacy conflict)
- Anything Windows-specific (firewall-audit.ipc.ts is PowerShell; skip)
- The old `ai_tab.py` UI: we rebuild; no repair of the broken layout.
- Re-enabling any LLM in 3.0 (an optional future 3.1 can re-add via a pluggable "advisor backend" — the engine already isolates that behind `advisor.py`).
