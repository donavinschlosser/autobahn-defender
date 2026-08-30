# Autobahn Defender — Full Code Audit (2026-08-31)

**Auditor:** Hermes Agent (primary, full-manual review — every live file read end-to-end)
**Scope:** Working copy `/home/kristopher/Projects/Autobahn Defender/` @ v2.0 no-AI state (post Aug-23 engine rework), plus `build_deb_v2.0` packaging.
**Method:** Line-by-line read of all 13 `engine/` modules, `main.py`, `security_tab.py`, `scanner.py` (2635 l.), `quarantine.py`, `updater.py`, `yara_updater.py`, `ai/rss_feeds.py`, `ai/intel_db.py`, `ai/__init__.py`, `firewall.py`, `kernel_checker.py`, `history_db.py`, `usb_monitor.py`, `settings.py` (API), packaging (control/postinst/prerm/launcher), plus an AST/pattern sweep over all 37 live `.py` files (compile check, dangerous-pattern scan, undefined-name cross-reference). **The application was NOT executed** (per instruction); all findings are static-analysis verified, and the NameError class below is proven by AST cross-reference, not speculation.
**Codeberg repo:** untouched (read-only directive honored). No code was changed.

---

## Verdict in one paragraph

The v1.4-era components (scanner pipeline, quarantine, updater, history DB, feed poller) remain solid — the v1.4 audit fixes held. But the **new v2.0 `engine/` package was never smoke-tested**: it contains **four classes of proof-by-AST runtime-dead code** (undefined names caught by broad `except`s), an advisor whose analyzers read **schema keys the checks never emit** (8 of 9 analyzers), and a **false-positive "patch verified" path**. Net effect: the *Network Audit* and *Hardening Audit* buttons always render "No issues found", the *Full Audit* silently drops most of its findings, CVEs all display as HIGH severity, the privacy shield never runs its GNOME checks, and a network hiccup can mark a vulnerable package "verified fixed". Separately, `scanner.py`'s file-collection cap makes a "Full System" scan stop after ~100k files. None of this crashes the app — it all fails *silently*, which is worse.

---

## A. CRITICAL — advertised features are dead or lying (fix before anything else)

### A-1. `engine/checks.py` — composite checks call 10 undefined `_t_*` names
**Evidence:** `engine/checks.py:2130,2137,2144,2151,2218,2224,2230,2236,2242,2248` call `_t_network_connections`, `_t_network_threat_monitor`, `_t_dns_check`, `_t_firewall_check`, `_t_privacy_hardening`, `_t_ssh_audit`, `_t_mac_status`, `_t_screen_lock`, `_t_password_policy`, `_t_disk_encryption`. AST cross-reference: **none of these names exist** in the module (they were the `ai/tools.py` function names; the port renamed them to `check_*` but the composite bodies were never updated). Each call raises `NameError`, which the surrounding `try/except Exception` converts to an `_err(...)` sub-result.
**Impact:** `check_network_security` and `check_hardening_audit` always return all-error sub-results (status "ok", data full of errors). The **Network Audit** task (`network_security` + `network_connections` + `dns_check`) and **Hardening Audit** task (`hardening_audit` + `privacy_hardening` + `ssh_audit`) — 2 of the 4 audit buttons — produce empty reports. `full_audit` includes both composites, so its coverage is gutted too. `_t_mac_status` doesn't exist at all anymore (MAC status check was never ported).
**Fix:** replace the 10 calls with `check_*` equivalents (or better: `run_check("check_...")`), and delete the `_t_mac_status` call or port a `check_mac_status`. Then see A-5.

### A-2. `engine/checks.py:1042,1051` — undefined `SUSPICIOUS_REMOTE_PORTS` / `HIGH_RISK_PORTS`
**Evidence:** used at lines 1042/1051; defined nowhere in `engine/` (they exist only in the dead `ai/tools.py:1411,1437` and were never copied).
**Impact:** `check_network_threat_monitor` raises `NameError` on the first established connection → `run_check` returns `_err` → the threat-monitor half of the composite is dead even after fixing A-1.
**Fix:** copy the two frozensets from `ai/tools.py` (or define fresh: 4444, 5555, 31337, 6667, 1234-class backdoor ports and high-risk 4444/8080/8443 etc.) into `engine/checks.py`.

### A-3. `engine/checks.py:395-407` — `check_yara_scan_file` uses `_yara_cache`/`_yara_cache_lock` from the wrong module
**Evidence:** references `_yara_cache_lock` (line 395) and `_yara_cache` (396/407) — defined in `scanner.py:518-519`, not in `engine/checks.py`. `NameError` → caught by the generic `except` → returns `"YARA scan failed: name '_yara_cache_lock' is not defined"` **every time**.
**Impact:** the YARA file-scan check is 100% dead.
**Fix:** module-level `_yara_cache: dict = {}` + `threading.Lock()` in `engine/checks.py` (or import the scanner's — but see F-6 for why engine must not import scanner).

### A-4. `engine/checks.py:1087` — `from . import AI_DATA_DIR` (doesn't exist in `engine`)
**Evidence:** `engine/__init__.py` defines `DATA_DIR/INTEL_DIR/...` but **not** `AI_DATA_DIR` (that lives in `ai/__init__.py:15`). `ImportError` → swallowed → `cache_path = None` → the Emerging-Threats blacklist cache in `check_network_threat_monitor` never engages; every invocation re-downloads.
**Impact:** dead cache + engine reaching into a package it's supposed to replace. (Note: this whole check is also superseded by `engine/network_watch.py` — see E-2 for the dedup fix.)
**Fix:** use `BLACKLIST_DIR` from `engine/__init__`, or delete the duplicate blacklist logic entirely in favor of `network_watch`.

### A-5. `engine/advisor.py` — 8 of 9 analyzers read keys the checks never emit
**Evidence (analyzer → key it reads → key the check actually returns):**
- `_analyze_ssh` (advisor.py:484) reads `issues` → `check_ssh_audit` returns **`findings`** (checks.py:965-971)
- `_analyze_hardening` (501) reads `issues` → composite returns `summaries`/`total_findings`
- `_analyze_privacy` (519) reads `issues` → check returns `findings`/`weak_count`
- `_analyze_dns` (536) reads `issues` → check returns `findings`
- `_analyze_persistence` (429) reads `suspicious_entries` → `check_scan_persistence` returns **`findings`** (the *standalone* `engine/persistence.py` returns `suspicious_entries` — the port mixed the two up)
- `_analyze_disk_encryption` (553) reads `unencrypted_volumes` → check returns **`unencrypted_devices`**
- `_analyze_startup` (571) reads `suspicious` → check returns `findings`
- `_analyze_network_security` (466) reads `threats` → composite returns `threat_findings`

Only `_analyze_system_audit` (317) reads keys that exist (`firewall/apparmor/ports/updates/ssh_config/auth_log`).
**Impact:** even where checks succeed, their findings vanish at the analysis step. Security scores are silently inflated ("No issues found. System appears secure." is the default output for 2 of 4 audit buttons). This is the single most damaging bug class in the project because it *looks like* the system is clean.
**Fix:** align every analyzer to the actual return schemas (or better: standardize all checks on one finding-dict shape `{severity,title,what,why,fix}` and have analyzers consume that directly — see plan §P2).

### A-6. `engine/privacy.py:109-112` — `echo "$XDG_CURRENT_DESKTOP"` without a shell
**Evidence:** `subprocess.run(["echo", "$XDG_CURRENT_DESKTOP"], ...)` — argv mode, no shell → stdout is the **literal string** `$XDG_CURRENT_DESKTOP`. The `"gnome"/"unity"/"cinnamon" in desktop` test can never match.
**Impact:** the entire GNOME/Cinnamon privacy-settings block (5 gsettings checks) never runs; `check_privacy_settings()` returns only the sysctl half. On the developer's own Linux Mint Cinnamon this feature is dead.
**Fix:** `desktop = os.environ.get("XDG_CURRENT_DESKTOP", "").lower()` — no subprocess needed at all. Also treat `_gsettings_get() is None` (schema/key missing) as *not applicable*, not `needs_attention` (currently a missing schema would show as a false "needs attention" row once the echo bug is fixed).

### A-7. `engine/patches.py:188-225` — `verify_patch_applied` reports "verified fixed" on empty results
**Evidence:** `query_osv()` returning `[]` (network error, timeout, OSV hiccup — the code logs-and-continues on failures) or a CVE-ID mismatch (see below) → `target_vulns` empty → `results` empty → `"all_resolved": all(...) if results else True` → **True**. `security_tab.py:541` then shows "✓ {pkg} has been updated and all CVEs are resolved!".
Second path: the tracker stores the **display ID** (canonical `CVE-…`, per cve.py:140) but `verify_patch_applied` matches `v.get("cve_id") == cve_id` against the same normalized display id — OK — however `_track_selected_cves` (security_tab.py:409) reads the ID **from the QTableWidget cell**, which is the display id; consistent. The empty-result path remains the killer.
**Impact:** a user can be told a vulnerable package is fixed when the check simply didn't run. For an antivirus product this is the worst possible failure direction.
**Fix:** distinguish "no data" from "resolved": `all_resolved` must be `False` (or `None` → "unknown") when `results` is empty AND the package still has open tracked entries; surface network errors explicitly.

### A-8. `engine/__init__.py:37-40` and `ai/__init__.py:15-18` — `XDG_DATA_HOME` handling drops the app suffix
**Evidence:** `Path(os.environ.get("XDG_DATA_HOME", "~/.local/share/autobahn-defender"))` — when `XDG_DATA_HOME` **is set** (Flatpak sandboxes, some DEs, users who customize), `DATA_DIR` becomes `$XDG_DATA_HOME` **itself**, so `INTEL_DIR` = `~/.local/share/intel`, `BLACKLIST_DIR` = `~/.local/share/blacklist` — colliding with/polluting the shared data root of every other XDG app.
**Impact:** silent data pollution + wrong-location state on any system that sets the variable. Works today only because it's usually unset.
**Fix:** `Path(os.environ.get("XDG_DATA_HOME", "~/.local/share")) / "autobahn-defender"` in both packages (and same pattern anywhere else env-default is used this way).

### A-9. `scanner.py:1745-1801` — "per-directory" cap actually caps the whole scan root at 100k files
**Evidence:** `count = 0` is initialized **per scan path** (line 1767), incremented for every collected file across the entire `os.walk` of that path, and `if count > self.MAX_FILES_PER_DIR: break` (1791/1797) exits the walk. `full_system` scans a single root (`/`), so collection stops at file #100,001.
**Impact:** on a typical 2026 desktop (0.5–2M files), a **Full System scan examines only the first ~100k files in walk order** — while the first-run dialog promises "Everything on your system is scanned." Coverage is maybe 5–20%, silently. (YARA phase uses `_collect_scannable_files`; parallel ClamAV also uses it — both capped.)
**Fix:** make the budget actually per-directory (reset `count` inside the walk per `root`), or per-scan-root with a much higher full-system cap (e.g. 2M), quick-scan keeps a tighter budget. Log when the cap trips so it's never silent.

### A-10. `engine/versions.py:48` — literal `str.replace` where `re.sub` was intended
**Evidence:** `return really.group(1).replace(r'[+~].*$', '',)` — replaces the **literal substring** `[+~].*$` (never present) instead of stripping `+dfsg`/`~beta` suffixes via regex.
**Impact:** `+really` versions with trailing Debian suffixes compare wrongly inside the CVE false-positive filter — can suppress a real vulnerability or pass a false one. Subtle, silent, data-corrupting.
**Fix:** `re.sub(r'[+~].*$', '', really.group(1))`. Longer term: replace the whole hand-rolled comparator with `apt_pkg.deb_version_compare` from `python3-apt` (preinstalled on every Debian/Ubuntu/Mint; authoritative semantics) with the pure-Python version kept only as fallback — see plan §P4.

---

## B. HIGH — serious correctness/security issues in live paths

### B-1. CVSS severity is never parsed — every CVE renders as "HIGH"
**Evidence:** `cve.py:182-188` stores the raw CVSS **vector string** (`CVSS:3.1/AV:N/AC:L/...`) in `severity`. `advisor.py:204` and `security_tab.py:385-390` test `"CRITICAL" in str(...).upper()` — a vector string never contains the word CRITICAL.
**Impact:** no CVE can ever be CRITICAL/MEDIUM/LOW in reports or the UI; prioritization is impossible; advisor scoring mis-weights every CVE finding.
**Fix:** parse the vector (tiny CVSS 3.1 base-score calculator ~40 lines, or capture `database_specific.severity` from OSV when present) and emit a real severity label + numeric score.

### B-2. `engine/apply.py:209-283` — `ssh_harden` can write settings into Match-block scope and silently changes commented defaults
**Evidence:** missing settings are **appended to the end of `sshd_config`** (243-245). If the file ends with a `Match` block (common), the appended `PermitRootLogin`/`PasswordAuthentication` lines apply **only inside that Match**, not globally — hardening silently doesn't happen. Also the rewrite converts `#PermitRootLogin prohibit-password` comment lines into active `PermitRootLogin no` (intended value changes are fine, but rewriting a *commented* line to an active one is a semantic change the user never sees diffed).
**Impact:** SSH hardening reports success while being ineffective; user-visible config churn.
**Fix:** write a drop-in `/etc/ssh/sshd_config.d/60-autobahn-hardening.conf` instead (Ubuntu/Mint `sshd_config` has `Include sshd_config.d/*.conf` at the **top** → drop-in is global scope, survives package upgrades, trivially reversible by deleting one file). Keep `sshd -t` validation + auto-rollback. Show a diff in the confirm dialog.

### B-3. `main.py:766-783` — RSS worker thread mutates Qt widgets directly
**Evidence:** `_poll_feeds_background` runs `poll_all_feeds()` in a plain `threading.Thread`, then calls `self.security_news_tab.set_last_updated(...)` and `.refresh_articles()` **from that thread**. Qt widgets may only be touched from the GUI thread (object affinity); this is the classic intermittent-crash pattern.
**Impact:** random hard-to-reproduce crashes during background feed refresh.
**Fix:** emit via a signal (define `feeds_polled = pyqtSignal(...)` on MainWindow, connect in GUI thread) — the codebase already does this correctly elsewhere (`_CVEWorker` etc.).

### B-4. `engine/apply.py:66-71` — useless sudo fallback; pkexec unusable in headless contexts
**Evidence:** `run_privileged` falls back to `["sudo"] + argv` with **no askpass** and `capture_output=True` — in a GUI there's no TTY, sudo reads a password from a terminal that doesn't exist → hangs to the 60s timeout. In a terminal-less/headless context pkexec has no authentication agent → fails with a polkit error string users won't understand.
**Impact:** on any system without pkexec (or from SSH/plain-CLI contexts, which the CLI plan introduces) every privileged action degrades to a 60-second freeze then failure.
**Fix:** `sudo -A` with a `SUDO_ASKPASS` helper (pkexec absent), and for the CLI: explicit `--require-tty` behavior — either detect `sys.stdin.isatty()` and use plain sudo, or refuse with a clear message. See plan §P3.

### B-5. `engine/persistence.py:32` — `/\.` pattern floods false positives
**Evidence:** `_SYSTEMD_SUSPICIOUS` includes `re.compile(r'/\.')` ("hidden dirs"). Any `ExecStart` containing `/home/user/.local/...`, `/etc/...`? no — but `/home/u/.config/...`, `/opt/app/.venv/...` etc. all match.
**Impact:** every legitimate service whose binary lives under a dot-directory is flagged HIGH "Suspicious ExecStart". `scanner.py`'s own copy of this scan (1026-1030) deliberately **omits** this pattern — the engine copy regressed. The Network Watch "Scan Persistence" button and `full_audit` both run the engine copy (`check_scan_persistence` uses its own list which does **not** include `/\.` — verify: checks.py:588-593 has 4 patterns, no `/\.` — correct; only `persistence.py` standalone has it). So the FP flood comes specifically from the Network Watch tab's "Scan Persistence + Hosts File" button (security_tab.py:905 → `persistence.scan_persistence()`).
**Fix:** drop `/\.` from `persistence.py`; require `/tmp|/dev/shm` or download-and-execute indicators for HIGH severity; dot-dirs alone are at most INFO. Unify with the checks.py pattern list (see E-2).

### B-6. `engine/cve.py:30-54` — ecosystem detection is 2024-frozen
**Evidence:** handles Ubuntu 20.04/22.04/24.04/24.10, Debian 11/12, Mint 20/21/22 only. "Ubuntu 24.10" is mapped to `Ubuntu:24.04` (**wrong** — OSV has a distinct `Ubuntu:24.10` ecosystem; 24.10 packages have different fixed versions). Nothing for Ubuntu 25.04/25.10/26.04, Debian 13, Mint 22.x point releases are fine via "Linux Mint 22" prefix. Unknown → silently defaults to `Ubuntu:24.04`.
**Impact:** on any 2025/2026-era Ubuntu (or 24.10), CVE results are computed against the **wrong distro release** — wrong fixed versions → wrong vulnerability verdicts. Silent.
**Fix:** parse `VERSION_ID` from `/etc/os-release` and build the ecosystem string generically (`Ubuntu:{VERSION_ID}`, `Debian:{VERSION_ID}`), with a curated override map for Mint→Ubuntu-base (22→24.04, 21→22.04, LMDE→Debian). Never guess silently — if unknown, say so in the result.

### B-7. `security_tab.py` — five long operations run on the GUI thread
**Evidence:** `_fix_all_patches` (492-528: sequential `pkexec apt-get install` per package, 120s timeout each + `verify_patch_applied` network calls), `_download_blacklist` (893-903: `requests.get` up to 60s), `_scan_network` (854-891: `ss` subprocess + per-connection CIDR scan), `_verify_patch` (530-555: OSV network call), `_check_privacy` (775-785: 13 sysctl subprocesses), `_scan_persistence` (905-926). None use the `_PatchWorker`/QThread pattern the same file already uses for CVE scans.
**Impact:** frozen UI for up to minutes; unresponsive "Not Responding" window; on Wayland potentially killed by the compositor. Violates the project's own established pattern.
**Fix:** route all of these through QThread workers (same as `_CVEWorker`). Mechanical, low-risk change. (The CLI rework in plan §P1 makes this moot by moving the logic into engine functions the CLI and GUI both call.)

### B-8. Root-only checks presented in an app that never runs as root
**Evidence:** `check_password_policy` (checks.py:1648-1658: `awk` on `/etc/shadow`), `check_auth_log_check` / `check_event_log` (`/var/log/auth.log` unreadable as user on Ubuntu ≥24.04 defaults), `check_system_audit`'s `ufw status verbose` / `aa-status` (partial output as user).
**Impact:** these checks return empty/permission-error results that either produce nothing (silent) or "Check failed — run sudo autobahn-defender" advice for a sudo mode that **does not exist** (`main.py` has no root launch path and shouldn't).
**Fix:** add a small pkexec-gated *collector* (e.g. `pkexec /usr/share/autobahn-defender/collect.py --shadow --authlog` writing a 0600 JSON to a tmp file owned by the user) OR use `journalctl` with appropriate group membership detection, and change the messaging to "requires elevated collector — click to run". See plan §P6.

---

## C. MEDIUM — robustness, efficiency, honesty of output

- **C-1. `engine/network_watch.py:176-179`** — `content += chunk` in the download loop is O(n²) byte copying (up to 50MB cap ⇒ gigabytes of memcpy). Use `io.BytesIO` or a list + `b"".join`. **C-1b:** `match_connection` (218-238) does a **linear scan** of up to 500k IPs + N CIDRs per connection per tick — build a set for exact IPs and a list of `ip_network` objects once at load; with firehol_level1 (~1.5k entries) it's fine today, but the caps allow pathological inputs.
- **C-2. `engine/apply.py:169-206`** — `sysctl_harden` issues **14 separate pkexec invocations** (1 file copy + 13 `sysctl -w`). Depending on polkit auth caching that's up to 14 password prompts and ~14 × process spawn. Write the conf file, then one `sysctl --system` → 2 invocations total. Also: `privacy.apply_all_privacy` (privacy.py:163-186) applies sysctls **runtime-only** (lost at reboot) while `sysctl_harden` persists to `/etc/sysctl.d/` — inconsistent behavior for the same settings; make both persist (or both not) and say which.
- **C-3. 38 swallowed `except: pass/continue`** across `engine/`, `main.py`, `scanner.py` (full list in the audit session log; highlights: `engine/checks.py:451,1094,1378,1469,1552,1659,1730,1747,1857,1885,1923,1947,1965`, `engine/cve.py:178`, `engine/cve_filter.py:124`, `main.py:807,1047,1051,1348`). This class of silence is precisely what hid A-1…A-4. Minimum fix: `log.debug("…: %s", e)` in each; better, a lint/test rule (see F-1).
- **C-4. `engine/cve.py:128-160`** — `is_affected` is computed and never used (dead); `fixed_in` takes the **first** `fixed` event seen across all ranges rather than the one for the range containing the installed version — multi-range OSV entries (common for long-lived packages) can yield the wrong "Fixed in". Also `get_cve_detail:247` validates CVE IDs only by `startswith("CVE-")` before f-string URL interpolation — add `^CVE-\d{4}-\d{4,7}$` full-match.
- **C-5. `ai/rss_feeds.py:169-179`** — `ZERO_DAY_KEYWORDS` includes `"CVE-2025"` and `"CVE-2026"`, which match essentially **every CVE article**; the zero-day flag therefore carries no signal. Drop year patterns; keep exploitation language ("actively exploited", "in-the-wild", "emergency patch") **and** cross-reference CISA KEV membership (the poller already fetches KEV — a KEV-hit is the strongest zero-day-adjacent signal available; plan §P5 makes this the core of the monitor).
- **C-6. `security_tab.py:310`** — `setSortingEnabled(True)` is left on while rows are inserted; sorting during fill reorders rows mid-loop (Qt anti-pattern), and row-index-based reads in `_track_selected_cves`/`_verify_patch`/`_resolve_selected_alert` then race the sort. Disable sorting during fill, enable after; or index by hidden ID column.
- **C-7. `updater.py`** — no integrity check beyond TLS for downloaded `.deb`/AppImage (acceptable for the threat model, but a sha256 printed in the release notes + verify-on-download is cheap); `version_tuple` maps non-numeric segments to 0, so a hypothetical tag `2.10beta` sorts as `2.0.0` — enforce semver tags in release process instead. `InstallProgressDialog` receives `["bash","-c","<string>"]` from `main.py:480-484` — the string is built entirely from hardcoded package names (not injectable today) but it's a root-shell-by-pattern; convert to argv form.
- **C-8. `engine/patches.py:96`** — `_simulate_upgrade` parses `apt-get -s upgrade` output text (fragile: version strings containing spaces/parentheses break `part[1:].split()`); `apt-get -s` also reports `Conf`/`Remv` lines ignored here. Fine for now; plan replaces with `apt list --upgradable --json`-ish parsing or python-apt.
- **C-9. `engine/checks.py:1410,1481,1751`** — `"x" in dir()` hacks (`nameservers`, `encrypted`, `upgradable`…) to paper over variable-scope confusion; works but is a smell; initialize vars up front.
- **C-10. `check_disk_encryption`** flags every unencrypted mounted filesystem (including EFI `vfat`!) as MEDIUM and unencrypted root as HIGH — on a default desktop this is 3-5 "findings" of user-chosen architecture. Should be INFO-tier with a clear "by design?" acknowledgment, or checked against a user-declared "I don't need encryption" preference (advisors like Lynis mark these informational for desktops).
- **C-11. Deb packaging (`build_deb_v2.0`)** — (a) `engine/__pycache__/*.pyc-311` shipped (stale-bytecode hazard, bloat — strip in build); (b) `prerm` still kills Ollama sidecars — v2.1 leftovers, dead code; (c) `control` Description says "6 deterministic audit profiles" — reality is 4 (doc drift); (d) `requirements.txt` (pip-style) shipped inside an apt package whose deps live in `control` — confusing; generate or drop; (e) `ai/` ships `threat_monitor.py` + `alerts.py`, which reference the removed AI infra — dead weight, ship only `__init__.py`, `rss_feeds.py`, `intel_db.py`; (f) `usr/share/metainfo` directory present but the appdata XML appears missing from the v2.0 deb tree (verify before next build); (g) launcher hardcodes `python3` — fine, but no `--` argument separation before user args.
- **C-12. `network_watch.BLACKLIST_SOURCES`** — direct Spamhaus DROP URL: Spamhaus ToS restricts automated fetching and they block default UAs; `firehol_level1` already aggregates DROP. Remove the direct source (keep firehol), or fetch via their published procedure.
- **C-13. `scanner.py:1187-1218` `_estimate_file_count`** walks up to 500k files for a *progress denominator* while actual collection caps at 100k (A-9) — the two budgets disagree; unify.
- **C-14. `check_update_status:1719-1729`** — uses `/var/lib/apt/lists/partial` mtime as "last apt update" heuristic; that dir's mtime changes on any apt invocation start; use the newest `lock`-free file in `/var/lib/apt/lists/` or `/var/lib/apt/periodic/update-success-stamp`.

---

## D. LOW / polish

- **D-1.** Three divergent copies of the hosts-tamper check (`scanner.py:1046`, `engine/checks.py:658`, `engine/persistence.py:136`) with three different protected-domain sets and safe-IP sets — DRY into one `engine/hosts_check.py` consumed by all three call sites.
- **D-2.** `engine/checks.py` module docstring still says "Replaces the v2.0 AI tool functions" — fine — but `__init__.py` docstring lists `state` and `knowledge_map` submodules that were never created (doc drift; `security_tab` imports only what exists — OK).
- **D-3.** `security_tab._download_blacklist` sets `QApplication_instance = self` (dead assignment).
- **D-4.** `_DEB_TTL`-style dedup in `NetworkWatch._last_alerts` grows unbounded by unique IP (bounded in practice; note).
- **D-5.** `main.py:18` sets `QT_LOGGING_RULES` via `setdefault` before importing PyQt — good; keep.
- **D-6.** `history_db` catches all `sqlite3.Error: pass` — acceptable for history logging, but add `logging.debug`.
- **D-7.** `firewall.py:139-144` runs 5 sequential pkexec prompts for UFW apply (polkit usually caches; consider batching via one `pkexec ufw …` script file).
- **D-8.** First-run guidance text (main.py:1201-1238) promises full-scan coverage contradicted by A-9; update copy after fixing.
- **D-9.** `ai/tools.py:502` `verify=False` — in a dead module (not imported by live code), but delete or fix before anyone resurrects it.
- **D-10.** `updater.py` User-Agent says `AutobahnDefender/1.0` (stale version string in two workers).

---

## E. What is GOOD (keep, don't touch)

1. **Quarantine chain** — O_NOFOLLOW open + fstat S_ISREG + detection-ledger content-hash binding + 3-pass chunked secure delete + deletion audit log + path-validated restore + safe-name manifest regex. This is genuinely well-engineered TOCTOU defense; the v1.4 fixes all held.
2. **`scanner.py` pipeline** — clean-env subprocesses, `--` argument separation, exclude self-files, upstream/bundled rule preference, per-file compile fallback, dedup rename, thread-safe `Rules.match` pool, cancellation that kills procs and pools. The 100k cap (A-9) is the only real defect; the rest is solid.
3. **Atomic JSONL everywhere** (`engine/alerts`, `patches`, `ai/intel_db`, `network_watch`) — mkstemp + chmod 0600 + `os.replace`, dirs 0700. Consistent and correct.
4. **`apply.py` argv-only pkexec** — no shell interpolation in any action; service whitelist; action audit log with rollback strings.
5. **ss parsers** — both variants (state-filtered without State column in `network_watch`; unfiltered in `checks`) use the correct column indices for their respective formats (the Aug-23 off-by-one fix held).
6. **KEV JSON defensive parsing** (`ai/rss_feeds.py:232-360`) handles JSON-Feed and raw CISA schemas.
7. **freshclam fallback ladder** (user config → DatabaseOwner retry → parse-error retry → system defs → pkexec freshclam → systemd service → direct HTTP mirrors) — battle-tested.
8. **history_db** WAL + 0600 sidecars (v1.4 fix held).

---

## F. Root-cause notes (feed these into the plan)

- **F-1. No tests, no smoke gate.** Every CRITICAL finding above (A-1…A-10) would have been caught by a 5-minute harness: import every module, iterate `engine.checks.CHECKS`, call each with `{}`, assert non-error or known-skip. The v3.0 plan promised `tests/`; it was never built. This is the single highest-leverage fix in the whole audit.
- **F-2. Three-way duplication** between `scanner.py` post-scan checks, `engine/checks.py`, and `engine/persistence.py` guarantees the divergence already seen (B-5: `/\.` in one copy only; D-1: three hosts checkers). One canonical module per check, everyone imports it.
- **F-3. The advisor's analyzer layer is a second schema** — checks emit ad-hoc dicts, analyzers re-interpret them, and the two drifted instantly. Kill the ad-hoc shape: every check returns `Finding` objects (same dataclass the advisor renders); analyzers disappear.
- **F-4. Silent failure is the house style** (38 `except: pass` + `_err` dicts that render as "unavailable" strings). A finding must be *loud* when its engine is broken — a `degraded` flag in results + a UI banner, minimum.
- **F-5. Version/ID canonicalization is scattered** (display id vs original id, hand-rolled Debian compare). Centralize: one `engine/ids.py` + `apt_pkg` comparator.
- **F-6. `engine/` is not headless-importable**: `engine/checks.py` does `from scanner import RULES_DIR` (pulls PyQt6 + quarantine into any CLI import). The CLI plan must invert this dependency (neutral `paths.py`).

---

## Prioritized fix order (before any new features)

| # | Finding | Effort | Risk if unfixed |
|---|---------|--------|-----------------|
| 1 | A-1/A-2/A-3/A-4 undefined names in engine/checks | hours | 4 dead features, silently |
| 2 | A-5 advisor schema mismatches | hours | reports lie ("secure") |
| 3 | A-7 false "verified fixed" | 1h | worst-direction AV failure |
| 4 | A-6 privacy echo bug | 10 min | dead feature on target DE |
| 5 | A-8 XDG_DATA_HOME | 10 min | data pollution on set-env systems |
| 6 | A-9 scan 100k cap | 30 min | "full scan" scans 5-20% |
| 7 | A-10 versions literal replace | 10 min | wrong CVE verdicts |
| 8 | B-1 CVSS parse | 1-2h | no severity prioritization |
| 9 | B-3 cross-thread Qt | 30 min | intermittent crashes |
| 10 | B-7 UI-thread blocking | 2-3h | frozen GUI |
| 11 | B-2 SSH drop-in | 1h | ineffective hardening |
| 12 | F-1 test harness | 1 day | recurrence of all the above |

*(The full implementation plan — CLI surface, zero-day monitor, remediation orchestration, and the fixes above as Phase 0 — follows in `AUTODEF_CLI_ZERODAY_PLAN.md`.)*