# Kudu Deep-Dive — What We Can Steal for Autobahn Defender

**Date:** 2026-08-07
**Repo:** `AdventDevInc/kudu` (Electron/TypeScript, MIT license, ~2.1k stars)
**Relevant engine files studied:**
- `src/main/platform/linux/malware.ts` — Linux native AV glue
- `src/main/services/yara-engine.ts` — YARA-X engine wrapper
- `src/main/services/yara-rules-store.ts` — cloud rules download/caching
- `src/main/services/threat-monitor.ts` — live network/DNS threat detection
- `src/main/services/threat-blacklist-store.ts` — IP/domain/CIDR blacklist
- `src/main/ipc/malware-scanner.ipc.ts` — main scan orchestration (2081 lines)
- `src/main/platform/linux/malware-paths.ts`, `paths.ts`, `network.ts`, `security.ts`
- `src/main/services/scan-cache.ts`, `file-utils.ts`
- `src/main/services/deletion-log-store.ts`, `threat-blacklist-store.ts`

**Autobahn Defender's current state:** PyQt6, YARA via `yara-python` (compiled rules cached by mtime), ClamAV integration (parallel clamscan chunks), whitelist by path, quarantine manager, plus an AI Security module (LFM2.5 model) with ~22 function-calling tools including `_t_yara_scan_file`, `_t_network_connections`, `_t_investigate_process`, `_t_file_info` (with entropy calc).

---

## 1. HOW KUDU SCANS FOR MALWARE (engine overview)

Kudu's scanner is **multi-phase**, each phase is an independent detection engine, results merged:

| Phase | Engine | What it does |
|-------|--------|--------------|
| 1 | File Discovery | Walks configured dirs, filters by extension + double-extension |
| 2 | **YARA signatures** | Cloud-downloaded ruleset, compiled once, scanned per-file |
| 3 | **Heuristic analysis** | PE header parse, entropy, W^X sections, suspicious API imports |
| 4 | **Script analysis** | Pattern-matches PowerShell/BAT/VBS/HTA for malicious behaviors |
| 5 | **System integrity** | `/etc/hosts` tampering detection |
| 6 | **Persistence scan** | Linux crontab + systemd user services |
| 7 | **Native AV** | ClamAV subprocess (Linux), codesign (macOS) |

Each detection is tagged with `source` (`signature`/`heuristic`/`defender`), a severity, and `details`. **This tagging model is the backbone** — it lets the UI group by engine and lets the user allowlist by content-hash.

---

## 2. THE STEALABLE FEATURES (ranked by value to Autobahn)

### 🟢 A. YARA Engine optimization — BEST WIN (port directly)
Kudu's `yara-engine.ts` solves the exact problem Autobahn's `scanner.py` has with the 1.7MB rules file:

1. **Bulk compile, not per-file.** Kudu concatenates ALL rule sources and compiles in ONE call (~2s for 1400 files). Its comment notes `addRuleFile()` per-file is **~240x slower** because it recompiles the accumulated set every call. Autobahn already does bulk `yara.compile(filepaths=...)`, so this is *already handled* — but Kudu adds:
2. **Platform tag filtering** — `_linux_`, `_windows_`, `_darwin_` in filename → skip other-OS rules before compiling. Autobahn ships 3 rule files; on Linux it could skip macos/windows rules at compile time for a faster load and smaller match space. **Direct steal.**
3. **Per-file validation fallback** — if bulk compile fails (bad syntax in one file), re-validate each file and exclude the broken ones instead of failing entirely. Autobahn would benefit: a corrupted rules file currently breaks the whole scan.
4. **Lazy + background init** — YARA compilation is deferred until first scan or explicit "check updates"; progress is pushed to the UI via a compile-progress counter. Autobahn recompiles on mtime change at scan time — could add a visible "compiling signatures..." progress state.

### 🟢 B. Detection ledger / action authorization (port concept)
Autobahn's quarantine works on user-clicked paths. Kudu's **detection ledger** is a security hardening worth copying:
- Quarantine/delete only act on files **flagged by a scan in this process**, recorded in an in-memory ledger with a **content-hash binding**.
- Before acting, it re-hashes the file and refuses if the bytes changed (prevents TOCTOU / swapped-file attacks).
- Entries expire after 24h TTL, capped at 10k records.
- "Mark safe" immediately revokes authorization and adds to an allowlist.

**For Autobahn:** the AI tool `_t_yara_scan_file` + quarantine could be hardened so an AI-invoked quarantine can only touch files the scanner actually flagged, and only if unchanged. Prevents a prompt-injected AI from deleting arbitrary files.

### 🟢 C. Linux persistence scan (NEW capability for Autobahn)
`scanLinuxPersistence()` in the IPC file is **fully Linux-native** and Autobahn has nothing like it:
- Parses user **crontab** for: `curl|wget` piped to `bash|sh|python`, execution from `/tmp`, base64-decode-and-execute.
- Parses **systemd user services** (`~/.config/systemd/user/*.service`) for: `ExecStart` from `/tmp`, download-and-execute, `Restart=always` pointing at hidden dirs.
This is a perfect **new AI tool** for Autobahn — the model could call a `scan_persistence` tool and get back a structured list of suspicious crontab/systemd entries. Direct, high-value port.

### 🟢 D. Hosts-file tampering detection (NEW AI tool)
`checkHostsFile()` flags redirections of ~40 major legit domains (google, microsoft, paypal, banks) to non-safe IPs. It has a careful SAFE_IPS allowlist. **Extremely high-confidence, low-FP check** that Autobahn lacks. Great standalone AI tool + could be part of the main scanner.

### 🟡 E. Script content analysis (port for the AI, not the main scanner)
`analyzeScriptContent()` has excellent regex heuristics for PowerShell/BAT/VBS/HTA:
- Encoded PowerShell (`-enc` + base64 blob), download cradles (`iwr`/`curl` + `iex`), AMSI bypass, reflective assembly loading, mimikatz refs.
- Requires **≥2 indicators** to flag (reduces FPs) EXCEPT base64-embedded-PE which is sufficient alone.
- The `TVqQAAMAAAAEAAAA` base64-PE-header detection is a gem.

Autobahn's AI already scans scripts for the model to read; adding a **`_t_analyze_script` tool** that returns Kudu-style indicator lists would let the AI make evidence-based judgments instead of raw file dumps. The ≥2-indicator rule and the specific regexes are directly reusable (they're language-agnostic patterns).

### 🟡 F. Threat monitor + blacklist (big feature, bigger effort)
Kudu's `threat-monitor.ts` does **live connection/DNS monitoring** against a downloadable IP/domain/CIDR blacklist:
- Parses `ss -tunap state established` (Linux) to get remote IP:port + PID per connection.
- Matches against IP set, domain set, and **CIDR ranges** (with proper IPv4/IPv6 math in `threat-monitor.ts`).
- Dedup with TTL, server-mode detection (only flag outbound when on a headless server via `systemctl get-default` + `loginctl`).
- Downloads a versioned blacklist with atomic replace.

**Relevance to Autobahn:** Autobahn already has `_t_network_connections`. Adding CIDR matching + a downloadable blacklist + a scheduled scan would turn "list connections" into "flag malicious connections." The CIDR matcher and `ss` parser are directly portable to Python. This is a **moderate-size project** — best done as an AI tool first, real-time monitor later.

### 🟡 G. Native AV status collection (Linux hardening dashboard)
`createLinuxSecurity().collectAntivirusStatus()` probes:
- ClamAV (install path + version), **SELinux** (`getenforce`), **AppArmor** (`aa-status --json`, counts enforcing profiles), UFW/firewalld/nftables/iptables, LUKS disk encryption (`lsblk -J`), apt/dnf/pacman update freshness, screen-lock policy, password policy (`/etc/login.defs`, `pwquality`, `faillock`), **SSH hardening** (sshd_config + drop-ins parsing), **fail2ban** (jails + banned counts), listening ports.

Autobahn has firewall.py, hardening.py, kernel_checker.py already — but the **SSH hardening audit** (parses sshd_config + `/etc/ssh/sshd_config.d/*.conf` with Match-block awareness) and **AppArmor profile counting** are clean additions as AI tools.

### 🟡 H. Scan-cache + deletion log (UX/integrity)
- `scan-cache.ts`: in-memory Map<id, ScanItem> capped at 50k, so clean handlers resolve paths by ID. Autobahn doesn't need this (PyQt passes paths directly).
- `deletion-log-store.ts` + `file-utils.ts`: **opt-in audit trail** of every deleted file (buffered writes, flush every 500, cap 100k descendants, `lstat` to distinguish dir vs symlink). Autobahn's history_db.py covers some of this, but the **secure delete (2-pass random+zero overwrite)** in `file-utils.ts` is cleaner than Autobahn's current `quarantine.py` chunked write. **Steal the 2-pass overwrite.**

---

## 3. SCANNER OPTIMIZATIONS WE CAN LEARN

1. **Extension whitelist + double-extension check** (Kudu) vs **scan-everything** (Autobahn). Kudu only YARA-scans a curated extension set (`.sh .py .rb .pl .js .so .bin .ko .elf .run .AppImage .deb .rpm .jar .desktop` for Linux) — far faster than Autobahn's "all regular files" approach. **Autobahn's all-files approach is slower but more thorough.** Middle ground: add a `quick scan` mode that uses Kudu's extension set, keep `full scan` as-is.
2. **Per-directory maxDepth/maxFiles budgets.** Kudu's `paths.ts` gives each scan root a depth+file cap (e.g. Downloads depth 6 / 10k files, HOME depth 1 / 500). Prevents pathological infinite walks. Autobahn's `p.rglob("*")` has no cap → could hang on huge trees. **Steal the budget model.**
3. **SKIP_DIRS** set (node_modules, .git, .svn, __pycache__) to avoid re-scanning huge junk. Autobahn whitelists by path but doesn't skip these during collection. **Cheap win.**
4. **Skip symlinks during collection** (`entry.isSymbolicLink()` guard). Autobahn checks `f.is_symlink()` already — good, keep it.
5. **Concurrency batching.** Kudu uses `Promise.allSettled(chunk.map(...))` with SIG_CONCURRENCY=16 for YARA and 8 for ClamAV. Autobahn already does parallel clamscan chunks; could apply the same batching to YARA file scanning.
6. **`filenameOnly` YARA rule metadata** — rules tagged `filenameOnly` only match outside system dirs (avoids false positives on legit system binaries). Autobahn could adopt this metadata convention.

---

## 4. LICENSING — clean to reuse

Kudu is **MIT licensed** (confirmed in `LICENSE` and README). We can copy/adapt the code with attribution. Autobahn Defender's license should be compatible. Recommended: add an attribution note in README/AUTHORS crediting AdventDevInc for any ported code. (Autobahn's own LICENSE is at `~/Projects/Autobahn Defender/LICENSE` — MIT, so fully compatible.)

---

## 5. RECOMMENDED PORT ORDER (low → high effort)

**Phase 1 — Quick wins (isolated AI tools, low risk):**
1. `_t_scan_persistence` — crontab + systemd user service analysis (port `scanLinuxPersistence`)
2. `_t_check_hosts_integrity` — hosts-file tampering (port `checkHostsFile`)
3. `_t_analyze_script` — script indicator analysis (port `analyzeScriptContent` regexes)
4. `_t_ssh_hardening_audit` — sshd_config + drop-ins (port from `collectSshHardening`)
5. AppArmor/SELinux status tool

**Phase 2 — Scanner engine upgrades:**
6. Platform-tag rule filtering at YARA compile time (skip macos/windows rules on Linux)
7. Per-file validation fallback for corrupted rule bundles
8. Per-directory maxDepth/maxFiles budgets + SKIP_DIRS during collection
9. Optional "quick scan" extension-whitelist mode

**Phase 3 — Security hardening:**
10. Detection ledger with content-hash binding for quarantine/delete (prevents AI or TOCTOU deleting arbitrary files)
11. 2-pass secure overwrite (random + zero) for quarantine deletion
12. Hosts-tampering + persistence checks folded into the main scanner's regular scan

**Phase 4 — Live monitoring (biggest effort):**
13. Network threat monitor: `ss` connection parser + CIDR matcher + downloadable IP/domain/CIDR blacklist

---

## 6. KEY FILES TO COPY FROM KUDO (paths in /tmp/kudu-research)

| Kudu file | What to steal |
|-----------|---------------|
| `src/main/ipc/malware-scanner.ipc.ts` lines 82-98 | SUSPICIOUS_FILENAMES (Windows — skip for Linux port) |
| lines 209-361 | entropy calc, PE analysis (Windows-focused) |
| lines 437-505 | **checkHostsFile** — high value, platform-neutral |
| lines 508-602 | **analyzeScriptContent** — high value, regexes portable |
| lines 820-891 | **scanLinuxPersistence** — crontab + systemd, direct port |
| `src/main/services/yara-engine.ts` | bulk compile + platform filter + per-file fallback |
| `src/main/platform/linux/paths.ts` | scan dirs + depth/file budgets + SKIP logic |
| `src/main/services/threat-monitor.ts` | CIDR matcher (IPv4/IPv6) + ss parser + dedup/TTL |
| `src/main/platform/linux/network.ts` | `ss -tunap` parsing → connection list |
| `src/main/platform/linux/security.ts` | SSH hardening, AppArmor, SELinux, fail2ban, firewall probes |
| `src/main/services/file-utils.ts` | 2-pass secure overwrite, isExcluded glob logic |

---

## BOTTOM LINE

Kudu is a **legit, well-engineered, MIT-licensed** scanner. The highest-value, lowest-risk steals for Autobahn are: **(1)** the Linux persistence scan, **(2)** hosts-file tamper detection, **(3)** the script-content analysis regexes, and **(4)** the SSH/AppArmor hardening audit — all as new AI tools. The scan-cache/ledger and CIDR threat-monitor are bigger projects but architecturally sound and directly adaptable to Autobahn's PyQt/Python stack. Nothing requires porting Kudu's Electron/TypeScript — all the detection logic is language-agnostic patterns and subprocess calls that map cleanly to Python.
