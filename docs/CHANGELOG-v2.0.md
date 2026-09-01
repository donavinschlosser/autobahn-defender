# Autobahn Defender v2.0 — Technical Changelog

Full change log since the v1.4 release. 24 commits, 85+ files, ~24,000 lines
added. Version string intentionally stays 2.0.0 across the engine rebuild —
check the build date / commit, not just the number.

## 1. Security Center & AI: from chatbot to agent platform

- **Removed** the Ollama/LFM2.5 local-AI sidecar (the `ai_tab`, model
  runtime, GPU requirement). The old "AI assistant" could only chat.
- **Added** a full **CLI** (`autobahn-defender <verb>`): scan,
  scan-processes, cve, patches, audit, checks, alerts, quarantine, network,
  intel, watch, remediate, defs, rules, apply, doctor, mcp. JSON envelopes
  (`schema_version`), stable exit codes (0 clean / 1 findings / 2 error),
  `--no-input`, `NO_COLOR`, BrokenPipeError → 141.
- **Added** the **MCP server** (`autobahn-defender mcp`): stdio JSON-RPC,
  11 tools mapping 1:1 to CLI verbs. Destructive tools require a one-time
  confirm token issued by `plan` (read-before-write).
- **Added** the **AI Agent tab**: connect Hermes/Claude/OpenClaw in seconds,
  live MCP test button, per-host copy-paste setup commands, and a permission
  matrix (`~/.autobahn/mcp_policy.json`): Off / Read-only / Full(+categories).
  The policy is enforced *inside* the MCP server on every call; mode=off
  refuses to start.
- **Added** `docs/AGENTS.md` — the MCP integration guide for agents.

## 2. CVE / vulnerability matching: rebuilt on real data

- **Fixed the root cause of stale alerts**: the OSV `querybatch` endpoint
  returns only `{id, modified}`; the old code extracted `fixed_in` from
  nothing, so every advisory became "no patch available" and 196 stale
  alerts (some CVEs from 2016) piled up forever.
- Advisories are now **individually enriched** from `/v1/vulns/<id>`: real
  per-release fix ranges, drop of misattributed package pairings (OSV index
  pairing bug, e.g. bouncycastle CVEs under binutils), and detection of
  **Ubuntu Pro/ESM-only fixes** (reported honestly as
  "fix exists but requires `sudo pro attach`", `patch_available=false`).
- Installed >= fixed ⇒ not affected (Debian-policy version comparison,
  apt_pkg-validated; Mint mapped to its Ubuntu base with loud warnings).
- **Self-healing alerts**: every intel check re-validates open alerts;
  CVEs that no longer match installed packages are auto-resolved
  (`resolution_note` recorded; user-created alerts untouched).
- CVE severity = CVSS 3.1 score (spec-exact parser), not keyword guesses.
- False-positive filter (Kudu-derived, MIT): suppressed disputed glibc CVEs,
  misattributed package families, installed >= fixed, >3-year unfixed,
  cross-branch mismatches.

## 3. Remediation & verification

- Lifecycle: contain (mask/unmask) → update → verify → restore.
- One-time confirm tokens for every write (read-before-write contract).
- **verify is honest**: unreachable CVE feed ⇒ `inconclusive`, never a
  false "fixed".
- SSH hardening writes a drop-in config instead of editing sshd_config.
- Sysctl hardening reduced from 14 privilege prompts to 2.
- Privileged actions pkexec-gated, review-first.

## 4. Network monitor & blacklist

- Connection monitor matches peers against the blacklist without AI.
- **Bogon-proof**: feeds that ship private ranges (`10.0.0.0/8`, `127/8`,
  CGNAT, multicast) no longer make LAN gateways (e.g. 10.10.10.1) look
  malicious — stripped at download time, scrubbed from cached files, and
  the matcher short-circuits local/loopback/link-local addresses.

## 5. YARA rules: rebuilt for precision

- **16 over-generalized rules rewritten** (4 audit passes) to require
  malware-specific indicators instead of common words ("play", "go",
  "ss/h/udp", "backdoor+agent"…). Rules covered: Mirai (+Jackskid), Kinsing,
  perfctl/perfcc, Play & ESXiArgs ransomware, stratum miners, process
  hiders, container escapes, SSH brute tools, Go/Rust backdoors, webshells.
- Result: **zero false positives** across the entire `/usr/bin` tree
  (before: ~9,400 hits on a stock system), verified with yara-python.
- Detection preserved: synthetic malware for each family still matches.
- One rule disabled honestly (LD_PRELOAD generic — unsalvageable; the
  name-based `Linux_Rootkit_Perfctl_Hider` covers the real case).
- Scanner hard guarantee: **dpkg-owned system files are never
  auto-quarantined** on a YARA match (action=flag); user files unaffected.
- Rules synced across repo `rules/`, the `yara/` auto-update package
  (VERSION bumped), `~/.autobahn/rules`, and the deb/AppImage payloads.

## 6. Intel feeds

- CISA KEV (1,687 entries), Ubuntu USN (10k+ rows), EPSS (366k scores),
  PoC-in-GitHub (**fixed**: moved to the GitHub contents API after the
  upstream README.json layout 404'd; 1,999 CVEs with PoCs in the current
  year alone).
- SQLite store, feed freshness tracked, 24h poll cadence.

## 7. Reliability & correctness

- Engine primitives extracted to `engine/` (GUI, CLI, and MCP share one
  implementation — no more divergent behavior).
- 123-test pytest suite; clean Ubuntu 24.04 container verification (install,
  headless operation, EICAR detection, remediate/defs/rules verbs).
- Headless fixes: `--version/--help` no longer init Qt.
- Undefined-name audit tool (`tools/self_audit.py`, Kudu-inspired) — CLEAN.
- GUI threading: feed/scan results via queued signals; fix-all/verify on
  worker threads.
- Small-window layout fixes (Settings/About word-wrap; Security News rich
  text via item delegate + scrollable body; window min-height for 9 tabs).
- Alert Center went from 196 stale entries to 0 (auto-resolve) with live
  re-checks confirming 0 actual vulnerable packages.

## 8. Packaging

- deb: 1.1 MB (the old experiment builds bundled full venvs and weighed
  1.8–1.9 GB), valid control/postinst/prerm, desktop + icons, 88 files.
- In-app updater: `dpkg -i` failure path now self-repairs via
  `apt-get install -f` before retrying (no more stuck upgrades when deps
  are missing).
- AppImage: docker pyinstaller build, glibc 2.35 compat, updated spec for
  the v2 module tree.
- Arch: `build_arch/PKGBUILD.v2` — source-based package for the 2.0 tree
  (v1.2-era PKGBUILD retired).
- Project hygiene: 25 GB of stale experiment builds removed, `/home/...`
  absolute paths replaced with portable ones, docs consolidated under
  `docs/`.