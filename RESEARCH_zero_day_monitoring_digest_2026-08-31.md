All research verified against live endpoints. Here is the digest.

---

# Real-Time Zero-Day/Vulnerability Monitoring Architecture — Technical Digest

*For Autobahn Defender (PyQt6, Ubuntu/Debian/Mint). All endpoints below were fetched and verified live on 2026-08-30 unless noted.*

## 1. Threat-Intel Feeds (free, no key or free key)

### CISA KEV — the highest-signal feed, zero auth
- **JSON:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (verified: v2026.08.27, 1,685 entries). CSV at the same path `.csv` (currently 403 to curl due to Akamai bot rules — use the JSON, or the mirror repo).
- **Mirror (git-friendly):** `https://github.com/cisagov/kev-data` — auto-updated on every KEV release (commits verified: "Add Updated KEV Files for 2026-08-28"). Schema: `https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities_schema.json`.
- **Cadence:** updates whenever CISA adds entries — typically several times/week (catalogVersion is a date string like `2026.08.27`).
- **Schema** (verified): top-level `{title, catalogVersion, dateReleased, count, vulnerabilities[]}`; each entry: `cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes[], cwes[]`. Poll daily; diff on `dateAdded`.

### OSV.dev — your CVE-match backend (already in Autobahn Defender)
- **Batch:** `POST https://api.osv.dev/v1/querybatch` with `{"queries":[{"package":{"ecosystem":"Ubuntu:22.04:LTS","name":"openssl"},"version":"3.0.2-0ubuntu1.12"}]}` — verified working; returns `{results:[{vulns:[{id,modified}]}]}` with `UBUNTU-CVE-*` IDs; hydrate via `GET https://api.osv.dev/v1/vulns/{id}`.
- **Limits:** docs at `https://google.github.io/osv.dev/api/` state verbatim: *"Currently there are no limits on the API"*; response size cap 32 MiB on HTTP/1.1, none on HTTP/2 (use HTTP/2). No key. Published SLOs: querybatch P50 ≤ 500 ms (`https://osv.dev/blog/posts/api-latency-improvements-and-revised-slos/`).
- **Schema:** `https://ossf.github.io/osv-schema/`.

### GitHub Advisory Database
- **REST (no auth):** `https://api.github.com/advisories?per_page=100&sort=published&direction=desc&ecosystem=PIP` — verified. **60 req/hr unauthenticated** per `x-ratelimit-limit` header observed; 5,000/hr with a free PAT. Docs: `https://docs.github.com/en/rest/security-advisories`.
- **Fields (verified):** `ghsa_id, cve_id, cvss, cvss_severities, severity, ecosystems, published_at, references[], vulnerabilities[], withdrawn_at` — and notably **`epss` is embedded per-advisory**, so one call gets you CVE+CVSS+EPSS together.
- Also cloneable as data: `https://github.com/github/advisory-database`.

### EPSS (FIRST.org) — prioritization layer
- **API (no key):** `https://api.first.org/data/v1/epss?cve=CVE-2024-3400` — verified: `{"cve":"CVE-2024-3400","epss":"0.999990000","percentile":"1.000000000","date":"2026-08-30"}`. Supports comma-separated CVE lists and `date` history. Docs: `https://api.first.org/epss/` (a "Rate Limit" section exists; no numeric limit is published — don't hammer it).
- **Bulk dump (the right way):** `https://epss.cyentia.com/epss_scores-current.csv.gz` (301 → `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`; verified 366,358 rows, header comment `#model_version:v2026.06.15`, columns `cve,epss,percentile`). Download daily, join locally — no API calls at all.

### Ubuntu USN / OVAL / OSV
- **Notices JSON (verified):** `https://ubuntu.com/security/notices.json` — `{notices:[], offset, limit, total_results}`; each notice: `id, title, published, cves[], cves_ids, releases, release_packages, references, related_notices, type`. 10 per page; paginate with `?offset=` (also `?release=` filters — HTML only, so use offset on the bare JSON).
- **RSS:** `https://ubuntu.com/security/notices/rss.xml` (verified, 10 latest items).
- **OVAL (verified live, 10.5 MB):** `https://security-metadata.canonical.com/oval/com.ubuntu.jammy.cve.oval.xml.bz2` (per-release; the `/oval/v2/` path is dead). Canonical OVAL docs: `https://documentation.ubuntu.com/security/security-updates/oval/`.
- **Ubuntu OSV export (verified, 41.7 MB tar.xz, refreshed ~daily):** `https://security-metadata.canonical.com/osv/osv-all.tar.xz` — all releases as OSV JSON; per-file examples in `https://github.com/canonical/ubuntu-security-notices`. Docs: `https://documentation.ubuntu.com/security/security-updates/osv/`. This is the *cleanest* machine-readable Ubuntu source — one download, diff locally, no API.

### Debian (for Debian/Mint users)
- **DSA RDF (verified):** `https://www.debian.org/security/dsa.rdf` (RSS 1.0/RDF, ~31 entries).
- **Full tracker JSON (verified, 87 MB):** `https://security-tracker.debian.org/tracker/data/json` — package→CVE map for all releases; heavy, cache it.

### PoC / exploit feeds
- **PoC-in-GitHub:** `https://github.com/nomi-sec/PoC-in-GitHub` — README organized by year → CVE → links to each PoC repo, auto-collected daily (verified 2026 entries). Parse the README or the `README.json` style per-year files; or `git pull` daily and diff.
- **trickest/cve:** `https://github.com/trickest/cve` — "almost every public CVE PoC," per-year markdown + `hot_cves.csv` (verified).
- Strategy: intersect PoC-feed CVEs with installed packages; "public PoC exists + I run the vulnerable version" = top-priority alert.

### NVD API 2.0 — status 2025–2026 (use as fallback only)
- **Endpoint (verified working unauthenticated, ~1.2 s):** `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`
- **Rate limits:** 5 requests / rolling 30 s without a key; **50 / 30 s with a free key** (`https://nvd.nist.gov/developers/request-an-api-key`; also confirmed via `https://github.com/wazuh/wazuh/issues/16555` and `https://scanrook.io/blog/nvd-api-key-guide`).
- **2026 status:** NIST formally abandoned full-enrichment-of-every-CVE on **2026-04-15**, moving to risk-based triage; the pre-2026-03 backlog was moved to "Not Scheduled" (**KEV CVEs are always enriched**) — `https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth`. Consequence: **don't build on NVD as your primary feed**; OSV + KEV + EPSS cover you better, and NVD's own KEV enrichment note means KEV data is never stale.

### Vulners
- Could not verify a free tier: `vulners.com` sits behind Cloudflare (403 from scripts), and the site now advertises "free trial" + paid plans for API/SDK. Treat as commercial; skip for a free desktop tool. (Alternative aggregator seen in research: `https://defend.network/api/` — free daily JSON merging CVSS+EPSS+KEV; not yet verified.)

## 2. Runtime Detection Architectures

| | eBPF (Falco/Tracee/Tetragon) | auditd (Wazuh/auditd-tools) | inotify / fanotify (user-space) |
|---|---|---|---|
| **Privilege** | Root or heavy caps: Falco modern probe needs `CAP_SYS_BPF, CAP_SYS_PERFMON, CAP_SYS_RESOURCE, CAP_SYS_PTRACE`; Tracee needs `CAP_SYS_RESOURCE` + (`CAP_BPF`+`CAP_TRACING` on ≥5.8, else `SYS_ADMIN`) | auditd runs as root daemon; **consumers need nothing** — events fan out to plugins/socket | inotify: unprivileged but per-user watch limits (default 8,192); fanotify: `CAP_SYS_ADMIN` for init, root for permission events |
| **Kernel reqs** | Falco modern eBPF: "no specific version, all ≥5.8 in practice" — needs BPF ring buffer + kernel BTF (`https://falco.org/docs/concepts/event-sources/kernel/`); Tracee: **≥5.4** (`https://aquasecurity.github.io/tracee/v0.19/docs/install/prerequisites/`); older kernels need BTFHub or per-kernel builds | Mainline since 2.6; every Ubuntu/Debian kernel | inotify: 2.6.13+; fanotify: 3.8+ with `CONFIG_FANOTIFY=y` |
| **Overhead** | Very low (in-kernel filtering; ~1–5% typical, ring-buffer delivery) | Low-moderate: rule matching in kernel, formatting in user-space; audit log I/O | inotify cheap per-watch but scales poorly; fanotify near-zero |
| **Sees** | All syscalls system-wide + kprobes (file, exec, net, mem) | Syscalls via audit rules (`-w` watches, `-a` rules), who-data attribution | File events only (inotify); file open/access (fanotify) |
| **Stability risk for a desktop app** | Medium — verifier keeps it safe, but caps/BTF quirks across Mint's mixed kernels; ships as a separate signed engine | **Low** — auditd is a distro service; your app is just a socket reader | **Lowest** — pure user-space, no caps |

**Rules** (verified from `https://github.com/falcosecurity/rules/blob/main/rules/rules_default.yaml` and Sysdig's example):
```yaml
# Exec from /tmp-like locations (real default rule):
- rule: Execution from /dev/shm
  condition: >
    spawned_process
    and (proc.exe startswith "/dev/shm/"
     or (proc.cwd startswith "/dev/shm/" and proc.exe startswith "./")
     or (shell_procs and proc.args startswith "-c /dev/shm"))
    and not container.image.repository in (falco_privileged_images, trusted_images)
  output: File execution detected from /dev/shm | file=%fd.name proc_cwd=%proc.cwd ...
  priority: WARNING

# ld.so.preload hijack (Sysdig-documented classic):
- rule: Modify ld.so.preload
  desc: Detect an attempt to write to file /etc/ld.so.preload
  condition: open_write and fd.name=/etc/ld.so.preload
  priority: WARNING
# Default file also ships macros like: - macro: etc_dir → (fd.name startswith /etc/)
```
Source: `https://falco.org/docs/reference/rules/default-rules/`, `https://sysdig.com/blog/unveil-processes-falco-cloud/`.

**Yes — a Python app can consume these without shipping any kernel driver:**
- **auditd route (recommended):** the `audisp-af_unix` plugin ships in the standard auditd package and writes the raw event stream to a **UNIX domain socket** your Python app simply reads: config `/etc/audit/plugins.d/af_unix.conf` (`args = 0640 /var/run/audisp-events` — mode + path). Docs: `https://manpages.debian.org/trixie/auditd/audisp-af_unix.8.en.html`, plugin framework `https://www.man7.org/linux/man-pages/man5/auditd-plugins.5.html`. Reference Python parsing: `https://github.com/jhb/auditd_tools` / `https://pypi.org/project/auditd-tools/`. You add your own audit rules (`auditctl -w /etc/ld.so.preload -p wa -k preload_hijack`), then match `key=` in the stream. No kernel code, no caps, works on every target distro. (This is exactly how Wazuh's FIM "who-data" mode works — `https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html` — realtime mode there is plain inotify.)
- **Falco route:** run Falco as a separate daemon with `json_output: true` and its gRPC outputs server over a **Unix socket (no auth, no TLS needed locally)** — `https://falco.org/docs/concepts/outputs/`, `https://github.com/falcosecurity/falco-exporter`. Your PyQt6 app subscribes to the socket and renders alerts. You depend on Falco's packaging (`apt`/DEB from `https://falco.org/docs/getting-started/installation/`), not on writing eBPF.
- **Tracee** can emit JSON/`--output json:` to stdout/file (`https://github.com/aquasecurity/tracee`) — pipe or file-tail it. Heavier; aimed at containers.

**Fit for Autobahn Defender:** PyQt6 app must never destabilize the host → **auditd-plugin consumption + inotify for $HOME + optional Falco integration if installed**. eBPF-only-own-driver is the one thing not to build yourself (BTF matrix across Mint 21/22 + Ubuntu 20.04+ kernels is a support tar pit; kernel module would be worse).

## 3. How Desktop AVs Do Real-Time Monitoring

**ClamAV (your engine) — on-access via fanotify, documented at `https://docs.clamav.net/manual/OnAccess.html`:**
- Requires **Linux kernel ≥ 3.8 with fanotify**, and for *blocking* (prevention) `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y` (check: `grep FANOTIFY /boot/config-$(uname -r)`). Without ACCESS_PERMISSIONS it still works in **notify-only mode** (scans + alerts, cannot block).
- Architecture: two processes — `clamd` (scanner daemon) + `clamonacc` (on-access client that registers fanotify marks and feeds clamd over `LocalSocket`/TCP). **Both must run elevated (`sudo clamd` / `sudo clamonacc`)** — fanotify initialization requires root; clamonacc additionally needs curl ≥ 7.45.
- Key `clamd.conf` options: `OnAccessIncludePath /home/user/Downloads` (recursive; uses the DDD/inotify scheme — raise `fs.inotify.max_user_watches`, default 8,192, to e.g. 524,288), `OnAccessPrevention yes` (blocks via fanotify "Operation not permitted"), `OnAccessExcludeUname clamav` (avoid self-scan loops), `OnAccessExcludeRootUID yes`, `OnAccessMaxFileSize`, `OnAccessMountPath` (mount-level watching; incompatible with `OnAccessPrevention` and the DDD options — docs warn `/` + prevention = system lockup; `OnAccessIncludePath /` is rejected outright for the same reason).
- **Dazuko is dead history:** ClamAV pre-2016 needed the Dazuko third-party kernel module; fanotify replaced it (`https://blog.clamav.net/2016/03/configuring-on-access-scanning-in-clamav.html`). Modern ESET/Sophos likewise: ESET used Dazuko historically, now fanotify on supported kernels (`https://www.av-comparatives.org/tests/linux-security_review_2015/`); Sophos ships its own intercept layer ("Talpa") with fanotify as the fallback kernel interface when Talpa doesn't match the kernel (`https://techvids.sophos.com/watch/hcr99jzszE3d5EfDLP1f5m`). **The industry answer is fanotify + a root daemon — no vendor ships a loadable kernel module as primary path anymore.**
- For your app: don't run on-access as part of the GUI. Ship a systemd unit that runs `clamd` + `clamonacc` (root, `_apt`-style dedicated user excluded via `OnAccessExcludeUname`), default `OnAccessIncludePath` to `~user/Downloads`, `~user/.cache`, and `/tmp`, and let the PyQt6 app surface events by tailing clamd logs / `clamonacc --log` or via your own alert DB. Detection is your existing ClamAV+YARA stack — on-access is purely a *delivery mechanism*.

## 4. "Zero-Day" Honesty: What a Local Tool Can and Cannot Detect

- **Terminology (Project Zero, `https://projectzero.google/0day.html`; Google TAG time-to-exploit study, `https://cloud.google.com/blog/topics/threat-intelligence/time-to-exploit-trends-2023`):** a *0-day* is exploited before a patch exists; an *n-day* is exploited after the fix is public. In TAG's 2023 in-the-wild set, 97 were 0-days vs 41 n-days, and ~30% of the analyzed set saw first exploitation only *after* public disclosure. **A local feed-driven tool detects n-days, never 0-days** — by definition, there is no CVE, no KEV entry, no patch for a true 0-day at exploitation time.
- What feeds give you is **fast n-day defense**: KEV dateAdded + USN publication + PoC-in-GitHub appearance typically land within days of disclosure, so "installed vulnerable version + KEV/PoC hit → update now" closes the window that TAG data shows attackers exploit in the first 30 days.
- What *runtime* detection gives you for actual 0-days is **post-exploitation behavior matching**: exec from `/tmp`/`/dev/shm`, `/etc/ld.so.preload` writes, hidden kernel modules, memfd fileless exec (all real Falco default rules). These catch the *consequences* of a novel exploit, not the exploit itself — and they false-positive on legitimate admin activity, so they belong in an alert-center, not an auto-block.
- Be honest in the UI: label the feature "exploited-vulnerability & behavior monitor," not "zero-day protection." A single-user desktop box has no realistic pre-auth network surface for a *local* tool to inspect; the honest threat model is: malware landing in ~/Downloads (fanotify+ClamAV covers it), package n-days (feeds cover it), and post-exploitation anomalies (auditd/eBPF rules cover it, imperfectly). YARA can catch known malware families including 0-day *variants* that re-use family code — that's the one place "zero-day" is semi-legitimate marketing.

## 5. Recommendations (effort → value)

1. **[Tiny effort / high value] Daily intel poller:** KEV JSON + Ubuntu `osv-all.tar.xz` (or `notices.json` RSS) + EPSS CSV bulk + PoC-in-GitHub diff → local SQLite; alert when an installed package version matches a KEV/USN/PoC CVE. All keyless, all verified, ~1 MB/day. Do this first; it *is* the "zero-day monitor" 90% of users actually need.
2. **[Small / high] clamonacc systemd unit** with fanotify on `~/Downloads`, `/tmp` (notify-only default, opt-in prevention), events surfaced in the alert center. Reuses your ClamAV+YARA engine; root stays in a service, GUI stays unprivileged.
3. **[Small / medium-high] audisp-af_unix consumer:** ship a `plugins.d` config + a few `auditctl` rules (ld.so.preload, /etc/passwd & ssh keys, systemd unit creation, execve from /tmp) and parse the socket in Python. No kernel code, no caps, distro-supported.
4. **[Medium / medium] Falco optional integration:** detect installed Falco, enable its gRPC Unix-socket outputs, subscribe and render. Big rule corpus for free; costs you only an adapter.
5. **[Don't build] own eBPF probes or any kernel module** — BTF/kernel matrix + caps are a support disaster for a desktop app; and **don't build on NVD API 2.0** as primary (5 req/30 s unauth, enrichment now triage-only).
6. **[Skip] Vulners** (commercial/Cloudflare-walled).

---

**Summary for parent:**
- **Did:** web research only (per task); worked around broken `web_extract` (misconfigured ddgs-only backend — per `hermes-web-tools-maintenance` skill, curl via terminal is the sanctioned fallback) by curl-testing every endpoint live.
- **Found:** all key feeds verified working keyless (KEV 1,685 entries; OSV batch incl. `Ubuntu:22.04:LTS` ecosystem; GitHub Advisories unauth 60/hr w/ embedded EPSS; EPSS API + 366k-row bulk CSV; Ubuntu notices.json/rss/OVAL/osv-all.tar.xz; Debian dsa.rdf + 87 MB tracker JSON; PoC-in-GitHub/trickest). NVD works but is rate-limited (5/30s unauth) and moved to triage-only enrichment Apr 2026 → demote to fallback. Runtime: auditd `audisp-af_unix` socket + inotify + optional Falco gRPC is the right Python-friendly stack; own eBPF/kmod rejected. ClamAV on-access = fanotify (≥3.8, `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`, root `clamd`+`clamonacc`, OnAccess* options documented). Zero-day honesty: local tools detect n-days via feeds + post-exploit behavior only; recommend renaming the feature accordingly.
- **Files created:** none in the repo (research only); scratch files under `/tmp` (`kev.json`, `falco_rules.yaml`, `onaccess.md`, etc.).
- **Issues:** `web_extract` unavailable (no API-key backend configured on this box — environmental, not fixable in-task); Vulners unverifiable behind Cloudflare (403); CISA CSV endpoint 403s to curl (JSON + kev-data mirror work fine). Digest above is ~2,450 words with cited URLs.