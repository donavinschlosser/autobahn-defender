# CLI Design Conventions for Security Tools + AI-Agent-Friendly CLIs
**Technical digest for Autobahn Defender** (PyQt6 Linux AV app; deterministic Python `engine/` package; CLI must serve humans *and* AI agents, run on stock Ubuntu/Mint python3.11 with zero pip installs). All URLs verified live during research.

---

## 1. Exit codes: findings vs. errors

The core problem: a scanner has **three** outcomes scripts/agents must distinguish — clean, findings, and failure — but POSIX gives no standard slot for "findings."

### What real scanners do

| Tool | Exit convention | Notes |
|---|---|---|
| **clamscan** | `0` no virus, `1` virus(es) found, `2` error occurred | The classic AV tri-state. Man page: https://linux.die.net/man/1/clamscan (also https://man.archlinux.org/man/clamscan.1, https://manpages.debian.org/testing/clamav/clamscan.1.en.html) |
| **grep** | `0` match selected, `1` no match, `2` error | The "findings-as-success" pattern — but note grep inverts: findings=0. https://www.gnu.org/software/grep/manual/grep.html#Exit-Status |
| **rkhunter** | `0` clean; **non-zero if any error *or* warning** — does NOT separate findings from failures | https://man.he.net/man8/rkhunter — an anti-pattern: agents can't tell "rootkit found" from "config unreadable." |
| **lynis** | `0` normal, `1` fatal, `64` unknown param, `65` incorrect data, `66` can't open file/dir, `78` warnings found (**only with `error-on-warnings=yes`**) | https://manpages.ubuntu.com/manpages/bionic/man8/lynis.8.html — sysexits(64-78) style + an opt-in "findings → nonzero" switch. Default `error-on-warnings=no`: https://raw.githubusercontent.com/CISOfy/lynis/master/default.prf |
| **trivy** | **`0` always on completed scan, even with findings**; `--exit-code 1` opts into failing on findings (works with `--severity` filter); `--exit-on-eol N` separate code for EOL OS | https://trivy.dev/docs/latest/guide/configuration/others/ — "By default, Trivy exits with code 0 even when security issues are detected. Use the --exit-code option if you want to exit with a non-zero exit code." Known pain point (overloaded flag): https://github.com/aquasecurity/trivy/issues/2144, https://github.com/aquasecurity/trivy/discussions/7915 |
| **gitleaks** | `--exit-code int` — "exit code when leaks have been encountered (default **1**)"; `0` no leaks; errors use Go/cobra defaults | README: https://github.com/gitleaks/gitleaks |
| **semgrep** | `0` ran clean (or findings without `--error`); `1` findings found (only with `--error`); `2` failure; `3` invalid syntax (`--strict`); `4` invalid pattern; `5` invalid YAML; `7` invalid rule; `8` unsupported language; `13` invalid API key | https://docs.semgrep.dev/cli-reference — grep-style default + opt-in exit-1-on-findings + rich error taxonomy |
| **osv-scanner** | Most explicit scheme: `0` packages scanned, no vulns; `1` vulns/findings found; **`1–126` reserved for vulnerability-result-related errors**; `127` general error; `128` no packages found; **`129–255` reserved for non-result-related errors** | https://google.github.io/osv-scanner/output/ (Return Codes section) |
| **Nagios plugins** | `0` OK, `1` WARNING, `2` CRITICAL, `3` UNKNOWN; single-line output on **stdout only** ("Nagios does not capture stderr"); standard flags `--help --version --timeout --warning --critical` | https://nagios-plugins.org/doc/guidelines.html |

### Shell-reserved codes to avoid colliding with
From https://shapeshed.com/unix-exit-codes/ (and Bash docs): `2` misuse of shell builtins, `126` command not executable, `127` command not found, `128` invalid exit arg, `128+n` killed by signal n (e.g. `130` = Ctrl-C/SIGINT). Never emit 126/127/128+ yourself — the calling shell will misinterpret them. sysexits.h values (64–78) are the other well-known namespace: https://manpages.ubuntu.com/manpages/bionic/man8/lynis.8.html shows a security tool actually using them.

### Recommendation
Follow the **ClamAV/OSV-Scanner tri-state, not grep, not rkhunter**:
- `0` = scan completed, **no findings** (clean)
- `1` = scan completed, **findings present**
- `2` = scan did NOT complete (operational error — bad path, DB unreadable, network down, timeout)
- Add `--fail-on <severity>` (or `--exit-code 1`) for CI-gate semantics à la trivy/gitleaks, and reserve OSV-style bands if you need finer codes: findings-related codes below 64, operational errors 64–125 (sysexits style), never 126–255.

Document the table in `--help` and man page. Scripts branch on `rc==0|1|2`; AIs read the JSON `status` field as ground truth and use exit code only as coarse signal. A "findings found" run is a **successful scan** — the findings are the product, which is why trivy defaults to 0 and why osv-scanner/semgrep/gitleaks make exit-1-on-findings either the default for a *detection* tool (gitleaks: leaks = the thing you asked about) or opt-in for a *gate*.

---

## 2. Machine-readable output

### The `--format` convention
Two idioms coexist:
- `--json` boolean flag (semgrep `--json`, `--sarif`; gitleaks `--report-format json|sarif|csv|junit`)
- `--format <kind>` choice flag (trivy, osv-scanner)

The **choice-flag is winning** because scanners need multiple machine formats. Verified inventories:
- **trivy**: `--format table|json|sarif|cyclonedx|spdx-json|template|github` + `--output/-o FILE`. Docs: https://trivy.dev/v0.58/docs/configuration/reporting/ (snippet: `$ trivy image --format json --output result.json debian:12`, `$ trivy image --format sarif -o report.sarif golang:1.12-alpine` — SARIF uploadable to GitHub code scanning). JSON schema repo: https://aquasecurity.github.io/trivy-schemas/
- **osv-scanner v2**: `--format table|vertical|markdown|html|json|sarif|spdx-2.3|cyclonedx-1.4|cyclonedx-1.5`, plus `--output-file`, `--serve` (local HTML on :8000), `--verbosity`. Docs: https://google.github.io/osv-scanner/usage/ and https://google.github.io/osv-scanner/output/
- **semgrep**: `semgrep scan --config p/default --json > results.json`, `--sarif` for GitHub Code Scanning; versioned JSON schema (`semgrep_output_v1.jsonschema`, see https://pkg.go.dev/github.com/BacchusJackson/go-semgrep); JSON/SARIF field reference: https://docs.semgrep.dev/cli-reference (page "JSON and SARIF fields")

### SARIF for scanners
SARIF v2.1.0 is the OASIS standard interchange for static-analysis results (rules + results + locations + severity): https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html. osv-scanner maps each vulnerability (grouped by aliases) to a SARIF *rule* with CVE id as `rule.id` and remediation text embedded (https://google.github.io/osv-scanner/output/). GitHub code-scanning ingestion is the practical reason to emit it.

### jq-friendliness rules (distilled from trivy/osv JSON shapes)
1. **One JSON document on stdout per run** — not mixed with logs (logs to stderr; trivy does exactly this: INFO/WARN lines go to stderr even in table mode).
2. **Top-level envelope**: `{"schema_version": "1.x", "created": "<ISO8601>", "results": [...], "summary": {"totals": {...}}}` — agents grep/jq the envelope first: `jq '.results | length'`.
3. **Flat, stable field names** in `snake_case`; severity as fixed enum (`CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN` — trivy/osv vocabulary).
4. **Every finding carries stable IDs**: CVE/GHSA id, check id, rule id (see §4).
5. NDJSON (newline-delimited JSON, one object per line, UTF-8): https://jsonlines.org/ — the format for *streaming* progress events and for tailing JSONL alert logs (`adengine monitor --format ndjson | jq -c 'select(.event=="alert")'`). Document: each line self-contained, no pretty-printing, `\n` terminated.

### Schema stability/versioning
- Put `schema_version` **inside the document** (trivy uses a top-level `SchemaVersion` int; semgrep versions the whole schema as `semgrep_output_v1`).
- Semver the schema; additive changes bump minor, removals/renames bump major and land behind a `--format json@2` or `--schema-version` escape hatch.
- Publish JSON Schema files (trivy: https://aquasecurity.github.io/trivy-schemas/) so agents/CI can validate before parsing.
- Never mix human prose into stdout when `--format json` is active; error messages still go to stderr as JSON or plain text — but the *document* stays parseable.

---

## 3. Python CLI framework under a zero-dependency constraint

**Constraint: stock Ubuntu/Mint python3.11, no pip.** That decides it:

- **argparse** — stdlib, always present. `add_subparsers()` gives git-style verb trees, `parents=` gives shared global-flag parsers, `argparse.BooleanOptionalAction` (3.9+) gives `--json/--no-json`, formatter classes control help layout. Docs: https://docs.python.org/3/library/argparse.html. Ubuntu's own CLI tooling (e.g. `ubuntu-advantage`, `distro-info`, many debhelper scripts) is argparse-based for exactly this reason; Debian policy forbids gratuitous runtime deps (https://www.debian.org/doc/packaging-manuals/python-policy/).
- **click** — third-party, decorator-based, arbitrary nesting, auto-help (https://click.palletsprojects.com/). Needs pip/apt `python3-click`.
- **typer** — click + type hints, "FastAPI of CLIs" (https://typer.tiangolo.com/); even `typer-slim` still pulls click. Not available on a stock box.

**Verdict: argparse is the only option that meets the constraint**, and it's what distro-packaged Python CLIs ship with. Cost: more boilerplate than click for nested trees; mitigate with a thin `parent_parser` for globals and a `command_registry` dict. Do *not* vendor click — supply-chain surface for an AV product is unacceptable.

### Command structure (git-style verbs)
Follow trivy `trivy <target> [flags] <subject>` (https://github.com/aquasecurity/trivy) and osv-scanner v2's `scan source|image` / `fix` verbs (https://google.github.io/osv-scanner/usage/). gitleaks mirrors it: `gitleaks dir|git|stdin` (https://github.com/gitleaks/gitleaks). semgrep: `scan|ci|lsp|mcp|login|logout|validate` (https://docs.semgrep.dev/cli-reference).

### Global flags (clig.dev + Nagios + pip consensus)
From https://clig.dev/ and https://nagios-plugins.org/doc/guidelines.html:
- `-h/--help`, `-V/--version` (capital V — clamscan, rkhunter convention)
- `--format <table|json|ndjson|sarif|markdown|html>` and `-o/--output FILE`
- `--quiet` / `--verbose` (repeatable `-vvv`, Nagios levels 0–3)
- `--no-color` (plus env: §5) and `--color=auto|always|never`
- `--timeout SECONDS` (Nagios mandates it; agents set it)
- `--config FILE`
- `--yes` / `--no-input` for non-interactive mode (§4)
- pip's model is a good reference for flag/verbosity/no-color UX: https://pip.pypa.io/en/stable/cli/pip/

### stdout vs stderr (CI/agent-friendly)
clig.dev, verbatim: "Send output to stdout. The primary output … Anything that is machine readable should also go to stdout. Send messaging to stderr. Log messages, errors, and so on should all be sent to stderr." (https://clig.dev/#output). Nagios adds: stdout should carry the one-line status, stderr is not captured by monitors. trivy in practice: scan report on stdout, timestamped INFO/WARN logs on stderr.

For a scanner: **report/JSON on stdout; progress bars, per-file ticks, warnings, and errors on stderr.** Then `av scan / --format json | jq` works while `av scan / 2>progress.log` still shows a spinner.

---

## 4. How AI coding agents consume CLIs

### MCP server pattern
Model Context Protocol = JSON-RPC 2.0 (https://www.jsonrpc.org/specification) over **stdio**: client launches server as a subprocess; server reads requests from stdin, writes responses to stdout, **one JSON message per line, no embedded newlines**; "The server MAY write UTF-8 strings to its standard error (stderr) for logging … The server MUST NOT write anything to its stdout that is not a valid MCP message." Spec: https://modelcontextprotocol.io/specification/2025-06-18/basic/transports (transports: stdio + Streamable HTTP). Tools are discovered via `tools/list` (servers SHOULD return tools in **deterministic order** — https://modelcontextprotocol.io/docs/concepts/tools) and invoked via `tools/call` with JSON-Schema-typed inputs.

Practical notes for Autobahn Defender:
- **`av mcp` subcommand** wraps the same engine calls the CLI verbs use — one codebase, two front-ends. Precedent: `semgrep mcp` ships as a first-class subcommand (https://docs.semgrep.dev/cli-reference; server repo https://github.com/semgrep/mcp). MCP-only servers (osv-scanner community, trivy plugins) exist, but a CLI that *also* speaks MCP wins: agents can shell out (`av scan --format json`) or connect (`av mcp`).
- An MCP stdio server is ~200 lines with stdlib only (json, sys, threading) — no SDK dependency needed; the wire format is just newline-delimited JSON-RPC.
- Keep **stdout pristine** in `mcp` mode — all engine logging must divert to stderr (this is a hard spec MUST NOT).

### Machine-readable `--help`
- `--help` output is the agent's API doc. clig.dev: display help on `-h`/`--help`, exit 0, include usage/examples. Nagios mandates `--help --version --timeout`. Keep help under ~a screen per verb; document **exit codes and output formats in the top-level help** — that's what an agent reads first.
- Offer `av help scan` and stable verb names; agents script `av --help | grep` to discover capabilities.

### Stable IDs
Agents branch and cross-reference on IDs, never on prose: CVE/GHSA ids in every finding (osv-scanner emits `https://osv.dev/GHSA-…` URLs directly in output — https://google.github.io/osv-scanner/output/); semgrep rules carry `check_id`; trivy findings carry `VulnerabilityID` + `AVD` advisory URLs (e.g. https://avd.aquasec.com/misconfig/ds002). Autobahn's checks registry should expose a public `check_id` (e.g. `AD-SSH-001`) in every line of every format.

### Non-interactive flags
- `--yes/-y` (auto-confirm quarantine/delete), `--no-input` (fail instead of prompting — never hang an agent); clig.dev Interactivity section: don't prompt if stdin isn't a TTY; pip uses `--no-input`: https://pip.pypa.io/en/stable/cli/pip/
- `--timeout` on every network-touching verb (CVE fetch via OSV.dev, update); agents always set one.
- Degrade gracefully when non-TTY: no spinners, no color, no pager.

---

## 5. POSIX conventions checklist

- **Exit codes**: 0 success; 1-125 app-defined; avoid 2-as-"usage" collision with your findings code if you adopt tri-state (use `64` EX_USAGE for bad args instead — sysexits); 126/127/128+ belong to the shell, never emit them. https://shapeshed.com/unix-exit-codes/
- **stderr for errors/diagnostics, stdout for data** (https://clig.dev/#output).
- **SIGPIPE**: when stdout's reader dies (`… | head`), the default Python `BrokenPipeError` path prints an ugly traceback and exits 1. Handle: catch `BrokenPipeError` at top level, `os._exit(0)` (or 141=128+SIGPIPE) after closing fd — the canonical recipe is in Python docs "note on SIGPIPE" (https://docs.python.org/3/library/signal.html) and CPython's own `python -c` behavior. Also `signal.signal(signal.SIGPIPE, signal.SIG_DFL)` pre-main works for simple tools.
- **Color**: disable when (1) stdout or stderr is not a TTY (check each independently — clig.dev), (2) `NO_COLOR` env var set and non-empty **regardless of value** (https://no-color.org/ — "when present and not an empty string (regardless of its value), prevents the addition of ANSI color"), (3) `TERM=dumb`, (4) `--no-color`/`--color=never` passed. Default `--color=auto`.
- **Locale independence**: machine output must be byte-stable across locales — emit JSON with `ensure_ascii=False` but fixed UTF-8, never locale-formatted floats/dates (ISO 8601 UTC), never translate machine formats (translations only for human table output). grep's locale model (LC_ALL > LC_foo > LANG) is the reference for *human* output: https://www.gnu.org/software/grep/manual/grep.html#Environment-Variables
- **Signal exit conventions**: die on SIGINT with 130, SIGTERM handled/cleanup; never trap and exit 0 on a signal (agents read that as success).
- Don't follow symlinks blindly / use full paths for subprocesses (Nagios guidelines' security notes — apt for an AV scanner: https://nagios-plugins.org/doc/guidelines.html).

---

## 6. Concrete command tree for Autobahn Defender

```
av [--config FILE] [--color=auto|always|never] [--no-color]
   [--format table|json|ndjson|sarif|markdown|html] [-o FILE]
   [--quiet|-q] [--verbose|-v…] [--timeout SECONDS] [--version/-V] [--help/-h]

  av scan PATH… [--recursive] [--checks ID…|--skip ID…]
                [--severity CRITICAL,HIGH,…] [--fail-on severity]
                [--max-filesize MB]                # tri-state exits 0/1/2
  av cve   [--host|--file lockfile…] [--package NAME@VER…]
           [--offline] [--fail-on severity]        # OSV.dev queries; cache in ~/.cache/autobahn/
  av audit system|config|services [--profile default|cis|strict]
                [--error-on-warnings]              # lynis-style; writes report + JSONL detail
  av monitor start|stop|status|tail [--interval SEC]
                [--alert-file PATH]                # alerts appended as JSONL; `tail` streams NDJSON
  av quarantine list|restore|delete|export [--id ID] [--yes] [--no-input]
  av update [--db-only|--rules-only] [--dry-run]   # signature/CVE cache refresh
  av report PATH [--since ISO8601] [--format html|markdown|json]
  av checks list|describe [--id AD-XXX]            # stable check registry w/ descriptions + docs URL
  av history [--last N] [--format json]
  av config show|validate|set KEY VALUE
  av mcp                                         # MCP stdio server (JSON-RPC 2.0, tools/list, tools/call)
```

Exit codes (documented in `av --help`):
```
0  scan/operation completed, no findings
1  completed, findings present (or --fail-on threshold met)
2  did not complete (I/O, DB, network, timeout)
64 invalid usage (bad args)          65 data error (unreadable target)
66 couldn't open file/dir            78 warnings-only mode triggered (audit)
130 interrupted (SIGINT)             141 SIGPIPE (piped consumer closed early)
```

---

## 7. Recommendations block

1. **Adopt the tri-state exit convention** (0 clean / 1 findings / 2 operational failure) — ClamAV + osv-scanner lineage. Add `--fail-on <severity>` for CI gates. Never fold findings and errors into one code (rkhunter's mistake); never emit 126–255.
2. **`--format <choice>` not `--json`**, choices `table|json|ndjson|sarif|markdown|html`, with `-o FILE`. JSON always on stdout, logs always on stderr; NDJSON for `monitor tail` streaming.
3. **Embed `schema_version` in every JSON/NDJSON document**; semver it; publish a JSON Schema; additive-only within a major. Stable `snake_case` fields; fixed severity enum; every finding carries `check_id` and CVE/GHSA id + advisory URL.
4. **argparse only** (stdlib; zero pip deps; distro convention). Build verb tree with `add_subparsers(dest='cmd')` + a shared `parents=[global]` parser; `BooleanOptionalAction` for `--json/--no-json` style toggles.
5. **Git-style verbs** (`scan/cve/audit/monitor/quarantine/update/report/checks/history/config/mcp`) mirroring trivy/osv-scanner/gitleaks/semgrep shapes; every verb supports `-h`, `--format`, `--timeout`, `--quiet`.
6. **Ship `av mcp`** — stdio JSON-RPC 2.0, newline-delimited, stdout reserved exclusively for protocol messages, stderr for logs; deterministic `tools/list` order; tools map 1:1 onto verbs. This makes Claude Code/Hermes first-class users with zero extra code paths.
7. **Non-interactive by default when not a TTY**: `--yes`, `--no-input`, no prompts, no spinners, no pager; agents always get a terminating process.
8. **POSIX hygiene**: `NO_COLOR` + per-fd isatty + `TERM=dumb` + `--color` flag (https://no-color.org/, https://clig.dev/); catch `BrokenPipeError` → exit 141; ISO-8601 UTC timestamps; locale-independent machine output; SIGINT→130.
9. **Put the exit-code table, format list, and example jq pipelines in `--help` and the man page** — that's the agent-facing API contract. Stable IDs everywhere (`AD-XXX` check ids, CVE ids, GHSA/osv.dev URLs).
10. **Test the contract**: CI runs `av scan fixture/ --format json | jq -e '.results[0].check_id'` and asserts exit codes 0/1/2 across fixture dirs — the same assertions an agent will make.