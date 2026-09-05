# Autobahn Defender — Guide for AI Agents & Scripts

Autobahn Defender 2.0 ships a full CLI (`autobahn-defender`) and an MCP
stdio server (`autobahn-defender mcp`) so agents can drive everything.
This is the contract. Stable across 2.x.

## Invocation

```
autobahn-defender <verb> [args] [--format table|json|ndjson|markdown|html] [-o FILE] [-q] [--timeout S] [--yes]
```

The same binary launches the GUI when run bare or from the menu.
Every verb also exists as an MCP tool (`autobahn-defender mcp`, tools
prefixed `autobahn.`); prefer MCP for interactive agents, prefer
`--format json` for pipelines.

## Exit codes (contract — scripts branch on these)

| code | meaning |
|------|---------|
| 0    | completed, no findings |
| 1    | completed, findings present (or `--fail-on SEV` threshold met) |
| 2    | operational failure (engine/network/timeout) |
| 64   | usage error |
| 130  | interrupted (SIGINT) |

JSON `status` field is ground truth ("ok"/"error"); exit code is a coarse signal. A scan WITH findings is a successful scan (findings are the product) — same convention as osv-scanner/trivy, opposite of grep.

## JSON envelope (schema_version 1 — additive changes only)

```json
{
  "schema_version": 1,
  "tool": "autobahn-defender",
  "version": "2.0.1",
  "command": "cve",
  "created": "2026-08-31T12:00:00+00:00",
  "status": "ok",
  "degraded": false,
  "warnings": [],
  "summary": {"ecosystem": "Ubuntu:24.04", "vulnerabilities_found": 3},
  "results": [ ... ]
}
```

Every finding carries stable IDs: `check_id` (AD-XXX-NNN) and/or `cve_id`.
jq examples:

```bash
autobahn-defender cve --format json | jq -r '.results[] | [.cve_id,.app_name,.severity] | @tsv'
autobahn-defender audit hardening --format json | jq '.summary.score'
autobahn-defender intel show --format json | jq -r '.results[] | select(.exploited==true) | .cve_id'
autobahn-defender watch once --format ndjson | jq -c 'select(.severity=="CRITICAL")'
```

## Rules for agents

1. Don't parse human tables — use `--format json`.
2. Exit 2 = "did not complete": fix the condition and re-run, don't treat as findings.
3. Privileged verbs (`apply`, `patches apply`, `quarantine delete`) refuse
   bare `--yes`; use the GUI review dialog, or read the plan first
   (`remediate plan` → token → execute) — never chain blindly.
4. Network verbs take `--timeout SECONDS`. Always set one.
5. Sandboxed environments: scan fixture dirs, never `/`.
6. Severity enum is fixed: CRITICAL|HIGH|MEDIUM|LOW|INFO|UNKNOWN.
7. `verify` statuses: `resolved` / `still_vulnerable` / `inconclusive` —
   "inconclusive" (no OSV data) is NOT resolved; keep alerts open.

## Verb map (GUI button → CLI)

| GUI | CLI |
|---|---|
| Scan (all types) | `scan [paths] [--quick]` |
| Process scan | `scan-processes` |
| CVE scan / track / fix-all / verify | `cve` · `patches check|verify|apply` |
| 4 audit buttons | `audit full|vuln|network|hardening` |
| Hardening apply buttons | `apply apparmor|fw-enable|fw-disable|sysctl|ssh` |
| Network watch | `network connections|download-blacklist|persistence|hosts` |
| Security News / zero-day watch | `intel poll|show|status` |
| Defs / YARA update | `defs update`, `rules update` |
| Quarantine | `quarantine list|restore|delete` |
| Alerts resolve/dismiss | `alerts resolve|dismiss <id>` |
| Self-check | `doctor` |
| AI tool server | `mcp` |

## MCP

Register `autobahn-defender mcp` as an MCP command server. 12 tools mirror the
CLI (initialize → tools/list → tools/call). Destructive tools require a
one-time `confirm_token` from `autobahn.remediate.plan` — read before write.

`autobahn.scan` runs file/folder/drive scans as DETACHED jobs (v2.0.1):
`{"action":"start","paths":["/some/dir"]}` → job id instantly; the worker
survives host disconnect. `status`/`tail` give live progress + the file
trail; `wait {job_id}` blocks until done and returns the full result
envelope; `cancel {job_id}` stops cooperatively. Real threats are
quarantined (SHA256 ledger-bound, GUI parity); distro-owned files are only
flagged for review.

`autobahn.cve.scan` default serves the last completed scan instantly and
auto-restarts a detached background refresh when missing/stale (LM Studio's
bridge kills requests at 60 s; live scans take minutes). Pass
`{"refresh": true}` to force a blocking live scan on long-timeout hosts.