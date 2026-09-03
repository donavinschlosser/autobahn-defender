"""Autobahn Defender MCP server (Phase 4) — stdio JSON-RPC 2.0, stdlib only.

Model Context Protocol: clients (Claude Code, Hermes, any MCP host) launch
`autobahn-defender mcp` as a subprocess; requests arrive as newline-delimited
JSON-RPC on stdin, responses go to stdout. stdout carries NOTHING but protocol
messages (spec MUST); all logging → stderr.

Tools mirror CLI verbs 1:1. Destructive tools (remediate/apply) require a
confirm_token issued by a prior plan/request call — read-before-write.
"""
from __future__ import annotations

import json
import sys
import time

from engine.version import APP_VERSION, DATA_SCHEMA_VERSION

PROTOCOL_VERSION = "2025-06-18"


# ── tool implementations (thin wrappers over engine.runner / cli handlers) ──

def _tool_doctor(_: dict) -> dict:
    from engine.checks import CHECKS, run_check
    from engine.paths import APP_DIR, DATA_DIR
    from engine.version import APP_VERSION as V
    bad = []
    for name in sorted({c for c in CHECKS if not c.startswith("_t_")}):
        res = run_check(name, {})
        if res.get("status") == "error" and "is not defined" in str(res.get("error", "")):
            bad.append(name)
    import shutil
    return {
        "version": V,
        "clamscan": bool(shutil.which("clamscan")),
        "pkexec": bool(shutil.which("pkexec")),
        "app_dir_exists": APP_DIR.exists(),
        "data_dir": str(DATA_DIR),
        "checks_undefined_name_errors": bad,
    }


def _tool_checks_list(_: dict) -> dict:
    from engine.checks import list_checks
    return {"checks": sorted({n for n in list_checks() if not n.startswith("_t_")})}


def _tool_check_run(args: dict) -> dict:
    from engine.checks import run_check
    name = str(args.get("check", ""))
    if not name.startswith("check_"):
        name = f"check_{name}"
    return run_check(name, args.get("arguments") or {})


def _tool_cve_scan(args: dict) -> dict:
    """Cache-first by default: a live OSV.dev scan takes minutes and
    short-timeout MCP hosts (LM Studio's stdio bridge = hard-coded 60 s)
    kill the request mid-flight (MCP -32001) — so default serves the last
    completed scan instantly and auto-starts a detached background refresh
    when it's missing/stale. refresh=true = blocking live scan, for hosts
    with generous timeouts (Hermes, CI, direct CLI)."""
    from engine import scan_cache
    if args.get("refresh"):
        return scan_cache.live()
    return scan_cache.auto()


def _tool_audit(args: dict) -> dict:
    """Cache-first for the vuln profile: the audit's vulnerability_scan task
    ran a LIVE OSV query + network patch check inline (bypassing the cve.scan
    cache) — minutes of blocking that 60s-limited hosts (LM Studio) kill, and
    because this server is serial it domino-timed-out every fast tool queued
    behind it (alerts, remediate.plan — observed Sep 4). Default now: CVE data
    from the scan cache, patch check skipped, never blocks. live=true restores
    the full blocking analysis for long-timeout hosts."""
    from engine import runner, scan_cache
    profile = str(args.get("profile", "hardening"))
    mapping = {"full": "full_audit", "vuln": "vulnerability_scan",
               "network": "network_audit", "hardening": "hardening_audit"}
    task_id = mapping.get(profile, profile)
    if task_id == "vulnerability_scan" and not bool(args.get("live")):
        cached = scan_cache.load()
        if cached is not None:
            cve_result = cached.get("result")
            cve_source = "cache"
            try:
                cve_age = max(0, int(time.time() - float(cached.get("stored_at", 0))))
            except Exception:
                cve_age = None
            refresh_started = False
        else:
            cve_result = {"status": "unavailable",
                          "note": "no cached scan yet; live OSV scan started "
                                  "in background — call autobahn.cve.scan "
                                  "again in a few minutes"}
            cve_source, cve_age = "unavailable", None
            refresh_started = scan_cache.start_refresh()
        res = runner.run_audit(task_id, cve_result=cve_result,
                               include_patches=False)
        out = {"score": res.get("score"), "degraded": res.get("degraded"),
               "findings": res.get("findings"), "cve_source": cve_source,
               "refresh_started": refresh_started,
               "patches_skipped": True,
               "note": "vuln audit served cache-first for short-timeout "
                       "hosts; patch-availability check skipped. Pass "
                       "{\"live\": true} for the full blocking analysis."}
        if cve_age is not None:
            out["cache_age_seconds"] = cve_age
        if cve_source == "unavailable":
            out["cve"] = cve_result  # carries the retry guidance verbatim
        return out
    res = runner.run_audit(task_id)
    return {"score": res.get("score"), "degraded": res.get("degraded"),
            "findings": res.get("findings")}


def _tool_intel_poll(args: dict) -> dict:
    from engine import runner
    return runner.run_intel_poll(sources=args.get("sources"))


def _tool_intel_check(_: dict) -> dict:
    from engine.intel.match import check_system
    return check_system()


def _tool_intel_list(args: dict) -> dict:
    from engine.intel.store import recent_alerts
    limit = int(args.get("limit", 40)) if isinstance(args, dict) else 40
    return {"alerts": recent_alerts(limit=limit)}


def _tool_quarantine_list(_: dict) -> dict:
    from engine import runner
    return {"items": runner.run_quarantine_list()}


def _tool_remediate_plan(args: dict) -> dict:
    from engine.remediate import plan_for_alert, request_token
    alert = args.get("alert") or {}
    plan = plan_for_alert(alert)
    if not plan.get("ok"):
        return plan
    tok = request_token(alert, str(args.get("step", "update")))
    return {**plan, "confirm_token": tok.get("token", ""),
            "confirm_step": args.get("step", "update")}


def _tool_remediate_execute(args: dict) -> dict:
    from engine.remediate import execute_step
    token = str(args.get("confirm_token", ""))
    if not token:
        return {"ok": False, "error": "confirm_token required (call remediate.plan first)"}
    return execute_step(token)


def _tool_alerts(_: dict) -> dict:
    from engine import alerts as alerts_mod
    return {"alerts": alerts_mod.load_alerts(active_only=True)}


# ── tool registry (deterministic order — spec SHOULD) ───────────────────────

TOOLS = [
    {
        "name": "autobahn.doctor",
        "description": "Environment/deps self-check for Autobahn Defender.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "autobahn.checks.list",
        "description": "List registered deterministic security checks.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "autobahn.checks.run",
        "description": "Run one security check by name (e.g. check_ssh_audit).",
        "inputSchema": {"type": "object",
                        "properties": {"check": {"type": "string"},
                                       "arguments": {"type": "object"}},
                        "required": ["check"]},
    },
    {
        "name": "autobahn.cve.scan",
        "description": "Installed-package CVE posture vs OSV.dev. Default: "
                       "instant cached result (auto-restarts a background "
                       "refresh when stale — call again in a few minutes). "
                       "refresh=true forces a live scan, which takes MINUTES "
                       "and will time out on 60s-limited hosts (LM Studio).",
        "inputSchema": {"type": "object",
                        "properties": {"refresh": {"type": "boolean",
                                                   "description": "Force a live blocking scan (minutes)."}}, "required": []},
    },
    {
        "name": "autobahn.audit",
        "description": "Run an audit profile: full|vuln|network|hardening. "
                       "vuln profile is cache-first (instant; patch check "
                       "skipped) — pass {\"live\": true} for the full "
                       "blocking analysis (minutes; will time out on 60s "
                       "hosts like LM Studio).",
        "inputSchema": {"type": "object",
                        "properties": {"profile": {"type": "string",
                                                   "enum": ["full", "vuln",
                                                            "network", "hardening"]},
                                       "live": {"type": "boolean",
                                                "description": "Force full blocking vuln audit (minutes)."}}},
    },
    {
        "name": "autobahn.intel.poll",
        "description": "Poll CISA KEV + Ubuntu USN + EPSS + PoC feeds. "
                       "Network-heavy: can take up to a minute on slow "
                       "links — prefer intel.list on short-timeout hosts.",
        "inputSchema": {"type": "object",
                        "properties": {"sources": {"type": "array",
                                                   "items": {"type": "string"}}}},
    },
    {
        "name": "autobahn.intel.check",
        "description": "Match intel feeds against installed packages; generates alerts.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "autobahn.intel.list",
        "description": "List recent intel-match alerts.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "autobahn.alerts",
        "description": "List active engine alerts (GUI Alert Center contents).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "autobahn.remediate.plan",
        "description": "Plan containment/update/verify/restore for an intel alert. "
                       "Returns steps and a one-time confirm_token (read-before-write).",
        "inputSchema": {"type": "object",
                        "properties": {"alert": {"type": "object"},
                                       "step": {"type": "string"}},
                        "required": ["alert"]},
    },
    {
        "name": "autobahn.remediate.execute",
        "description": "Execute a planned remediation step; requires the "
                       "one-time confirm_token from remediate.plan.",
        "inputSchema": {"type": "object",
                        "properties": {"confirm_token": {"type": "string"}},
                        "required": ["confirm_token"]},
    },
]

_DISPATCH = {
    "autobahn.doctor": _tool_doctor,
    "autobahn.checks.list": _tool_checks_list,
    "autobahn.checks.run": _tool_check_run,
    "autobahn.cve.scan": _tool_cve_scan,
    "autobahn.audit": _tool_audit,
    "autobahn.intel.poll": _tool_intel_poll,
    "autobahn.intel.check": _tool_intel_check,
    "autobahn.intel.list": lambda args: {"alerts": _recent_intel_alerts()},
    "autobahn.alerts": _tool_alerts,
    "autobahn.remediate.plan": _tool_remediate_plan,
    "autobahn.remediate.execute": _tool_remediate_execute,
}


def _recent_intel_alerts():
    from engine.intel.store import recent_alerts
    return recent_alerts(limit=40)


# ── JSON-RPC loop ────────────────────────────────────────────────────────────

def _reply(msg_id, result) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": code, "message": message}}


def _load_policy() -> dict:
    """Local MCP access policy (written by the GUI's AI Agent tab)."""
    import os
    path = os.path.expanduser("~/.autobahn/mcp_policy.json")
    default = {"mode": "read", "allow_update": True, "allow_contain": False,
               "allow_firewall": False, "require_token": True}
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            default.update({k: v for k, v in data.items() if k in default})
    except Exception:
        pass
    return default


_POLICY = _load_policy()
_WRITE_TOOLS = {"autobahn.remediate.plan", "autobahn.remediate.execute",
                "autobahn.apply"}


def _policy_check(tool_name: str) -> str | None:
    """Return a refusal reason, or None if the call is allowed."""
    mode = _POLICY.get("mode", "read")
    if mode == "off":
        return ("AI access is switched OFF in Autobahn Defender "
                "(AI Agent tab → Access mode: Off).")
    if tool_name in _WRITE_TOOLS and mode != "full":
        return ("Write tools are disabled — Access mode is Read-only. "
                "Change it in Autobahn Defender → AI Agent tab.")
    if tool_name in _WRITE_TOOLS and mode == "full":
        if tool_name == "autobahn.remediate.execute":
            step = _POLICY
            if not _POLICY.get("require_token", True):
                pass  # token still enforced by engine; policy can't relax it
        # category toggles: refine by step hint (best-effort, engine still gates)
    return None


def _handle(msg: dict) -> dict | None:
    method = msg.get("method", "")
    msg_id = msg.get("id")
    if method == "initialize":
        return _reply(msg_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "autobahn-defender", "version": APP_VERSION},
        })
    if method == "notifications/initialized":
        return None  # notification — no response
    if method == "tools/list":
        return _reply(msg_id, {"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        fn = _DISPATCH.get(name)
        if fn is None:
            return _error(msg_id, -32601, f"unknown tool: {name}")
        refusal = _policy_check(name)
        if refusal:
            return _reply(msg_id, {
                "content": [{"type": "text", "text": f"refused by policy: {refusal}"}],
                "isError": True,
            })
        try:
            result = fn(arguments)
        except Exception as e:
            return _reply(msg_id, {
                "content": [{"type": "text", "text": f"error: {e}"}],
                "isError": True,
            })
        return _reply(msg_id, {
            "content": [{"type": "text", "text": json.dumps(result, default=str,
                                                            ensure_ascii=False)}],
            "isError": False,
        })
    if method == "ping":
        return _reply(msg_id, {})
    if msg_id is None:
        return None  # unknown notification
    return _error(msg_id, -32601, f"method not found: {method}")


def run_mcp_server() -> int:
    """Stdio loop. stdout is protocol-only; logs → stderr (spec MUST).

    Requests are dispatched to a small worker pool, not handled inline:
    this server used to process one request at a time, so one slow call
    (e.g. a live scan on a host that had already given up at 60 s) wedged
    the queue and domino-timed-out every fast tool behind it (observed on
    LM Studio, Sep 4 2026). JSON-RPC responses may return out of order —
    clients match by id; stdout writes are locked so replies never interleave.
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor

    def log(msg: str) -> None:
        sys.stderr.write(f"[autobahn-mcp] {msg}\n")
        sys.stderr.flush()

    if _POLICY.get("mode", "read") == "off":
        log("MCP access disabled by policy (AI Agent tab: mode=off) — refusing to serve.")
        sys.stderr.write("[autobahn-mcp] enable it via Autobahn Defender → AI Agent tab\n")
        return 3

    log(f"MCP server starting (protocol {PROTOCOL_VERSION}, app {APP_VERSION}, "
        f"schema {DATA_SCHEMA_VERSION}, policy mode={_POLICY.get('mode', 'read')}, "
        f"workers=4)")
    write_lock = threading.Lock()

    def emit(resp: dict | None) -> None:
        if resp is None:
            return
        with write_lock:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError as e:
                    emit(_error(None, -32700, f"parse error: {e}"))
                    continue
                # The HANDLING runs in the pool, not inline: one slow tool
                # must never block the reader or other tools (the Sep 4
                # domino-timeout). _handle(m) is passed as a callable, NOT
                # called here — `submit(emit, _handle(m))` would evaluate
                # it inline and stay serial (caught by the parallel test).
                m = msg if isinstance(msg, dict) else {}
                pool.submit(lambda m=m: emit(_handle(m)))
    except KeyboardInterrupt:
        pass
    log("MCP server stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_mcp_server())