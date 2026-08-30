"""Autobahn Defender CLI entry point (Phase 2).

`autobahn-defender <verb>` — human tables by default, --format json for
agents/stdout pipelines. Exit contract lives in cli/exitcodes.py.
All heavy lifting is in engine.runner; this module parses args and renders.
"""
from __future__ import annotations

import signal
import sys


def _install_sigpipe_default() -> None:
    """Die quietly on SIGPIPE (`... | head`) per POSIX pipe convention."""
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (AttributeError, ValueError):
        pass


# ─── shared render helpers ───────────────────────────────────────────────────

def _emit(args, doc, env) -> None:
    """Send the envelope to the destination in the requested format."""
    fmt = getattr(args, "format", "table")
    if fmt == "json":
        env.emit_json(doc, getattr(args, "output", None))
    elif fmt == "ndjson":
        recs = doc.get("results") or []
        if isinstance(recs, dict):
            recs = [recs]
        env.emit_ndjson(recs, getattr(args, "output", None))
    else:
        from .formatters import render_table
        env._write(render_table(doc), getattr(args, "output", None))


def _write_raw(args, text) -> None:
    try:
        if getattr(args, "output", None):
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        else:
            sys.stdout.write(text + "\n")
    except BrokenPipeError:
        raise SystemExit(141)


def _finding_rows(rows: list[dict]) -> list[dict]:
    """Only real findings (quarantine/flag) for exit-code purposes."""
    return [r for r in rows if isinstance(r, dict)
            and r.get("action") in ("quarantine", "flag")]


# ─── verbs ───────────────────────────────────────────────────────────────────

def cmd_scan(args, env) -> int:
    from .exitcodes import EXIT_ERROR, exits_with_findings
    from engine import runner
    paths = args.paths or []
    env.progress(f"scanning {len(paths)} path(s)...", args.quiet)
    try:
        res = runner.run_scan(
            paths, quick=bool(args.quick),
            progress_cb=(None if args.quiet else
                         lambda pct, msg: env.progress(msg, args.quiet)))
    except Exception as e:
        env.emit_json(env.envelope("scan", status="error",
                                   summary={"error": str(e)[:400]}))
        return EXIT_ERROR
    if res.get("error"):
        # operational failure — exit 2 per contract
        doc = env.envelope("scan", status="error",
                           results=res.get("details") or [],
                           summary={"error": res["error"], "paths": paths})
        _emit(args, doc, env)
        return EXIT_ERROR
    doc = env.envelope("scan", results=res.get("details") or [], summary={
        "files_scanned": res.get("files_scanned", 0),
        "threats_found": res.get("threats_found", 0),
        "engines": res.get("engines", {}),
        "paths": paths,
    })
    _emit(args, doc, env)
    return exits_with_findings(_finding_rows(res.get("details") or []),
                               getattr(args, "fail_on", None))


def cmd_scan_processes(args, env) -> int:
    from .exitcodes import EXIT_ERROR, exits_with_findings
    from engine import runner
    res = runner.run_scan_processes()
    doc = env.envelope("scan-processes", results=res.get("details") or [],
                       summary={"threats_found": res.get("threats_found", 0)})
    _emit(args, doc, env)
    return exits_with_findings(_finding_rows(res.get("details") or []))


def cmd_cve(args, env) -> int:
    from .exitcodes import exits_with_findings
    from engine import runner
    res = runner.run_cve_scan(offline=bool(getattr(args, "offline", False)))
    vulns = res.get("vulnerabilities") or []
    for w in res.get("warnings") or []:
        env.progress(f"WARNING: {w}", args.quiet)
    doc = env.envelope("cve", results=vulns, summary={
        "ecosystem": res.get("ecosystem"),
        "packages_checked": res.get("packages_checked", 0),
        "vulnerabilities_found": res.get("vulnerabilities_found", 0),
        "filtered_out": res.get("filtered_out", 0),
    }, warnings=res.get("warnings") or [])
    _emit(args, doc, env)
    return exits_with_findings(vulns, getattr(args, "fail_on", None))


def cmd_patches(args, env) -> int:
    from .exitcodes import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, EX_USAGE
    from engine import runner
    action = args.action
    if action == "check":
        res = runner.run_patch_check()
        doc = env.envelope("patches check", results=res.get("details") or [], summary={
            "tracked": res.get("tracked", 0), "open": res.get("open", 0),
            "fixes_available": res.get("fixes_available", 0),
            "fixes_applied": res.get("fixes_applied", 0)})
        _emit(args, doc, env)
        return EXIT_CLEAN
    if action == "verify":
        if not args.package:
            env.progress("verify requires a package name", args.quiet)
            return EX_USAGE
        res = runner.run_verify_patch(args.package)
        doc = env.envelope("patches verify", results=res.get("results") or [],
                           summary={"package": args.package,
                                    "status": res.get("status"),
                                    "note": res.get("note", "")})
        _emit(args, doc, env)
        if res.get("status") == "inconclusive":
            return EXIT_ERROR
        if res.get("all_resolved"):
            return EXIT_CLEAN
        return EXIT_FINDINGS
    if action == "apply":
        if not args.package:
            env.progress("apply requires a package name", args.quiet)
            return EX_USAGE
        if not args.yes:
            env.progress("refusing: privileged action — pass --yes after "
                         "reviewing `patches check` output.", args.quiet)
            return EX_USAGE
        res = runner.run_apply_batch([args.package])
        doc = env.envelope("patches apply", results=res.get("results") or [],
                           summary={"applied": res.get("applied", 0),
                                    "failed": res.get("failed", 0)})
        _emit(args, doc, env)
        return EXIT_CLEAN if res.get("success") else EXIT_ERROR
    return EX_USAGE


def cmd_audit(args, env) -> int:
    from .exitcodes import exits_with_findings
    from engine import runner
    profile_map = {"full": "full_audit", "vuln": "vulnerability_scan",
                   "network": "network_audit", "hardening": "hardening_audit"}
    task_id = profile_map[args.profile]
    env.progress(f"running audit: {task_id} (this can take 30-90s)...", args.quiet)
    res = runner.run_audit(task_id)
    findings = res.get("findings") or []
    fmt = getattr(args, "format", "table")
    if fmt == "markdown":
        _write_raw(args, res.get("report_markdown", ""))
        return exits_with_findings(findings, None)
    if fmt == "html":
        _write_raw(args, res.get("report_html", ""))
        return exits_with_findings(findings, None)
    doc = env.envelope(f"audit {args.profile}", results=findings, summary={
        "score": res.get("score"),
        "degraded": bool(res.get("degraded")),
        "checks_run": res.get("checks_run") or [],
    }, degraded=bool(res.get("degraded")))
    _emit(args, doc, env)
    return exits_with_findings(findings, None)


def cmd_checks(args, env) -> int:
    from .exitcodes import EXIT_CLEAN, EX_USAGE
    from engine.checks import list_checks, run_check
    if args.action == "list":
        names = list_checks()
        unique = sorted(set(n for n in names if not n.startswith("_t_")))
        doc = env.envelope("checks list", results=[
            {"check_id": n} for n in unique], summary={"count": len(unique)})
        _emit(args, doc, env)
        return EXIT_CLEAN
    name = args.check_name
    if not name:
        env.progress("checks run requires a check name", args.quiet)
        return EX_USAGE
    if not name.startswith("check_"):
        name = f"check_{name}"
    res = run_check(name, {})
    ok = res.get("status") == "ok"
    data = res.get("data") if ok else {}
    findings = data.get("findings") if isinstance(data, dict) else None
    doc = env.envelope(f"checks run {args.check_name}",
                       results=findings if isinstance(findings, list) else [],
                       summary={"status": res.get("status"),
                                "error": None if ok else str(res.get("error"))[:300],
                                "degraded": bool(data.get("degraded")) if isinstance(data, dict) else False},
                       status="ok" if ok else "error",
                       degraded=bool(isinstance(data, dict) and data.get("degraded")))
    _emit(args, doc, env)
    return EXIT_CLEAN if ok else EXIT_ERROR


def cmd_alerts(args, env) -> int:
    from .exitcodes import EXIT_CLEAN, EXIT_ERROR, EX_USAGE
    from engine import alerts as alerts_mod
    action = args.action
    if action == "list":
        rows = alerts_mod.load_alerts(active_only=True)
        doc = env.envelope("alerts list", results=rows,
                           summary={"active": len(rows)})
        _emit(args, doc, env)
        return EXIT_CLEAN
    if action in ("resolve", "dismiss"):
        if not args.alert_id:
            env.progress(f"{action} requires an alert id", args.quiet)
            return EX_USAGE
        ok = (alerts_mod.resolve_alert(args.alert_id) if action == "resolve"
              else alerts_mod.dismiss_alert(args.alert_id))
        doc = env.envelope(f"alerts {action}", results=[
            {"id": args.alert_id, "ok": bool(ok)}])
        _emit(args, doc, env)
        return EXIT_CLEAN if ok else EXIT_ERROR
    if action == "clear":
        removed = alerts_mod.clear_resolved()
        doc = env.envelope("alerts clear", results=[],
                           summary={"removed": removed})
        _emit(args, doc, env)
        return EXIT_CLEAN
    return EX_USAGE


def cmd_quarantine(args, env) -> int:
    from .exitcodes import EXIT_CLEAN, EXIT_ERROR, EX_USAGE
    from engine import runner
    action = args.action
    if action == "list":
        res = runner.run_quarantine_list()
        doc = env.envelope("quarantine list", results=res,
                           summary={"count": len(res)})
        _emit(args, doc, env)
        return EXIT_CLEAN
    if not args.quarantine_name:
        env.progress(f"{action} requires a quarantine name (see `quarantine list`)",
                     args.quiet)
        return EX_USAGE
    if args.action == "restore":
        res = runner.run_quarantine_restore(args.quarantine_name)
        ok = bool(res.get("success"))
    else:  # delete — destructive, needs --yes
        if not args.yes:
            env.progress("refusing: quarantine delete is destructive — "
                         "re-run with --yes after reviewing `quarantine list`.",
                         args.quiet)
            return EX_USAGE
        res = runner.run_quarantine_delete(args.quarantine_name)
        ok = bool(res.get("success"))
    doc = env.envelope(f"quarantine {args.action}", results=[res])
    _emit(args, doc, env)
    return EXIT_CLEAN if ok else EXIT_ERROR


def cmd_network(args, env) -> int:
    from .exitcodes import EXIT_CLEAN, EXIT_FINDINGS
    from engine import runner
    res = runner.run_network_action(args.action)
    summary = {"action": args.action}
    results = []
    if args.action == "connections":
        results = res.get("connections", [])
        summary["connections"] = len(results)
        summary["threats"] = len(res.get("threats", []))
        results = res.get("connections", []) + [
            {**t, "type": "threat"} for t in res.get("threats", [])]
    elif args.action == "persistence":
        results = res.get("findings", [])
        summary["findings"] = len(results)
    else:  # hosts / download-blacklist
        results = res if isinstance(res, list) else [res]
        if isinstance(res, dict):
            summary.update({k: v for k, v in res.items() if k != "findings"})
    doc = env.envelope(f"network {args.action}", results=results, summary=summary)
    _emit(args, doc, env)
    if args.action == "connections" and summary.get("threats"):
        return EXIT_FINDINGS
    return EXIT_CLEAN


def cmd_apply(args, env) -> int:
    from .exitcodes import EXIT_CLEAN, EXIT_ERROR, EX_USAGE
    from engine import runner
    if not args.yes:
        env.progress(f"refusing: '{args.action}' is a privileged system change "
                     "(review-first policy). Pass --yes to accept it, or use "
                     "the GUI Hardening panel.", args.quiet)
        return EX_USAGE
    res = runner.run_apply_action(args.action)
    ok = bool(res.get("success"))
    doc = env.envelope(f"apply {args.action}", results=[{
        "action": args.action,
        "success": ok,
        "error": str(res.get("error", ""))[:400],
        "details": res.get("changes") or res.get("drop_in") or "",
    }], summary={"success": ok})
    _emit(args, doc, env)
    return EXIT_CLEAN if ok else EXIT_ERROR


# ─── dispatch ────────────────────────────────────────────────────────────────

_COMMANDS = {
    "scan": "cmd_scan",
    "scan-processes": "cmd_scan_processes",
    "cve": "cmd_cve",
    "patches": "cmd_patches",
    "audit": "cmd_audit",
    "checks": "cmd_checks",
    "alerts": "cmd_alerts",
    "quarantine": "cmd_quarantine",
    "network": "cmd_network",
    "intel": "cmd_intel",
    "watch": "cmd_watch",
    "apply": "cmd_apply",
    "doctor": "cmd_doctor",
    "mcp": "cmd_mcp",
}


def main(argv: list[str] | None = None) -> int:
    _install_sigpipe_default()
    from .parsers import build_parser
    from . import envelope as env_mod
    from .exitcodes import EX_USAGE

    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    if not getattr(args, "command", None):
        parser.print_help(sys.stderr)
        return EX_USAGE

    handler_name = _COMMANDS.get(args.command)
    if not handler_name:
        parser.print_help(sys.stderr)
        return EX_USAGE

    if handler_name == "cmd_mcp":
        from .mcp_server import run_mcp_server
        return run_mcp_server()

    import importlib
    handler = globals().get(handler_name)
    if handler is None:
        mod = importlib.import_module(".verbs_intel", package=__package__)
        handler = getattr(mod, handler_name, None)
    if handler is None:
        mod = importlib.import_module(".doctor", package=__package__)
        handler = getattr(mod, handler_name, None)
    if handler is None:
        parser.print_help(sys.stderr)
        return EX_USAGE

    env = env_mod
    try:
        return int(handler(args, env))
    except SystemExit as exc:
        return int(exc.code or 0) if exc.code else 0
    except KeyboardInterrupt:
        env.progress("interrupted", getattr(args, "quiet", False))
        return 130
    except Exception as e:
        env.progress(f"error: {e}", getattr(args, "quiet", False))
        if _should_emit_json(args):
            env_mod.emit_json(env_mod.envelope(args.command, status="error",
                                               summary={"error": str(e)[:500]}))
        return 2


def _should_emit_json(args) -> bool:
    return getattr(args, "format", "table") in ("json", "ndjson")