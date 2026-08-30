"""CLI verbs: intel (poll/show/status/check) and watch (once/status) — Phase 2.2/3."""
from __future__ import annotations


def cmd_intel(args, env) -> int:
    from .exitcodes import EXIT_CLEAN, EXIT_ERROR, EX_USAGE
    from engine import runner
    action = getattr(args, "action", "status")

    if action == "poll":
        env.progress("polling threat-intel feeds (KEV, USN, EPSS, PoC)...",
                     args.quiet)
        res = runner.run_intel_poll(sources=getattr(args, "source", None))
        doc = env.envelope("intel poll", results=[res], summary={
            "sources_polled": res.get("sources_polled"),
            "sources_ok": res.get("sources_ok"),
            "per_source": {k: {"ok": v.get("ok"), "total": v.get("total")}
                           for k, v in (res.get("results") or {}).items()},
        }, status="ok" if res.get("ok") else "error")
        _emit(args, doc, env)
        return EXIT_CLEAN if res.get("ok") else EXIT_ERROR

    if action == "show":
        limit = getattr(args, "limit", 40)
        res = runner.run_intel_show(limit=limit)
        alerts = res.get("alerts", [])
        doc = env.envelope("intel show", results=alerts,
                           summary={"alerts": len(alerts)})
        _emit(args, doc, env)
        return EXIT_CLEAN

    if action == "status":
        from engine.intel.store import feed_catalog, DB_PATH
        feeds = {}
        for name in ("kev", "usn", "epss", "poc"):
            feeds[name] = feed_catalog(name)
        doc = env.envelope("intel status", results=[
            {"feed": k, "catalog": v} for k, v in feeds.items()],
            summary={"db": str(_db_path())})
        _emit(args, doc, env)
        return EXIT_CLEAN

    return EX_USAGE


def cmd_watch(args, env) -> int:
    from .exitcodes import EXIT_CLEAN, EXIT_ERROR
    from engine import runner
    action = getattr(args, "action", "status")

    if action == "once":
        # one monitor pass: intel check + network scan + persistence
        intel = runner.run_intel_check()
        net = runner.run_network_action("connections")
        pers = runner.run_network_action("persistence")
        threat_count = len(net.get("threats") or [])
        doc = env.envelope("watch once", results={
            "intel": intel.get("summary") or {},
            "network_threats": net.get("threats") or [],
            "persistence": pers.get("suspicious_entries") or pers.get("findings") or [],
        }, summary={
            "intel_ok": bool(intel.get("ok")),
            "new_alerts": (intel.get("summary") or {}).get("new_alerts", 0),
            "network_threats": threat_count,
            "persistence_findings": len(pers.get("suspicious_entries")
                                        or pers.get("findings") or []),
        })
        _emit(args, doc, env)
        if doc["summary"]["new_alerts"] or threat_count:
            return EXIT_FINDINGS
        return EXIT_CLEAN

    if action == "status":
        from engine.watch.inotify_watch import inotify_available
        doc = env.envelope("watch status", results=[{
            "inotify_available": inotify_available(),
            "note": ("Tier A (inotify) runs inside the GUI when Active "
                     "Monitoring is enabled, or via the autobahn-watch "
                     "systemd user timer for headless use."),
        }])
        _emit(args, doc, env)
        return EXIT_CLEAN

    return EXIT_ERROR


def _emit(args, doc, env) -> None:
    from cli.main import _emit as shared_emit
    shared_emit(args, doc, env)


def _db_path():
    from engine.intel.store import DB_PATH
    return DB_PATH