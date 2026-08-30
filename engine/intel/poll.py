"""Intel poll orchestrator — one full collection cycle across all feeds."""
from __future__ import annotations

import logging
from typing import Any

from ..version import APP_VERSION
from . import epss as epss_mod
from . import kev as kev_mod
from . import poc as poc_mod
from . import store
from . import ubuntu_osv

log = logging.getLogger(__name__)


def run_poll(sources: list[str] | None = None, usn_pages: int = 3) -> dict[str, Any]:
    """Poll selected (default: all) feeds. Returns per-source summaries."""
    store.init_db()
    wanted = {s.lower() for s in (sources or [])} if sources else None

    results: dict[str, Any] = {}
    if wanted is None or "kev" in wanted:
        results["kev"] = kev_mod.poll_kev()
    if wanted is None or "usn" in wanted:
        results["usn"] = ubuntu_osv.poll_usn(pages=usn_pages)
    if wanted is None or "epss" in wanted:
        results["epss"] = epss_mod.poll_epss()
    if wanted is None or "poc" in wanted:
        results["poc"] = poc_mod.poll_poc()

    ok_count = sum(1 for r in results.values() if r.get("ok"))
    return {
        "ok": ok_count > 0,
        "sources_polled": len(results),
        "sources_ok": ok_count,
        "results": results,
        "tool_version": APP_VERSION,
    }