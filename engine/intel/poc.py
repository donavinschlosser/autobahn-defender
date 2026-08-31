"""PoC-in-GitHub collector — public proof-of-concept tracker.

Verified live 2026-08-30: https://github.com/nomi-sec/PoC-in-GitHub organizes
by year; per-year README.json lists CVE→repo links. We fetch the current year
list and store the CVE ids. Weekly cadence (large file, slow to change).
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any

import requests

from . import store

log = logging.getLogger(__name__)

poc_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

BASE = ("https://api.github.com/repos/nomi-sec/PoC-in-GitHub/contents/")
_BROWSERS = {"User-Agent": "AutobahnDefender/2.0",
             "Accept": "application/vnd.github+json"}

_POC_CACHE: dict[int, set[str]] = {}


def _poc_year_from_api(year: int, timeout: int) -> set[str] | None:
    """Fetch the PoC CVE list for one year via the GitHub contents API.

    The old raw-URL pattern ({master}/{year}/README.json) 404s since the
    project switched to per-CVE files ({year}/CVE-YYYY-NNNN.json); the API
    directory listing works for every year.
    """
    import time as _time
    url = f"{BASE}{year}"
    cves: set[str] = set()
    try:
        r = requests.get(url, timeout=timeout, headers=_BROWSERS)
        if r.status_code == 404:
            return set()
        r.raise_for_status()
        for m in poc_RE.finditer(r.text):
            cves.add(m.group(0))
        return cves
    except Exception as e:
        log.warning("PoC API fetch for %d failed: %s", year, e)
        return None


def poll_poc(year: int | None = None, timeout: int = 90) -> dict[str, Any]:
    year = year or datetime.now().year
    cves: set[str] = set()
    # current year first; if it's empty (early in the year) also pull the
    # previous year so the store stays useful
    for yr in (year, year - 1):
        got = _poc_year_from_api(yr, timeout)
        if got:
            cves |= got
        if yr != year and cves:
            break
    if not cves:
        return {"source": "poc", "ok": False,
                "error": "no PoC data available from GitHub API", "year": year}

    cve_list = sorted(cves)
    stored = store.upsert_pocs(cve_list, "poc-in-github") if cve_list else 0
    store.upsert_feed("poc", str(year), len(cve_list))
    return {"source": "poc", "ok": True, "year": year,
            "cves_found": len(cve_list), "stored": stored}