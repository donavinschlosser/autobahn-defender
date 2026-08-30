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

BASE = ("https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/")


def poll_poc(year: int | None = None, timeout: int = 90) -> dict[str, Any]:
    year = year or datetime.now().year
    url = f"{BASE}{year}/README.json"
    cves: set[str] = set()
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"User-Agent": "AutobahnDefender/2.0"})
        r.raise_for_status()
        for m in poc_RE.finditer(r.text):
            cves.add(m.group(0))
    except Exception as e:
        return {"source": "poc", "ok": False, "error": str(e), "year": year}

    cve_list = sorted(cves)
    stored = store.upsert_pocs(cve_list, "poc-in-github") if cve_list else 0
    store.upsert_feed("poc", str(year), len(cve_list))
    return {"source": "poc", "ok": True, "year": year,
            "cves_found": len(cve_list), "stored": stored}