"""CISA KEV collector — the highest-signal feed, zero auth.

Official JSON (verified live 2026-08-30, 1,685 entries):
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Git mirror fallback: https://github.com/cisagov/kev-data (raw develop branch).
Cadence: several times/week; diff on dateAdded.
"""
from __future__ import annotations

import logging
from typing import Any

import requests

from . import store

log = logging.getLogger(__name__)

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
KEV_MIRROR_URL = ("https://raw.githubusercontent.com/cisagov/kev-data/main/"
                  "known_exploited_vulnerabilities.json")


def _fetch_json(url: str, timeout: int = 60) -> dict | None:
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"User-Agent": "AutobahnDefender/2.0 (KEV poller)"})
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.warning("KEV fetch failed (%s): %s", url, e)
        return None


def poll_kev() -> dict[str, Any]:
    """Fetch + store the KEV catalog. Returns a summary dict."""
    data = _fetch_json(KEV_URL) or _fetch_json(KEV_MIRROR_URL)
    if not isinstance(data, dict):
        return {"source": "kev", "ok": False, "error": "unreachable (both mirrors)"}

    entries = data.get("vulnerabilities") or []
    catalog_version = str(data.get("catalogVersion") or "")
    known_catalog = store.feed_catalog("kev")
    changed = (known_catalog != catalog_version)

    rows = []
    for v in entries:
        if not isinstance(v, dict):
            continue
        cve_id = v.get("cveID") or ""
        if not cve_id:
            continue
        rows.append({
            "cve_id": cve_id,
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "date_added": v.get("dateAdded", ""),
            "due_date": v.get("dueDate", ""),
            "known_ransomware": v.get("knownRansomwareCampaignUse", ""),
            "required_action": v.get("requiredAction", ""),
            "notes": v.get("notes", ""),
        })
    stored = store.upsert_kev(rows) if rows else 0
    store.upsert_feed("kev", catalog_version, len(entries))
    return {
        "source": "kev", "ok": True,
        "catalog": catalog_version,
        "catalog_changed": known_catalog != catalog_version,
        "total": len(entries),
        "new_since_last_poll": stored,
    }


def all_kev_cves() -> set[str]:
    if not store.DB_PATH.exists():
        return set()
    conn = store._connect()
    try:
        rows = conn.execute("SELECT cve_id FROM kev").fetchall()
    finally:
        conn.close()
    return {r[0] for r in rows}