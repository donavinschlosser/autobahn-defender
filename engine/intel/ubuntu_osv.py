"""Ubuntu security-notices collector (USN) — via ubuntu.com notices.json.

Verified live 2026-08-30: https://ubuntu.com/security/notices.json
(notices[] with cves_ids + release_packages per release; 10 per page,
paginate ?offset=). Covers Ubuntu AND Linux Mint (via base mapping).
Debian/LMDE users are covered by the Debian tracker JSON (poll weekly).
"""
from __future__ import annotations

import logging
import re
from typing import Any

import requests

from . import store

log = logging.getLogger(__name__)

USN_JSON_URL = "https://ubuntu.com/security/notices.json"


def poll_usn(pages: int = 3, timeout: int = 30) -> dict[str, Any]:
    """Fetch the most recent USN notices and store CVE→fixed-version rows."""
    rows: list[dict[str, Any]] = []
    total_notices = 0
    try:
        for page in range(max(1, min(pages, 10))):
            r = requests.get(USN_JSON_URL, params={"offset": page * 10},
                             timeout=timeout,
                             headers={"User-Agent": "AutobahnDefender/2.0"})
            r.raise_for_status()
            data = r.json()
            notices = data.get("notices") or []
            total_notices += len(notices)
            for n in notices:
                usn_id = n.get("id") or ""
                published = n.get("published") or ""
                release_packages = n.get("release_packages") or {}
                cve_ids = set(n.get("cves_ids") or [])
                # also parse CVE ids out of the cves[] entries
                for c in (n.get("cves") or []):
                    if isinstance(c, dict):
                        cid = c.get("id") or ""
                        if cid.startswith("CVE-"):
                            cve_ids.add(cid)
                    elif isinstance(c, str) and c.startswith("CVE-"):
                        cve_ids.add(c)
                if not cve_ids:
                    continue
                for release, pkgs in release_packages.items():
                    if not isinstance(pkgs, list):
                        continue
                    for p in pkgs:
                        if not isinstance(p, dict):
                            continue
                        name = p.get("name") or ""
                        fixed = p.get("version") or ""
                        for cve in cve_ids:
                            rows.append({
                                "usn_id": usn_id, "cve_id": cve,
                                "release": release, "package": name,
                                "fixed_version": fixed_version(p),
                                "published": published,
                            })
            if len(notices) < 10:
                break
    except Exception as e:
        return {"source": "usn", "ok": False, "error": str(e)}

    stored = store.upsert_usn(rows) if rows else 0
    store.upsert_feed("usn", f"notices:{total_notices}", len(rows))
    return {"source": "usn", "ok": True, "notices": total_notices,
            "rows": len(rows), "stored": stored}


def fixed_version(pkg_entry: dict) -> str:
    """Release-package entry shape: {name, version, source_version, ...}."""
    v = pkg_entry.get("version") or pkg_entry.get("source_version") or ""
    return str(v)


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")