"""EPSS collector — FIRST Exploit Prediction Scoring System, bulk CSV dump.

Verified live 2026-08-30: https://epss.cyentia.com/epss_scores-current.csv.gz
(~2.5MB gz, ~366k rows, columns: cve,epss,percentile + model header line).
Downloaded daily; joined locally — zero API calls.
"""
from __future__ import annotations

import csv
import gzip
import io
import logging
from datetime import datetime, timezone
from typing import Any

import requests

from . import store

log = logging.getLogger(__name__)

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
EPSS_URL_ALT = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def poll_epss(timeout: int = 120) -> dict[str, Any]:
    """Download + store the daily EPSS dump. Returns a summary dict."""
    last_err = None
    for url in (EPSS_URL, EPSS_URL_ALT):
        try:
            r = requests.get(url, timeout=timeout, stream=True)
            r.raise_for_status()
            raw = gzip.decompress(r.content)
            text = raw.decode("utf-8", errors="replace")
            rows = []
            score_date = ""
            reader = csv.reader(io.StringIO(text))
            for i, row in enumerate(reader):
                if i == 0:
                    # '#model_version:...,score_date:2026-08-30T12:03:42Z'
                    if "score_date:" in (row[0] if row else ""):
                        score_date = row[0].split("score_date:")[-1]
                    continue
                if len(row) >= 3 and row[0].startswith("CVE-"):
                    try:
                        rows.append({"cve_id": row[0],
                                     "epss": float(row[1]),
                                     "percentile": float(row[2]),
                                     "score_date": score_date})
                    except ValueError:
                        continue
            stored = store.upsert_epss(rows)
            store.upsert_feed("epss", score_date, len(rows))
            return {"source": "epss", "ok": True, "score_date": score_date,
                    "total": len(rows), "stored": stored}
        except Exception as e:
            last_err = e
            continue
    return {"source": "epss", "ok": False, "error": str(last_err)}