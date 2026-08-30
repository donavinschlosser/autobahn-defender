"""Intel store — SQLite (WAL) state for feed data and generated alerts.

Replaces JSONL for intel (bulk data, indexed lookups). File:
  ~/.local/share/autobahn-defender/intel/intel.db   (0600, dir 0700)

Tables:
  feeds      — last-fetched metadata per source (etag/last_modified/catalog)
  kev        — CISA KEV entries (cve_id PK, dateAdded, dueDate, ransomware…)
  usn        — Ubuntu security notices (usn, cve, release, fixed_version)
  epss       — CVE → epss score + percentile (latest daily dump)
  poc        — CVE ids with public PoCs (source, first_seen)
  alerts     — generated match alerts (dedup key cve|pkg|status)
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

from ..paths import DATA_DIR

DB_PATH = DATA_DIR / "intel" / "intel.db"
_db_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS feeds (
    name TEXT PRIMARY KEY,
    catalog TEXT,
    fetched_at TEXT,
    entry_count INTEGER
);
CREATE TABLE IF NOT EXISTS kev (
    cve_id TEXT PRIMARY KEY,
    vendor TEXT, product TEXT, name TEXT,
    date_added TEXT, due_date TEXT,
    known_ransomware TEXT, required_action TEXT,
    notes TEXT
);
CREATE TABLE IF NOT EXISTS usn (
    usn_id TEXT, cve_id TEXT, release TEXT,
    fixed_version TEXT, package TEXT,
    published TEXT,
    PRIMARY KEY (usn_id, cve_id, release)
);
CREATE TABLE IF NOT EXISTS epss (
    cve_id TEXT PRIMARY KEY,
    epss REAL, percentile REAL, score_date TEXT
);
CREATE TABLE IF NOT EXISTS poc (
    cve_id TEXT PRIMARY KEY,
    source TEXT, first_seen TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_key TEXT PRIMARY KEY,
    cve_id TEXT, package TEXT, installed TEXT, fixed_in TEXT,
    severity TEXT, exploited INTEGER DEFAULT 0,
    public_poc INTEGER DEFAULT 0, epss REAL,
    status TEXT DEFAULT 'open',
    title TEXT, action TEXT,
    created_at TEXT, updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_kev_cve ON kev(cve_id);
CREATE INDEX IF NOT EXISTS idx_usn_cve ON usn(cve_id);
CREATE INDEX IF NOT EXISTS idx_alerts_cve ON alerts(cve_id);
"""


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(DB_PATH.parent), 0o700)
    except OSError:
        pass
    conn = sqlite3.connect(str(DB_PATH), timeout=15)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    try:
        os.chmod(str(DB_PATH), 0o600)
    except OSError:
        pass
    for side in (DB_PATH.parent / "intel.db-wal", DB_PATH.parent / "intel.db-shm"):
        try:
            if side.exists():
                os.chmod(str(side), 0o600)
        except OSError:
            pass
    return conn


def init_db() -> None:
    with _db_lock:
        conn = _connect()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()


# ── feeds metadata ───────────────────────────────────────────────────────────

def upsert_feed(name: str, catalog: str, count: int) -> None:
    from datetime import datetime, timezone
    with _db_lock:
        conn = _connect()
        conn.execute(
            "INSERT INTO feeds(name, catalog, fetched_at, entry_count) VALUES(?,?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET catalog=excluded.catalog, "
            "fetched_at=excluded.fetched_at, entry_count=excluded.entry_count",
            (name, catalog, datetime.now(timezone.utc).isoformat(timespec="seconds"),
             int(count)))
        conn.commit()
        conn.close()


def feed_catalog(name: str) -> str | None:
    if not DB_PATH.exists():
        return None
    with _db_lock:
        conn = _connect()
        row = conn.execute("SELECT catalog FROM feeds WHERE name=?", (name,)).fetchone()
        conn.close()
    return row[0] if row else None


# ── writers ──────────────────────────────────────────────────────────────────

def upsert_kev(entries: list[dict[str, Any]]) -> int:
    """Insert/refresh KEV rows; returns count of NEW cve ids."""
    with _db_lock:
        conn = _connect()
        conn.executescript(_SCHEMA)
        new_ids = set()
        for e in entries:
            cur = conn.execute("SELECT 1 FROM kev WHERE cve_id=?", (e["cve_id"],))
            if cur.fetchone() is None:
                new_ids.add(e["cve_id"])
            conn.execute(
                "INSERT INTO kev(cve_id, vendor, product, name, date_added, due_date,"
                " known_ransomware, required_action, notes) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(cve_id) DO UPDATE SET name=excluded.name, "
                "due_date=excluded.due_date, known_ransomware=excluded.known_ransomware",
                (e.get("cve_id"), e.get("vendor", ""),
                 e.get("product", ""), e.get("name", ""),
                 e.get("date_added", ""), e.get("due_date", ""),
                 e.get("known_ransomware", ""), e.get("required_action", ""),
                 json.dumps(e.get("notes", ""))[:4000]))
        conn.commit()
        conn.close()
    return len(new_ids)


def upsert_usn(rows: list[dict[str, Any]]) -> int:
    """rows: {usn_id, cve_id, release, fixed_version, package, published}"""
    with _db_lock:
        conn = _connect()
        conn.executescript(_SCHEMA)
        count = 0
        for r in rows:
            conn.execute(
                "INSERT OR IGNORE INTO usn(usn_id, cve_id, release, fixed_version, "
                "package, published) VALUES(?,?,?,?,?,?)",
                (r.get("usn_id"), r.get("cve_id"), r.get("release", ""),
                 r.get("fixed_version", ""), r.get("package", ""),
                 r.get("published", "")))
            count += 1
        conn.commit()
        conn.close()
    return count


def upsert_epss(rows: list[dict[str, Any]]) -> int:
    with _db_lock:
        conn = _connect()
        conn.executescript(_SCHEMA)
        conn.executemany(
            "INSERT OR REPLACE INTO epss(cve_id, epss, percentile, score_date) "
            "VALUES(?,?,?,?)",
            [(r["cve_id"], r.get("epss", 0.0), r.get("percentile", 0.0),
              r.get("score_date", "")) for r in rows])
        conn.commit()
        conn.close()
    return len(rows)


def upsert_pocs(cve_ids: list[str], source: str) -> int:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _db_lock:
        conn = _connect()
        conn.executescript(_SCHEMA)
        for cve in cve_ids:
            conn.execute(
                "INSERT OR IGNORE INTO poc(cve_id, source, first_seen) VALUES(?,?,?)",
                (cve, source, now))
        conn.commit()
        conn.close()
    return len(cve_ids)


def add_alert(alert: dict[str, Any]) -> bool:
    """Insert an intel match alert; returns False when it already exists."""
    from datetime import datetime, timezone
    key = f"{alert.get('cve_id')}|{alert.get('package')}|{alert.get('status', 'open')}"
    conn = _connect()
    conn.executescript(_SCHEMA)
    cur = conn.execute("SELECT 1 FROM alerts WHERE alert_key=?", (key,))
    exists = cur.fetchone() is not None
    if exists:
        conn.close()
        return False
    conn.execute(
        "INSERT INTO alerts(alert_key, cve_id, package, fixed_in, severity, "
        "exploited, public_poc, epss, status, title, action, created_at, updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (key, alert.get("cve_id"), alert.get("package", ""),
         alert.get("fixed_in", ""), alert.get("severity", "HIGH"),
         1 if alert.get("exploited") else 0,
         1 if alert.get("public_poc") else 0,
         alert.get("epss"), alert.get("status", "open"),
         alert.get("title", ""), alert.get("action", ""),
         alert.get("created_at") or datetime.now(timezone.utc).isoformat(timespec="seconds"),
         datetime.now(timezone.utc).isoformat(timespec="seconds")))
    conn.commit()
    conn.close()
    return True


def recent_alerts(limit: int = 40, open_only: bool = False) -> list[dict[str, Any]]:
    if not DB_PATH.exists():
        return []
    conn = _connect()
    q = "SELECT * FROM alerts"
    if open_only:
        q += " WHERE status='open'"
    q += " ORDER BY created_at DESC LIMIT ?"
    cur = conn.execute(q, (limit,))
    cols = [d[0] for d in cur.description]
    rows = cur.fetchall()
    conn.close()
    return [dict(zip(cols, r)) for r in rows]


# ── readers used by match ────────────────────────────────────────────────────

def kev_contains(cve_ids: set[str]) -> dict[str, dict[str, Any]]:
    """Return KEV rows for the given CVE ids."""
    out: dict[str, Any] = {}
    if not cve_ids or not DB_PATH.exists():
        return out
    conn = _connect()
    qmarks = ",".join("?" for _ in cve_ids)
    try:
        rows = conn.execute(
            f"SELECT cve_id, vendor, product, name, date_added, due_date, "
            f"known_ransomware FROM kev WHERE cve_id IN ({qmarks})",
            tuple(cve_ids)).fetchall()
    except sqlite3.Error:
        rows = []
    conn.close()
    for r in rows:
        out[r[0]] = {"vendor": r[1], "product": r[2], "name": r[3],
                     "date_added": r[4], "due_date": r[5],
                     "known_ransomware": r[6]}
    return out


def poc_contains(cve_ids: set[str]) -> set[str]:
    if not cve_ids or not DB_PATH.exists():
        return set()
    conn = _connect()
    qmarks = ",".join("?" for _ in cve_ids)
    try:
        rows = conn.execute(
            f"SELECT cve_id FROM poc WHERE cve_id IN ({qmarks})",
            tuple(cve_ids)).fetchall()
    except sqlite3.Error:
        rows = []
    conn.close()
    return {r[0] for r in rows}


def epss_for(cve_ids: set[str]) -> dict[str, float]:
    out = {}
    if not cve_ids or not DB_PATH.exists():
        return out
    conn = _connect()
    qmarks = ",".join("?" for _ in cve_ids)
    try:
        rows = conn.execute(
            f"SELECT cve_id, epss FROM epss WHERE cve_id IN ({qmarks})",
            tuple(cve_ids)).fetchall()
    except sqlite3.Error:
        rows = []
    conn.close()
    for cve, score in rows:
        out[cve] = score
    return out