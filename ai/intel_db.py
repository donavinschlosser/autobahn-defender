"""
Autobahn Defender v2.0 -- AI-managed intelligence database.

JSONL files under ~/.local/share/autobahn-defender/intel/:
  vulnerabilities.jsonl  -- CVEs affecting installed software
  zero_day_alerts.jsonl  -- Zero-day news items
  security_news.jsonl    -- RSS feed history
  resolved.jsonl         -- Resolved items (archive)

Each line is one JSON object. The AI reads these files, processes new
info, and writes updated files atomically. The AI manages the lifecycle:
adds new items, marks resolved, removes old items after 30+ days.

All managed automatically by the AI -- the user does NOT edit these.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import INTEL_DIR

# File names (under INTEL_DIR)
VULNS_FILE = "vulnerabilities.jsonl"
ZERO_DAY_FILE = "zero_day_alerts.jsonl"
NEWS_FILE = "security_news.jsonl"
RESOLVED_FILE = "resolved.jsonl"

ALL_FILES = [VULNS_FILE, ZERO_DAY_FILE, NEWS_FILE, RESOLVED_FILE]

# Items older than this (days) are pruned from active databases.
PRUNE_AGE_DAYS = 30
# Resolved items older than this are removed entirely.
RESOLVED_PRUNE_AGE_DAYS = 90


def ensure_dirs():
    """Create the intel directory and empty JSONL files if missing.

    SECURITY: Directory is created with mode 0o700 (owner-only access)
    to prevent other local users from reading the user's security
    intelligence data (vulnerability reports, RSS history, etc.).
    """
    INTEL_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Restrict permissions if the dir already exists with loose perms
    try:
        os.chmod(str(INTEL_DIR), 0o700)
    except OSError:
        pass
    for name in ALL_FILES:
        p = INTEL_DIR / name
        if not p.exists():
            p.touch()
            try:
                os.chmod(str(p), 0o600)
            except OSError:
                pass


def _path(name: str) -> Path:
    return INTEL_DIR / name


def read_all(name: str) -> list[dict[str, Any]]:
    """Read every record from a JSONL file. Returns [] if missing/empty."""
    p = _path(name)
    if not p.exists():
        return []
    out: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _atomic_write(name: str, records: Iterable[dict[str, Any]]) -> None:
    """Write records to the file atomically (write tmp, rename)."""
    p = _path(name)
    INTEL_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        dir=str(INTEL_DIR), prefix=name + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False))
                f.write("\n")
        os.replace(tmp, p)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def append(name: str, record: dict[str, Any]) -> None:
    """Append a single record to a JSONL file.

    Writes the full line + flush + fsync for durability. If the process
    crashes mid-write, the file will have a complete last line (no
    partial/corrupt JSON).
    """
    p = _path(name)
    INTEL_DIR.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False))
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())


def append_many(name: str, records: Iterable[dict[str, Any]]) -> None:
    """Append multiple records with a single fsync at the end."""
    p = _path(name)
    INTEL_DIR.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False))
            f.write("\n")
        f.flush()
        os.fsync(f.fileno())


def dedup_key(record: dict[str, Any]) -> str:
    """Build a stable dedup key for a record.

    Uses 'id' if present, else 'url', else 'cve', else hash of the
    JSON-serialized record. Used to avoid re-processing the same item.
    """
    for k in ("id", "url", "cve", "title"):
        v = record.get(k)
        if v:
            return str(v)
    return json.dumps(record, sort_keys=True)


def filter_new(
    name: str, candidates: Iterable[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return only candidates whose dedup_key is not already in the file."""
    existing = {dedup_key(r) for r in read_all(name)}
    out = []
    for c in candidates:
        k = dedup_key(c)
        if k not in existing:
            existing.add(k)
            out.append(c)
    return out


def mark_resolved(name: str, predicate) -> int:
    """Move records matching predicate(name, record)->bool from `name`
    into RESOLVED_FILE. Returns the number moved."""
    remaining = []
    moved = []
    for rec in read_all(name):
        if predicate(rec):
            rec["resolved_at"] = datetime.now(timezone.utc).isoformat()
            moved.append(rec)
        else:
            remaining.append(rec)
    if moved:
        _atomic_write(name, remaining)
        append_many(RESOLVED_FILE, moved)
    return len(moved)


def prune_old(name: str, age_days: int = PRUNE_AGE_DAYS) -> int:
    """Remove records older than age_days based on 'seen_at' or 'date'
    ISO timestamp field. Returns count removed."""
    from datetime import timedelta

    cutoff = datetime.now(timezone.utc) - timedelta(days=age_days)
    kept = []
    removed = 0
    for rec in read_all(name):
        ts = rec.get("seen_at") or rec.get("date") or rec.get("timestamp")
        try:
            if ts and datetime.fromisoformat(ts) < cutoff:
                removed += 1
                continue
        except (TypeError, ValueError):
            pass
        kept.append(rec)
    if removed:
        _atomic_write(name, kept)
    return removed


def stats() -> dict[str, int]:
    """Return record counts per file (for UI display)."""
    return {name: len(read_all(name)) for name in ALL_FILES}


def search(name: str, query: str, limit: int = 50) -> list[dict[str, Any]]:
    """Simple case-insensitive substring search across all fields."""
    q = query.lower()
    out = []
    for rec in read_all(name):
        blob = json.dumps(rec, ensure_ascii=False).lower()
        if q in blob:
            out.append(rec)
            if len(out) >= limit:
                break
    return out