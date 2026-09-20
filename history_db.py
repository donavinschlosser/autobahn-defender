"""
Autobahn Defender - History Database
SQLite-backed logging for scan results, quarantine actions, and audits.
"""

import sqlite3
import json
import os
import threading
from datetime import datetime
from pathlib import Path

# v2.0.4: resolve through engine.paths (sudo-safe data dir — see that module)
try:
    from engine.paths import HISTORY_DB as DB_PATH
except ImportError:  # pragma: no cover
    DB_PATH = Path.home() / ".autobahn" / "history.db"
_db_lock = threading.Lock()


def _get_conn():
    """Get a database connection with WAL mode for safe concurrent reads.
    Ensures the DB file and any WAL/SHM sidecar files have restrictive permissions.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(DB_PATH.parent), 0o700)
    except OSError:
        pass
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    # Ensure restrictive permissions on the DB file and any WAL/SHM sidecars
    try:
        os.chmod(str(DB_PATH), 0o600)
    except OSError:
        pass
    for sidecar in [DB_PATH.with_suffix(".db-wal"), DB_PATH.with_suffix(".db-shm")]:
        if sidecar.exists():
            try:
                os.chmod(str(sidecar), 0o600)
            except OSError:
                pass
    return conn


def init_db():
    """Create tables if they don't exist and set restrictive permissions."""
    # Ensure parent directory exists and has correct permissions
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(DB_PATH.parent), 0o700)
    except OSError:
        pass
    # Create file with restrictive permissions before writing
    if not DB_PATH.exists():
        DB_PATH.touch()
        try:
            os.chmod(str(DB_PATH), 0o600)
        except OSError:
            pass
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            files_scanned INTEGER DEFAULT 0,
            threats_found INTEGER DEFAULT 0,
            details_json TEXT DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS quarantine_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            original_path TEXT,
            quarantine_name TEXT,
            threat TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            audit_type TEXT NOT NULL,
            findings_json TEXT DEFAULT '[]'
        );
    """)
    conn.commit()
    conn.close()
    # Set restrictive permissions on the database file
    try:
        os.chmod(str(DB_PATH), 0o600)
    except OSError:
        pass


def log_scan(scan_type, files_scanned, threats_found, details):
    """Log a completed scan."""
    with _db_lock:
        try:
            with _get_conn() as conn:
                conn.execute(
                    "INSERT INTO scan_history (timestamp, scan_type, files_scanned, threats_found, details_json) VALUES (?, ?, ?, ?, ?)",
                    (datetime.now().isoformat(), scan_type, files_scanned, threats_found, json.dumps(details[:200])),
                )
                conn.commit()
        except sqlite3.Error:
            pass


def log_quarantine_action(action, original_path, quarantine_name, threat):
    """Log a quarantine action (quarantine, restore, delete)."""
    with _db_lock:
        try:
            with _get_conn() as conn:
                conn.execute(
                    "INSERT INTO quarantine_history (timestamp, action, original_path, quarantine_name, threat) VALUES (?, ?, ?, ?, ?)",
                    (datetime.now().isoformat(), action, original_path or "", quarantine_name or "", threat or ""),
                )
                conn.commit()
        except sqlite3.Error:
            pass


def log_audit(audit_type, findings):
    """Log an audit (kernel, hardening)."""
    with _db_lock:
        try:
            with _get_conn() as conn:
                conn.execute(
                    "INSERT INTO audit_history (timestamp, audit_type, findings_json) VALUES (?, ?, ?)",
                    (datetime.now().isoformat(), audit_type, json.dumps(findings)),
                )
                conn.commit()
        except sqlite3.Error:
            pass


def get_scan_history(limit=50):
    """Return recent scan history as list of dicts."""
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
    except sqlite3.Error:
        return []


def get_quarantine_history(limit=50):
    """Return recent quarantine history as list of dicts."""
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM quarantine_history ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
    except sqlite3.Error:
        return []


def get_audit_history(limit=20):
    """Return recent audit history as list of dicts."""
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_history ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
    except sqlite3.Error:
        return []