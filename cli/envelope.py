"""JSON envelope for every machine-readable output (Phase 2.2 contract).

Shape (schema_version 1 — additive changes only within this major):
{
  "schema_version": 1,
  "tool": "autobahn-defender",
  "version": "2.0.2",
  "command": "cve",
  "created": "2026-08-31T12:00:00+00:00",
  "status": "ok" | "error",
  "degraded": false,
  "summary": {...},
  "results": [...]
}
Progress and human logs NEVER touch stdout in --format json mode.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any

from engine.version import APP_VERSION, DATA_SCHEMA_VERSION


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def envelope(command: str, results: list | dict | None = None,
             summary: dict | None = None, status: str = "ok",
             degraded: bool = False, warnings: list | None = None) -> dict[str, Any]:
    return {
        "schema_version": DATA_SCHEMA_VERSION,
        "tool": "autobahn-defender",
        "version": APP_VERSION,
        "command": command,
        "created": utc_now_iso(),
        "status": status,
        "degraded": degraded,
        "warnings": warnings or [],
        "summary": summary or {},
        "results": results if results is not None else [],
    }


def emit_json(document: dict[str, Any], output_file: str | None = None) -> None:
    """Write one JSON document (pretty) to the destination."""
    text = json.dumps(document, indent=2, ensure_ascii=False, default=str)
    _write(text + "\n", output_file)


def emit_ndjson(records: list[dict], output_file: str | None = None) -> None:
    """Write newline-delimited JSON records (one object per line)."""
    lines = []
    for rec in records:
        lines.append(json.dumps(rec, ensure_ascii=False, default=str))
    _write("\n".join(lines) + "\n", output_file)


def _write(text: str, output_file: str | None) -> None:
    # BrokenPipeError -> exit 141 per POSIX pipe convention (clig.dev).
    try:
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(text)
        else:
            sys.stdout.write(text)
            sys.stdout.flush()
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        raise SystemExit(141)


def progress(message: str, quiet: bool = False) -> None:
    """Progress/log lines on STDERR only (stdout is data)."""
    if quiet:
        return
    try:
        sys.stderr.write(f"[autobahn-defender] {message}\n")
        sys.stderr.flush()
    except BrokenPipeError:
        raise SystemExit(141)