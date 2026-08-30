"""Human-readable table rendering for CLI output (audit: honest, compact)."""
from __future__ import annotations

import shutil
import sys
from typing import Any

# NO_COLOR + per-fd isatty + TERM — clig.dev / no-color.org conventions.
_USE_COLOR = None


def use_color(args) -> bool:
    pref = getattr(args, "color", "auto")
    if pref == "never":
        return False
    if pref == "always":
        return True
    if __import__("os").environ.get("NO_COLOR"):
        return False
    if __import__("os").environ.get("TERM", "") == "dumb":
        return False
    return sys.stdout.isatty()


_SEV_COLORS = {
    "CRITICAL": "\033[1;31m", "HIGH": "\033[0;31m", "MEDIUM": "\033[0;33m",
    "LOW": "\033[0;32m", "INFO": "\033[0;36m", "UNKNOWN": "\033[0;90m",
}
_RESET = "\033[0m"


def render_table(doc: dict) -> str:
    """Render an envelope as a compact human table per command type."""
    cmd = doc.get("command", "")
    summary = doc.get("summary") or {}
    results = doc.get("results") or []
    lines = [f"Autobahn Defender {doc.get('version','')} — {cmd}"]

    if doc.get("degraded"):
        lines.append("DEGRADED — some checks returned errors; results incomplete.")
    for w in doc.get("warnings") or []:
        lines.append(f"WARNING: {w}")

    if cmd.startswith("audit"):
        lines.append(f"Security Score: {summary.get('score', '?')}/100")
        if not results:
            lines.append("No issues found.")
            return "\n".join(lines)
        lines.append("")
        for f in results:
            lines.append(f"[{f.get('severity')}] {f.get('title')}")
            if f.get("what"):
                lines.append(f"    What : {_one(f.get('what'))}")
            if f.get("why"):
                lines.append(f"    Why  : {f['why']}")
            if f.get("fix"):
                lines.append(f"    Fix  : {f['fix']}")
            lines.append("")
        lines.append(f"{len(results)} finding(s)")
        return "\n".join(lines)

    if cmd == "scan":
        lines.append(f"Files scanned : {summary.get('files_scanned', 0):,}")
        lines.append(f"Threats found : {summary.get('threats_found', 0)}")
        engines = summary.get("engines") or {}
        lines.append(f"Engines       : YARA={'yes' if engines.get('yara') else 'no'}, "
                     f"ClamAV={'yes' if engines.get('clamav') else 'no'}")
        for d in results:
            if d.get("action") in ("quarantine", "flag"):
                lines.append(f"  THREAT: {d.get('file')} — {d.get('threat')}")
            elif d.get("action") in ("error", "info"):
                lines.append(f"  [{d.get('action')}] {d.get('threat', '')}")
        return "\n".join(lines)

    if cmd == "cve":
        lines.append(f"Ecosystem       : {summary.get('ecosystem')}")
        lines.append(f"Packages checked: {summary.get('packages_checked', 0):,}")
        lines.append(f"Vulnerabilities : {summary.get('vulnerabilities_found', 0)} "
                     f"({summary.get('filtered_out', 0)} false positives filtered)")
        for v in results[:30]:
            fixed = v.get("fixed_in") or "(no fix published)"
            lines.append(f"  [{str(v.get('severity','?')):8}] {v.get('cve_id','')} "
                         f"in {v.get('app_name','')} {v.get('installed_version','')}"
                         f"  → fixed in {fixed_in_fmt(v.get('fixed_in'))}")
        if len(results) > 30:
            lines.append(f"  ... and {len(results) - 30} more (use --format json for all)")
        for w in doc.get("warnings") or []:
            lines.append(f"  WARNING: {w}")
        return "\n".join(lines)

    if cmd == "doctor":
        failed = summary.get("failed", 0)
        lines.append(f"doctor: {failed} failed / {summary.get('total', 0)} checks")
        for c in results:
            mark = "ok  " if c.get("ok") else "FAIL"
            lines.append(f"  [{'x' if c.get('ok') else ' '}] {c.get('check')}"
                         + (f" — {c.get('detail')}" if c.get("detail") else ""))
        return "\n".join(lines)

    # generic fallback: one line per result dict
    if summary:
        lines.append("  " + ", ".join(f"{k}={_fmt(v)}" for k, v in summary.items()))
    if isinstance(results, list):
        for row in results[:60]:
            if isinstance(row, dict):
                title = row.get("title") or row.get("issue") or row.get("check") or ""
                sev = row.get("severity", "")
                lines.append(f"  [{sev:8}] {str(title)[:110]}")
            elif isinstance(row, str):
                lines.append(f"  {row}")
    if not results:
        lines.append("(no results)")
    return "\n".join(lines)


def _fmt(v):
    if isinstance(v, bool):
        return "yes" if v else "no"
    return str(v)


def _one(s):
    return " ".join(str(s).split())


def fixed_in_fmt(v):
    return v or "(none)"