"""
Autobahn Defender — CVE scanning via OSV.dev API + false-positive filtering.

Replaces the AI tool _t_cve_check with a deterministic local function.
Uses OSV.dev batch query API (free, no key required) and applies the
cve_filter module to suppress false positives.
"""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path
from typing import Any

import requests

from .cve_filter import is_likely_false_positive, deduplicate_cves

log = logging.getLogger(__name__)

_OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
_OSV_DETAIL_URL = "https://api.osv.dev/v1/vulns/"
_BATCH_SIZE = 1000
_MAX_RETRIES = 3
_TIMEOUT = 30


def detect_ecosystem() -> str:
    """Detect the OSV ecosystem string from /etc/os-release."""
    try:
        content = Path("/etc/os-release").read_text()
    except Exception:
        return "Ubuntu:24.04"  # Safe default

    # Map common distros to OSV ecosystem strings
    if "Ubuntu 24.04" in content or "Ubuntu 24.10" in content:
        return "Ubuntu:24.04"
    elif "Ubuntu 22.04" in content:
        return "Ubuntu:22.04"
    elif "Ubuntu 20.04" in content:
        return "Ubuntu:20.04"
    elif "Debian 12" in content or "Debian bookworm" in content:
        return "Debian:12"
    elif "Debian 11" in content or "Debian bullseye" in content:
        return "Debian:11"
    elif "Linux Mint 22" in content or "LMDE 6" in content:
        return "Ubuntu:24.04"  # Mint 22 is based on Ubuntu 24.04
    elif "Linux Mint 21" in content:
        return "Ubuntu:22.04"  # Mint 21 is based on Ubuntu 22.04
    elif "Linux Mint 20" in content:
        return "Ubuntu:20.04"
    return "Ubuntu:24.04"  # Default fallback


def get_installed_packages() -> list[dict[str, str]]:
    """Get list of installed packages with versions via dpkg-query."""
    try:
        r = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
            capture_output=True, text=True, timeout=30,
        )
        packages = []
        for line in (r.stdout or "").splitlines():
            if "\t" in line:
                name, ver = line.split("\t", 1)
                packages.append({"name": name, "version": ver})
        return packages
    except Exception as e:
        log.error("Failed to list packages: %s", e)
        return []


def query_osv(packages: list[dict[str, str]], ecosystem: str | None = None) -> list[dict[str, Any]]:
    """Batch query OSV.dev for vulnerabilities.

    Args:
        packages: list of {"name": ..., "version": ...}
        ecosystem: OSV ecosystem string (auto-detected if None)

    Returns:
        list of vulnerability dicts with keys:
        cve_id, app_name, installed_version, fixed_in, summary, severity
    """
    if not ecosystem:
        ecosystem = detect_ecosystem()
    if not packages:
        return []

    session = requests.Session()
    all_results: list[dict[str, Any]] = []

    for i in range(0, len(packages), _BATCH_SIZE):
        batch = packages[i:i + _BATCH_SIZE]
        queries = [
            {"package": {"name": p["name"], "ecosystem": ecosystem},
             "version": p["version"]}
            for p in batch
        ]

        for attempt in range(_MAX_RETRIES):
            try:
                r = session.post(
                    _OSV_QUERY_URL,
                    json={"queries": queries},
                    timeout=_TIMEOUT,
                )
                if r.status_code == 429:
                    time.sleep(2 ** attempt)
                    continue
                r.raise_for_status()
                batch_results = r.json().get("results", [])
                for pkg, res in zip(batch, batch_results):
                    for v in res.get("vulns", []):
                        all_results.append(_normalize_osv_vuln(v, pkg, ecosystem))
                break
            except requests.RequestException as e:
                log.warning("OSV batch %d attempt %d failed: %s", i, attempt, e)
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                else:
                    log.error("OSV batch %d exhausted retries", i)

    return all_results


def _normalize_osv_vuln(vuln: dict, pkg: dict, ecosystem: str) -> dict[str, Any]:
    """Normalize an OSV vulnerability entry into our standard format."""
    cve_id = vuln.get("id", "")
    # OSV may have aliases (e.g. CVE-XXXX-YYYY) — prefer canonical CVE ID
    aliases = vuln.get("aliases", [])
    canonical_cve = ""
    if not cve_id.startswith("CVE-"):
        for alias in aliases:
            if alias.startswith("CVE-"):
                canonical_cve = alias
                break
    # Keep the original ID for dedup but use canonical CVE for display
    display_id = canonical_cve if canonical_cve else cve_id

    # Extract fixed version and last_affected from affected ranges
    fixed_in = ""
    last_affected = ""
    is_affected = False
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("ecosystem") != ecosystem:
            continue
        # Check if the installed version is actually in the affected range
        is_affected = True
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed_in = event["fixed"]
                if "last_affected" in event:
                    last_affected = event["last_affected"]
            if fixed_in:
                break
        if fixed_in:
            break

    # If the installed version is past last_affected, it's not vulnerable
    if last_affected:
        try:
            from .versions import is_version_at_least
            if is_version_at_least(pkg["version"], last_affected):
                # Already past the vulnerable range — mark as not affected
                return {
                    "cve_id": display_id,
                    "app_name": pkg["name"],
                    "installed_version": pkg["version"],
                    "fixed_in": fixed_in or last_affected,
                    "summary": "",
                    "severity": "",
                    "aliases": aliases,
                    "_not_affected": True,  # signal to filter
                }
        except Exception:
            pass

    # Extract severity
    severity = ""
    for sev in vuln.get("severity", []):
        score = sev.get("score", "")
        if "CVSS_V3" in sev.get("type", "") or not severity:
            severity = score
            if "CVSS_V3" in sev.get("type", ""):
                break

    return {
        "cve_id": display_id,
        "app_name": pkg["name"],
        "installed_version": pkg["version"],
        "fixed_in": fixed_in,
        "summary": (vuln.get("summary", "") or "")[:500],
        "severity": severity,
        "aliases": aliases,
    }


def scan_cves(packages: list[dict[str, str]] | None = None,
              ecosystem: str | None = None,
              apply_filter: bool = True) -> dict[str, Any]:
    """Full CVE scan: query OSV, filter false positives, deduplicate.

    Returns:
        {
            "ecosystem": str,
            "packages_checked": int,
            "vulnerabilities_found": int,  # after filtering
            "raw_count": int,              # before filtering
            "filtered_out": int,
            "vulnerabilities": [...],      # filtered + deduplicated
        }
    """
    if packages is None:
        packages = get_installed_packages()
    if not ecosystem:
        ecosystem = detect_ecosystem()

    raw_vulns = query_osv(packages, ecosystem)
    raw_count = len(raw_vulns)

    if apply_filter:
        # Filter out entries marked as not_affected (installed version past vulnerable range)
        raw_vulns = [v for v in raw_vulns if not v.pop("_not_affected", False)]
        # Apply false-positive filter
        filtered = [v for v in raw_vulns if not is_likely_false_positive(v)]
        # Deduplicate
        filtered = deduplicate_cves(filtered)
    else:
        filtered = raw_vulns

    return {
        "ecosystem": ecosystem,
        "packages_checked": len(packages),
        "vulnerabilities_found": len(filtered),
        "raw_count": raw_count,
        "filtered_out": raw_count - len(filtered),
        "vulnerabilities": filtered[:200],  # cap for display
    }


def get_cve_detail(cve_id: str) -> dict[str, Any]:
    """Fetch detailed information for a single CVE from OSV.dev."""
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        return {"error": "Invalid CVE ID format. Expected CVE-YYYY-NNNNN."}

    try:
        r = requests.get(f"{_OSV_DETAIL_URL}{cve_id}", timeout=_TIMEOUT)
        if r.status_code == 404:
            return {"error": f"{cve_id} not found in OSV database."}
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return {"error": f"Failed to fetch {cve_id}: {e}"}

    # Extract CVSS scores
    cvss_v3 = ""
    cvss_v2 = ""
    for sev in data.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            cvss_v3 = sev.get("score", "")
        elif sev.get("type") == "CVSS_V2":
            cvss_v2 = sev.get("score", "")

    # Extract affected packages
    affected_packages = []
    for aff in data.get("affected", []):
        pkg = aff.get("package", {})
        affected_packages.append({
            "name": pkg.get("name", ""),
            "ecosystem": pkg.get("ecosystem", ""),
            "ranges": [
                event for rng in aff.get("ranges", [])
                for event in rng.get("events", [])
            ],
        })

    # Extract references
    refs = [ref.get("url", "") for ref in data.get("references", [])]

    return {
        "cve_id": cve_id,
        "summary": data.get("summary", ""),
        "details": (data.get("details", "") or "")[:2000],
        "cvss_v3": cvss_v3,
        "cvss_v2": cvss_v2,
        "published": data.get("published", ""),
        "modified": data.get("modified", ""),
        "affected_packages": affected_packages,
        "references": refs,
        "aliases": data.get("aliases", []),
    }