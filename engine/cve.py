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
_OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
_OSV_DETAIL_URL = "https://api.osv.dev/v1/vulns/"
_BATCH_SIZE = 1000
_MAX_RETRIES = 3
_TIMEOUT = 30


def detect_ecosystem() -> str:
    """Detect the OSV ecosystem string from /etc/os-release.

    Audit 2026-08-31 B-6 fix: the old hand-coded if/elif only knew 2024-era
    releases and silently defaulted unknown systems to Ubuntu:24.04 (wrong
    fixed versions => wrong verdicts). Now parses VERSION_ID generically and
    never guesses silently — unknown systems return "UNKNOWN" and callers
    display a warning.
    """
    info = {}
    try:
        content = Path("/etc/os-release").read_text()
        for line in content.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                info[k.strip()] = v.strip().strip('"')
    except OSError:
        pass

    distro_id = (info.get("ID") or "").lower()
    version_id = info.get("VERSION_ID") or ""
    distro_like = (info.get("ID_LIKE") or "").lower()

    # Linux Mint (and LMDE) map to their Ubuntu/Debian base
    if "linuxmint" in info.get("ID", "").lower() or "mint" in distro_like:
        try:
            major = int(version_id.split(".")[0])
        except (ValueError, IndexError):
            major = 0
        return {
            22: "Ubuntu:24.04", 21: "Ubuntu:22.04", 20: "Ubuntu:20.04",
        }.get(major, f"LinuxMint:{version_id}")
    if "lmde" in (info.get("NAME") or "").lower() or "lmde" in version_id.lower():
        return "Debian:12"  # LMDE 6 = bookworm

    if distro_id == "ubuntu" or "ubuntu" in distro_like:
        return f"Ubuntu:{version_id}" if version_id else "UNKNOWN"
    if distro_id == "debian" or "debian" in distro_like:
        return f"Debian:{version_id}" if version_id else "Debian:12"

    return "UNKNOWN"


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


def _enrich_from_details(vuln: dict, pkg: dict, ecosystem: str) -> dict[str, Any]:
    """Fetch the full OSV record for one advisory and apply the installed
    version against its real Ubuntu 24.04 ranges.

    Why this exists: OSV's *batch* endpoint (/v1/querybatch) returns only
    {id, modified} — no package ranges — so fixed-version detection used to
    run on empty data and every returned advisory became an alert with
    fixed_in="" ("No patch available"), including CVEs fixed years ago.

    ESM handling: on Ubuntu, fixes sometimes live only in Pro/ESM
    (Ubuntu:Pro:24.04:LTS, fixed version carries ~esm / ~ppa suffix). Those
    are NOT installable by plain apt without an Ubuntu Pro token, so the
    advisory is reported with patch_available=False and an esm=True note
    instead of claiming the system is patched by archive updates.
    """
    from .versions import is_version_at_least

    vid = vuln.get("id", "")
    try:
        r = requests.get(f"{_OSV_VULN_URL}/{vid}", timeout=_TIMEOUT,
                         headers={"User-Agent": "AutobahnDefender/2.0"})
        if r.status_code != 200:
            return {}
        full = r.json()
    except Exception as e:
        log.warning("OSV detail fetch %s failed: %s", vid, e)
        return {}

    archive_fixed = ""
    esm_fixed = ""
    matched_our_pkg = False
    pro_eco = f"Ubuntu:Pro:{ecosystem.split(':', 1)[1]}" if ecosystem.startswith("Ubuntu:") else ""
    for affected in full.get("affected", []):
        p = affected.get("package", {})
        eco = p.get("ecosystem", "")
        if eco not in (ecosystem, pro_eco):
            continue
        # Misattribution guard: OSV pairs advisories with packages by index in
        # some flows; verify the advisory block actually names the package we
        # queried (Ubuntu source-package name). If it names a different package
        # (e.g. bouncycastle CVE attached to a binutils query), drop it.
        if (p.get("name") or "").lower() != pkg["name"].lower():
            # allow binary-name matches (esm binaries list)
            bins = {b.get("binary_name", "").lower()
                    for b in affected.get("ecosystem_specific", {}).get("binaries", [])}
            if pkg["name"].lower() not in bins:
                continue
        matched_our_pkg = True
        is_esm_block = eco.startswith("Ubuntu:Pro")
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    if is_esm_block:
                        esm_fixed = esm_fixed or event["fixed"]
                    else:
                        archive_fixed = archive_fixed or event["fixed"]
        # ESM fixes often live only in ecosystem_specific.binaries metadata
        # (events list just has introduced:0). Grab the fixed binary version.
        if is_esm_block and not esm_fixed:
            for b in affected.get("ecosystem_specific", {}).get("binaries", []):
                if (b.get("binary_name", "").lower() == pkg["name"].lower()
                        and b.get("binary_version")):
                    esm_fixed = esm_fixed or b["binary_version"]
                    break

    if not matched_our_pkg:
        # Advisory doesn't actually cover this package on this release —
        # OSV matched on a range with no fixed boundary (introduced: 0).
        return {"_drop_mismatch": True}

    out = {}
    # carry over the full record's display fields (batch response lacks them)
    if full.get("aliases"):
        out["aliases"] = full["aliases"]
    if full.get("summary"):
        out["summary"] = full["summary"]
    if full.get("severity"):
        out["severity"] = full["severity"]
    if archive_fixed:
        out["fixed_in"] = archive_fixed
        # Installed already >= fix → not affected at all.
        if is_version_at_least(pkg["version"], archive_fixed):
            out["_not_affected"] = True
    elif esm_fixed:
        out["fixed_in"] = esm_fixed
        out["esm_only"] = True
        if is_version_at_least(pkg["version"], esm_fixed):
            out["_not_affected"] = True
    return out


def query_osv(packages: list[dict[str, str]], ecosystem: str | None = None) -> list[dict[str, Any]]:
    """Batch query OSV.dev for vulnerabilities, then enrich each advisory
    with its full record (the batch endpoint returns id+modified only).

    Args:
        packages: list of {"name": ..., "version": ...}
        ecosystem: OSV ecosystem string (auto-detected if None)

    Returns:
        list of vulnerability dicts with keys:
        cve_id, app_name, installed_version, fixed_in, summary, severity
        (+ esm_only=True when a matching fix exists only in Ubuntu Pro/ESM;
         + _not_affected=True when the installed version is already >= fix)
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
                        enriched = _enrich_from_details(v, pkg, ecosystem)
                        if enriched.get("_not_affected") or enriched.get("_drop_mismatch"):
                            continue
                        enriched.pop("_not_affected", None)
                        all_results.append(
                            _normalize_osv_vuln({**v, **enriched}, pkg, ecosystem))
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
    aliases = vuln.get("aliases", []) or []
    canonical_cve = ""
    if not cve_id.startswith("CVE-"):
        for alias in aliases:
            if alias.startswith("CVE-"):
                canonical_cve = alias
                break
    # Keep the original ID for dedup but use canonical CVE for display
    display_id = canonical_cve if canonical_cve else cve_id

    # fixed_in may be precomputed by _enrich_from_details (which fetched the
    # full record with real Ubuntu ranges). Only fall back to parsing the
    # vuln dict's own affected block when no enrichment happened.
    fixed_in = vuln.get("fixed_in") or ""
    esm_only = bool(vuln.get("esm_only"))
    last_affected = ""
    if not vuln.get("fixed_in"):
        for affected in vuln.get("affected", []):
            if affected.get("package", {}).get("ecosystem") != ecosystem:
                continue
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
        **({"esm_only": True} if esm_only else {}),
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

    warnings = []
    if ecosystem == "UNKNOWN":
        warnings.append(
            "Could not identify the distro release from /etc/os-release — "
            "CVE results may be wrong. Please report this OS to the project.")
        log.warning("scan_cves: ecosystem UNKNOWN; results may be unreliable")

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
        "warnings": warnings,
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