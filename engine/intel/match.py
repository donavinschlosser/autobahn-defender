"""Intel match — join feeds against installed packages → alerts.

Chain (deterministic, cheap):
  1. Installed pkg+version (dpkg-query)
  2. OSV.dev batch query → vulnerable (CVE, pkg, installed, fixed_in)  [reuse engine.cve]
  3. KEV membership → severity CRITICAL + exploited (+ransomware flag)
  4. USN presence  → severity HIGH floor
  5. Public PoC    → bump one level, tag public_poc
  6. EPSS          → annotate (never sole criterion)
Dedup key: cve|pkg|status; alerts fire on NEW keys only.
"""
from __future__ import annotations

import logging
from typing import Any

from .. import cve as cve_mod
from . import kev as kev_mod
from . import store

log = logging.getLogger(__name__)

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 0}


def _bump(sev: str) -> str:
    order = ["INFO", "LOW", "MEDIUM", "HIGH"]
    try:
        i = order.index(sev)
    except ValueError:
        return "HIGH"
    return order[min(i + 1, len(order) - 1)]


def check_system(limit_packages: int = 4000) -> dict[str, Any]:
    """Full join: installed pkgs → OSV → KEV/PoC/EPSS enrichment → alerts."""
    ecosystem = cve_mod.detect_ecosystem()
    if ecosystem == "UNKNOWN":
        return {"ok": False,
                "error": "Unknown distro release — intel match aborted (results "
                         "would be wrong). Fix /etc/os-release or report this OS.",
                "matches": []}

    packages = cve_mod.get_installed_packages()
    if not packages:
        return {"ok": False, "error": "no packages detected (dpkg-query failed)",
                "matches": []}

    # cap query size for safety; OSV handles thousands fine
    scan_list = packages[:limit_packages]
    scan = cve_mod.scan_cves(packages=scan_list, ecosystem=ecosystem)
    vulns = scan.get("vulnerabilities") or []
    warnings = list(scan.get("warnings") or [])

    all_cves = {v.get("cve_id") for v in vulns if v.get("cve_id")}
    kev_hits = kev_mod.all_kev_cves() & all_cves
    poc_hits = store.poc_contains(all_cves)
    epss_map = store.epss_for(all_cves)

    matches = []
    new_alerts = 0
    for v in vulns:
        cve_id = v.get("cve_id") or ""
        pkg = v.get("app_name") or ""
        installed = v.get("installed_version") or ""
        fixed_in = v.get("fixed_in") or ""

        in_kev = cve_id in kev_hits
        has_poc = cve_id in poc_hits
        epss = epss_map.get(cve_id)

        # Severity chain: KEV dominates; USN floor HIGH; PoC bumps
        sev = "HIGH"
        if in_kev:
            sev = "CRITICAL"
        elif has_poc:
            sev = _bump(sev)

        kev_meta = store.kev_contains({cve_id}).get(cve_id, {}) if in_kev else {}
        ransomware = kev_meta.get("known_ransomware") == "Known"

        title_bits = []
        if in_kev:
            title_bits.append("ACTIVELY EXPLOITED (CISA KEV)")
        if has_poc:
            title_bits.append("public PoC available")
        if epss is not None and epss >= 0.5:
            title_bits.append(f"EPSS {epss:.2f}")

        title = (f"{cve_id} in {pkg} {installed}"
                 + (" — " + ", ".join(title_bits) if title_bits else ""))

        action_bits = []
        if fixed_in and v.get("esm_only"):
            action_bits.append(
                f"Fix {fixed_in} exists only in Ubuntu Pro/ESM (requires an "
                "Ubuntu Pro token: sudo pro attach). Not fixed by plain apt updates.")
        elif fixed_in:
            action_bits.append(f"sudo apt update && sudo apt install --only-upgrade {pkg}")
        else:
            action_bits.append("No fixed version published yet — monitor the advisory.")
        if ransomware:
            action_bits.append("Known ransomware campaign — treat as urgent.")

        match = {
            "cve_id": cve_id, "package": pkg, "installed": installed,
            "fixed_in": fixed_in, "severity": sev,
            "exploited": bool(in_kev), "public_poc": bool(has_poc),
            "epss": epss, "ransomware": ransomware,
            **({"esm_only": True} if v.get("esm_only") else {}),
            "title": title,
        }
        matches.append(match)

        alert = {
            "cve_id": cve_id, "package": pkg, "fixed_in": fixed_in,
            "severity": sev, "exploited": in_kev, "public_poc": has_poc,
            "epss": epss, "status": "open",
            "title": title,
            "action": "; ".join(action_bits),
            "created_at": v.get("seen_at"),
        }
        if store.add_alert(alert):
            new_alerts += 1
            # Surface into the main alert system (lifecycle + GUI Alert Center)
            _emit_engine_alert(match)

    # Self-healing: close active intel alerts whose CVE is no longer reported
    # vulnerable by the fresh scan (fixed upstream, package removed, or the
    # old alert came from the broken fixed_in="" era). Without this, the
    # Alert Center accumulates years-old CVEs that never re-validate.
    from .. import alerts as alerts_mod
    still_open = {m["cve_id"] for m in matches}
    try:
        resolved = alerts_mod.auto_resolve_alerts(still_open, reason="intel re-check")
    except Exception as e:
        log.debug("auto-resolve pass failed: %s", e)
        resolved_count = 0
    else:
        resolved_count = resolved
    summary = {
        "ecosystem": ecosystem,
        "packages_checked": scan.get("packages_checked", len(scan_list)),
        "vulnerabilities": scan.get("vulnerabilities_found", len(vulns)),
        "kev_matches": sum(1 for m in matches if m["exploited"]),
        "poc_matches": sum(1 for m in matches if m["public_poc"]),
        "new_alerts": new_alerts,
        "matches": len(matches),
        "auto_resolved": resolved_count,
    }
    return {"ok": True, "summary": summary, "matches": matches,
            "warnings": warnings}


def _emit_engine_alert(match: dict[str, Any]) -> None:
    """Push the match into the engine alerts JSONL (GUI Alert Center + CLI)."""
    try:
        from ..alerts import create_alert, add_alert
        sev = match["severity"].lower()
        if match.get("ransomware"):
            action = ("URGENT (ransomware campaign): update "
                      f"'{match['package']}' now: sudo apt update && "
                      f"sudo apt install --only-upgrade {match['package']}")
        elif match.get("fixed_in") and match.get("esm_only"):
            action = (f"Fix {match['fixed_in']} is only in Ubuntu Pro/ESM — "
                      "requires `sudo pro attach` (or ignore if you accept the risk).")
        elif match.get("fixed_in"):
            action = (f"sudo apt update && sudo apt install --only-upgrade "
                      f"{match['package']}")
        else:
            action = (f"No patch yet — monitor https://osv.dev/vulnerability/"
                      f"{match['cve_id']}")
        add_alert(create_alert(
            severity=sev,
            title=match["title"],
            recommended_action=action,
            affected_package=match.get("package", ""),
            installed_version=match.get("installed", ""),
            patch_available=bool(match.get("fixed_in") and not match.get("esm_only")),
            source="intel",
            cve_id=match.get("cve_id", ""),
        ))
    except Exception as e:
        log.debug("alert fan-out failed: %s", e)