"""engine.runner — the verb implementations shared by GUI, CLI, and MCP.

Phase 1.2b: every front-end calls THESE functions; nobody re-implements
behavior. Functions return plain JSON-serializable dicts.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from .paths import QUARANTINE_DIR

log = logging.getLogger(__name__)

ProgressCb = Callable[[int, str], None]

# audit task label → engine.advisor task id (CLI names are user-facing)
_AUDIT_ALIASES = {
    "full": "full_audit",
    "vuln": "vulnerability_scan",
    "network": "network_audit",
    "hardening": "hardening_audit",
    # accept the engine IDs directly too
    "full_audit": "full_audit",
    "vulnerability_scan": "vulnerability_scan",
    "network_audit": "network_audit",
    "hardening_audit": "hardening_audit",
}


def run_scan(paths: list[str], quick: bool = False,
             progress_cb: ProgressCb | None = None) -> dict[str, Any]:
    """Run a malware scan over paths (YARA + ClamAV), headless-safe."""
    from . import scanner_core
    return scanner_core.scan_custom_paths(paths, quick=quick, progress_cb=progress_cb)


def run_scan_processes() -> dict[str, Any]:
    """Process-scan (yara/psutil-based miner + backdoor detection)."""
    from .checks import run_check
    res = run_check("check_running_processes", {})
    # The check emits process-listing text; the threat-analysis flavor lives in
    # scanner.py's ScanWorker (GUI). For the CLI we surface the classic
    # suspicious-name command pattern heuristics here:
    import re as _re
    details = []
    threats = 0
    if res.get("status") == "ok":
        out = res.get("data", {}).get("output", "")
        SUSPICIOUS = ("xmrig", "cpuminer", "minerd", "cgminer", "bfgminer",
                      "cryptonight", "ethminer", "claymore", "nicehash", "kthreaddi")
        for line in out.splitlines():
            low = line.lower()
            for s in SUSPICIOUS:
                if s in low:
                    details.append({"file": line.strip()[:120],
                                    "threat": f"Suspicious process: {s}",
                                    "action": "flag"})
                    threats += 1
                    break
    return {"threats_found": threats, "details": details}


def run_cve_scan(offline: bool = False) -> dict[str, Any]:
    """CVE scan (OSV.dev). offline: return cached-only marker (no network)."""
    from . import cve as cve_mod
    if offline:
        return {"ecosystem": cve_mod.detect_ecosystem(),
                "warnings": ["offline mode: no OSV query performed"],
                "packages_checked": 0, "vulnerabilities_found": 0,
                "raw_count": 0, "filtered_out": 0, "vulnerabilities": []}
    return cve_mod.scan_cves()


def run_patch_check() -> dict[str, Any]:
    from .patches import check_for_fixes
    return check_for_fixes()


def run_verify_patch(package: str, cve_id: str = "") -> dict[str, Any]:
    from .patches import verify_patch_applied
    return verify_patch_applied(package, cve_id)


def run_apply_batch(packages: list[str]) -> dict[str, Any]:
    from .apply import apply_batch
    return apply_batch(packages)


def run_audit(task_id: str) -> dict[str, Any]:
    from . import advisor
    canonical = _AUDIT_ALIASES.get(task_id, task_id)
    result = advisor.run_audit(canonical)
    d = advisor.result_to_dict(result)
    d["report_markdown"] = result.report_markdown
    d["report_html"] = result.report_html
    return d


def run_check_by_id(check_id: str, args: dict | None = None) -> dict[str, Any]:
    from .checks import run_check
    if not check_id.startswith("check_"):
        check_id = f"check_{check_id}"
    return run_check(check_id, args or {})


def run_quarantine_list() -> list[dict[str, Any]]:
    """List quarantined entries (read-only, no PyQt)."""
    import json
    manifest = QUARANTINE_DIR / "manifest.json"
    if not manifest.exists():
        return []
    try:
        data = json.loads(manifest.read_text())
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def run_quarantine_restore(quarantine_name: str) -> dict[str, Any]:
    from quarantine import QuarantineManager
    qm = QuarantineManager()
    ok, msg = qm.restore_file(quarantine_name)
    return {"success": ok, "message": msg, "name": quarantine_name}


def run_quarantine_delete(quarantine_name: str) -> dict[str, Any]:
    from quarantine import QuarantineManager
    qm = QuarantineManager()
    ok, msg = qm.delete_file(quarantine_name)
    return {"success": ok, "message": msg, "name": quarantine_name}


def run_network_action(action: str) -> dict[str, Any]:
    """connections | persistence | hosts | download-blacklist"""
    if action == "connections":
        from .network_watch import get_connections
        conns = get_connections()
        watch = _get_network_watch()
        threats = watch.scan() if watch else []
        note = ""
        if watch is not None and not watch.has_blacklist():
            note = ("No blacklist downloaded — threats list is empty. "
                    "Run: autobahn-defender network download-blacklist")
        return {"connections": conns, "threats": threats, "note": note}
    if action == "download-blacklist":
        watch = _get_network_watch()
        ok = watch.refresh_blacklist() if watch else False
        return {"ok": bool(ok), "source": "firehol_level1"}
    if action == "persistence":
        from .persistence import scan_persistence
        return scan_persistence()
    if action == "hosts":
        from .persistence import check_hosts_file
        return check_hosts_file()
    return {"error": f"unknown network action: {action}"}


def _get_network_watch():
    try:
        from .network_watch import NetworkWatch
        return NetworkWatch()
    except Exception:
        return None


def run_intel_poll(sources=None) -> dict[str, Any]:
    """Poll all (or selected) intel feeds and return the summary."""
    from .intel.poll import run_poll
    return run_poll(sources=sources)


def run_intel_check() -> dict[str, Any]:
    """Match the collected intel against installed packages."""
    from .intel.match import check_system
    return check_system()


def run_intel_show(limit: int = 40) -> dict[str, Any]:
    from .intel.store import recent_alerts
    return {"alerts": recent_alerts(limit=limit)}


def run_apply_action(action: str) -> dict[str, Any]:
    """Dispatch a privileged hardening action (review-first: CLI requires --yes,
    GUI shows the confirm dialog — both land here)."""
    from . import apply as apply_mod
    if action == "apparmor":
        return apply_mod.apparmor_enforce()
    if action == "fw-enable":
        return apply_mod.firewall_enable()
    if action == "fw-disable":
        return apply_mod.firewall_disable()
    if action == "sysctl":
        return apply_mod.sysctl_harden()
    if action == "ssh":
        return apply_mod.ssh_harden()
    return {"success": False, "error": f"unknown action {action}"}


def run_defs_update() -> dict[str, Any]:
    """ClamAV definitions update (headless: direct freshclam + system fallback)."""
    # The GUI's DefsUpdateWorker is QThread-based; a headless twin lives here.
    import subprocess
    from .scanner_core import find_freshclam
    freshclam = find_freshclam()
    if not freshclam:
        return {"success": False, "error": "freshclam not found — install clamav"}
    try:
        r = subprocess.run(
            ["pkexec", freshclam], capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            # pkexec absent / cancelled: non-elevated attempt (defs dir may be user-writable)
            r = subprocess.run([freshclam], capture_output=True, text=True, timeout=600)
        return {"success": r.returncode == 0,
                "output": (r.stdout or r.stderr or "")[-1000:]}
    except FileNotFoundError:
        return {"success": False, "error": "pkexec/freshclam missing"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "definition update timed out"}


def run_yara_update() -> dict[str, Any]:
    """YARA rules update (Codeberg). Headless variant of yara_updater."""
    from .yara_headless import update_rules
    return update_rules()