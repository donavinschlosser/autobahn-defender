"""
Autobahn Defender — Deterministic security advisor (v2, schema-unified).

P0 rewrite (audit 2026-08-31): the v1 advisor had 9 hand-written analyzers
that read dict keys the checks never returned — 8 of 9 silently produced
nothing and security reports said "No issues found" on broken systems. This
version consumes the unified `findings` list every check now emits
(engine.checks returns {"findings": [...]} per P0.3) plus small per-check
fallback shims for the legacy shapes. No AI model, no Ollama, no heuristics
drift: one schema end-to-end (engine/findings.Finding).
"""
from __future__ import annotations

import html
import logging
from dataclasses import asdict, dataclass, field
from typing import Any

from . import checks as check_mod
from . import cve as cve_mod
from . import findings as findings_mod
from . import patches as patch_mod
from .findings import Finding

log = logging.getLogger(__name__)

# Severity weights for scoring (same as the v2 AI prompt rules)
_SEVERITY_WEIGHTS = {
    "critical": 20,
    "high": 10,
    "medium": 5,
    "low": 2,
    "info": 0,
    "unknown": 2,
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}


@dataclass
class AuditResult:
    task_id: str
    score: int
    findings: list[Finding] = field(default_factory=list)
    raw_results: dict[str, Any] = field(default_factory=dict)
    report_markdown: str = ""
    report_html: str = ""
    degraded: bool = False
    checks_run: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "score": self.score,
            "degraded": self.degraded,
            "checks_run": list(self.checks_run),
            "findings": [f.to_dict() for f in self.findings],
            "report_markdown": self.report_markdown,
            "report_html": self.report_html,
        }


# Task definitions — maps button IDs to ordered check lists
# Condensed from 6 to 4 to eliminate redundancy (v2 bugfix note #5).
TASK_DEFS: dict[str, dict[str, Any]] = {
    "full_audit": {
        "label": "Full Security Audit",
        "checks": [
            "system_audit",
            "scan_persistence",
            "check_hosts",
            "network_security",
            "ssh_audit",
            "hardening_audit",
            "kernel_info",
            "disk_encryption",
            "screen_lock",
            "password_policy",
        ],
        "description": "Comprehensive security audit covering all checks: firewall, "
                       "AppArmor, processes, ports, updates, SUID, SSH, kernel, auth "
                       "log, persistence, hosts file, network threats, hardening, "
                       "disk encryption, screen lock, and password policy.",
    },
    "vulnerability_scan": {
        "label": "Vulnerability Scan",
        "checks": ["vulnerability_scan"],
        "description": "Scan installed packages against OSV.dev for known CVEs, "
                       "check for available patches, and report update status. "
                       "False positives are filtered automatically.",
    },
    "network_audit": {
        "label": "Network Security Audit",
        "checks": ["network_security", "network_connections", "dns_check"],
        "description": "Analyze network connections, DNS configuration, and "
                       "threat monitoring.",
    },
    "hardening_audit": {
        "label": "Hardening Audit",
        "checks": ["hardening_audit", "privacy_hardening", "ssh_audit"],
        "description": "Check kernel hardening, sysctl settings, SSH config, "
                       "privacy settings, and disk encryption.",
    },
}


def run_audit(task_id: str) -> AuditResult:
    """Execute a task's checks in order and produce a scored report."""
    task = TASK_DEFS.get(task_id)
    if not task:
        return AuditResult(
            task_id=task_id, score=0,
            findings=[],
            report_markdown=f"Unknown task: {task_id}",
        )

    findings: list[Finding] = []
    raw_results: dict[str, Any] = {}
    checks_run: list[str] = []
    degraded = False

    for check_name in task["checks"]:
        if check_name == "vulnerability_scan":
            # Special handling: run CVE scan + patch check + update status
            result = _run_vulnerability_scan()
            raw_results["vulnerability_scan"] = result
            findings.extend(_findings_from_vuln_scan(result))
        else:
            result = check_mod.run_check(f"check_{check_name}", {})
            raw_results[check_name] = result
            checks_run.append(check_name)
            findings.extend(_findings_from_check(check_name, result))
            # Composite checks surface their own degraded flag
            if isinstance(result.get("data"), dict) and result["data"].get("degraded"):
                degraded = True

    # Deduplicate findings by (severity, title)
    seen: set[tuple[str, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.severity, f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique

    findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 99))

    # Calculate score
    score = 100
    has_perm_error = False
    for f in findings:
        score -= _SEVERITY_WEIGHTS.get(f.severity.lower(), 0)
        if "permission" in f.what.lower() or "root" in f.what.lower():
            has_perm_error = True
    score = max(0, score)
    if has_perm_error and score > 89:
        score = 89
    if degraded:
        score = min(score, 95)

    result = AuditResult(
        task_id=task_id,
        score=score,
        findings=findings,
        raw_results=raw_results,
        degraded=degraded,
        checks_run=checks_run,
    )
    result.report_markdown = _render_markdown(result, task)
    result.report_html = _render_html(result, task)
    return result


def result_to_dict(result: AuditResult) -> dict[str, Any]:
    """JSON-safe representation (CLI envelope + MCP)."""
    return {
        "task_id": result.task_id,
        "score": result.score,
        "degraded": result.degraded,
        "checks_run": result.checks_run,
        "findings": [f.to_dict() for f in result.findings],
    }


def _run_vulnerability_scan() -> dict[str, Any]:
    """Run the composite vulnerability scan (CVE + patches + updates)."""
    result: dict[str, Any] = {}
    try:
        result["cve"] = cve_mod.scan_cves()
    except Exception as e:
        result["cve"] = {"error": str(e)}
    try:
        result["patches"] = patch_mod.check_for_fixes()
    except Exception as e:
        result["patches"] = {"error": str(e)}
    try:
        result["updates"] = check_mod.run_check("check_update_status", {})
    except Exception as e:
        result["updates"] = {"error": str(e)}
    return result


def _findings_from_vuln_scan(result: dict[str, Any]) -> list[Finding]:
    """Generate findings from the vulnerability scan results."""
    out: list[Finding] = []

    cve_data = result.get("cve", {}) or {}
    vulns = cve_data.get("vulnerabilities", []) or []
    for v in vulns[:20]:
        cve_id = v.get("cve_id", "Unknown")
        pkg = v.get("app_name", "Unknown")
        installed = v.get("installed_version", "?")
        fixed_in = v.get("fixed_in", "")
        summary = (v.get("summary") or "")[:200]

        raw_sev = str(v.get("severity") or "")
        if raw_cvss := raw_sev if raw_sev.startswith("CVSS:") else "":
            score, label = findings_mod.parse_cvss31(raw_cvss)
            severity = label if label not in ("UNKNOWN", "NONE") else "HIGH"
        else:
            # OSV sometimes provides database_specific.severity labels upstream
            severity = findings_mod.normalize_severity(
                findings_mod.extract_score_text(raw_sev) or "HIGH")
            if severity == "UNKNOWN":
                severity = "HIGH"

        if fixed_in:
            fix_cmd = f"sudo apt update && sudo apt install --only-upgrade {pkg}"
        else:
            fix_cmd = f"No patch available yet — track: https://osv.dev/vulnerability/{cve_id}"

        out.append(Finding(
            severity=severity,
            check_id=f"AD-CVE-{cve_id}",
            title=f"CVE: {cve_id} affects {pkg} {installed}",
            what=f"Package {pkg} (installed {installed}) is vulnerable to {cve_id}. {summary}",
            why="This vulnerability could allow an attacker to compromise the "
                f"system through {pkg}.",
            fix=fix_cmd,
            source="vulnerability_scan",
            cve_id=cve_id,
            raw={"fixed_in": fixed_in, "installed": installed},
        ))

    if cve_data.get("error"):
        out.append(Finding(
            severity="LOW",
            check_id="AD-CVE-ERR",
            title="CVE scan error",
            what=f"CVE scan failed: {cve_data['error']}",
            why="Unable to check for known vulnerabilities.",
            fix="Check network connectivity and try again.",
            source="vulnerability_scan",
        ))

    patch_data = result.get("patches", {})
    if isinstance(patch_data, dict) and patch_data.get("fixes_available", 0) > 0:
        for detail in patch_data.get("details", []):
            if detail.get("status") == "fix_available":
                out.append(Finding(
                    severity="MEDIUM",
                    check_id="AD-PATCH-AVAIL",
                    title=f"Patch available: {detail['package']} ({detail['cve_id']})",
                    what=f"Update available for {detail['package']}: "
                         f"{detail['installed']} -> {detail['available']}",
                    why="Installing this update will resolve the vulnerability.",
                    fix=detail.get("fix_command", f"sudo apt upgrade {detail['package']}"),
                    source="vulnerability_scan",
                ))

    update_data = result.get("updates", {})
    if isinstance(update_data, dict) and update_data.get("status") == "ok":
        data = update_data.get("data", {})
        sec_updates = 0
        data = data or {}
        if isinstance(data, dict):
            for fd in data.get("findings", []):
                if "security updates available" in str(fd.get("issue", "")):
                    severity = "HIGH" if fd.get("severity") == "high" else "MEDIUM"
                    out.append(Finding(
                        severity="HIGH",
                        check_id="AD-UPD-SEC",
                        title=fd.get("issue", "Security updates available"),
                        what=fd.get("issue", "Pending security updates."),
                        why="Security updates patch known vulnerabilities; delaying "
                            "installation leaves the system exposed.",
                        fix="sudo apt update && sudo apt upgrade",
                        source="vulnerability_scan",
                    ))
                elif isinstance(fd, dict) and str(fd.get("severity", "")).lower() == "high":
                    out.append(_as_finding(fd, "update_status"))
    return out


def _as_finding(d: dict, source: str) -> Finding:
    """Convert a check finding dict into the canonical Finding."""
    sev = str(d.get("severity") or "MEDIUM").upper()
    if sev not in _SEV_ORDER and sev != "INFO":
        sev = "MEDIUM"
    if sev == "UNKNOWN":
        sev = "MEDIUM"
    # Prefer the most descriptive title field; fall back to a setting/indicator
    title = (d.get("title") or d.get("issue") or d.get("indicator")
             or d.get("indicator_detail")
             or (f"{d.get('setting')}: {d.get('description', '')}".strip(": ")
                 if d.get("setting") else "")
             or (f"{source}: {d.get('setting', 'finding')} needs attention"
                 if d.get("setting") else f"{source}: finding"))
    what = str(d.get("what") or d.get("detail") or d.get("issue") or title)
    why = d.get("why") or d.get("description") or ""
    fix = d.get("fix") or d.get("recommended_action") or ""
    return Finding(
        severity=sev,
        check_id=str(d.get("check_id", "") or "AD-" + source)[:32],
        title=str(title)[:300],
        what=str(what)[:800],
        why=str(why)[:800],
        fix=str(fix)[:500],
        source=source,
        cve_id=str(d.get("cve_id", "") or ""),
        exploited=bool(d.get("exploited", False)),
        raw={k: v for k, v in d.items()
             if k not in ("severity", "title", "what", "why", "fix", "cve_id")},
    )


def _findings_from_check(check_name: str, result: dict[str, Any]) -> list[Finding]:
    """Extract findings from a check result (unified schema, with fallbacks).

    P0.3: every composite/feature check now emits a unified `findings` list;
    this function consumes it, then falls back to check-shaped interpretation
    of any check that still lacks native findings.
    """
    if result.get("status") != "ok":
        return [Finding(
            severity="LOW",
            check_id=f"AD-CHK-{check_name}"[:24],
            title=f"Check failed: {check_name}",
            what=f"Check {check_name} returned an error: "
                 f"{str(result.get('error', 'unknown'))[:200]}",
            why="Unable to complete this security check. The system may have "
                "an issue that prevents analysis.",
            fix="Try running again as your user; if it persists, see the "
                "audit report for the degraded flag.",
            source=check_name,
        )]

    data = result.get("data", {})
    if not isinstance(data, dict):
        return []

    out: list[Finding] = []
    for fd in data.get("findings") or []:
        if not isinstance(fd, dict):
            continue
        if "status" in fd and fd.get("status") == "ok":
            continue  # informational OK entries
        out.append(_as_finding(fd, check_name))

    # The system_audit check keeps a composite of sub-results; its analyzer
    # is preserved (it reads keys that genuinely exist).
    if check_name == "system_audit":
        out.extend(_system_audit_findings(data))
    return out


def _system_audit_findings(data: dict) -> list[Finding]:
    """Analyze check_system_audit's composite output (keys verified live)."""
    out: list[Finding] = []

    fw = data.get("firewall", {})
    if fw.get("status") == "ok":
        output = fw.get("data", {}).get("output", "")
        if "status: inactive" in output.lower():
            out.append(Finding(
                severity="HIGH", check_id="AD-FW-001",
                title="Firewall is inactive",
                what="The system firewall (UFW/iptables) is not active.",
                why="Without a firewall, all listening services are exposed to "
                    "any network the machine joins.",
                fix="sudo ufw enable && sudo ufw default deny incoming",
                source="system_audit",
            ))

    aa = data.get("apparmor", {})
    if aa.get("status") == "ok":
        output = aa.get("data", {}).get("output", "")
        if "complain" in output.lower():
            out.append(Finding(
                severity="MEDIUM", check_id="AD-AA-001",
                title="AppArmor profiles in complain mode",
                what="Some AppArmor profiles are in complain mode (logging only).",
                why="Complain mode logs policy violations but does not block them.",
                fix="sudo aa-enforce /etc/apparmor.d/*",
                source="system_audit",
            ))

    ports = data.get("ports", {})
    if ports.get("status") == "ok":
        output = ports.get("data", {}).get("output", "")
        if "0.0.0.0" in output or "[::]:" in output:
            out.append(Finding(
                severity="MEDIUM", check_id="AD-NET-001",
                title="Services listening on all interfaces",
                what="Some services are bound to 0.0.0.0/[::].",
                why="Services accessible on all interfaces are exposed to any "
                    "network the machine is connected to.",
                fix="Review the ports list and bind services to 127.0.0.1 where "
                    "external access isn't required.",
                source="system_audit",
            ))

    ssh = data.get("ssh_config", {})
    if ssh.get("status") == "ok":
        content = ssh.get("data", {}).get("content", "")
        if "PermitRootLogin yes" in content:
            out.append(_as_finding({
                "severity": "HIGH", "title": "SSH root login enabled",
                "what": "SSH permits direct root login.",
                "why": "Root login over SSH allows brute-force attacks against "
                       "the most privileged account.",
                "fix": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config.d/",
            }, "ssh_config"))
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_SEV_COLORS = {
    "CRITICAL": "#FF4444", "HIGH": "#FF8800", "MEDIUM": "#FFCC00",
    "LOW": "#88AA00", "INFO": "#888888", "UNKNOWN": "#888888",
}


def _render_markdown(result: AuditResult, task: dict) -> str:
    lines = [f"# {task['label']}", ""]
    if result.degraded:
        lines.append("> ⚠ **DEGRADED** — some checks returned errors; "
                     "results may be incomplete.")
        lines.append("")
    lines.append(f"**Security Score: {result.score}/100**")
    lines.append("")

    if not result.findings:
        lines.append("No issues found.")
        return "\n".join(lines)

    lines.append(f"**{len(result.findings)} findings:**")
    lines.append("")
    for f in result.findings:
        lines.append(f"### [{f.severity}] {f.title}")
        lines.append("")
        if f.what:
            lines.append(f"**What this means:** {f.what}")
            lines.append("")
        if f.why:
            lines.append(f"**Why it matters:** {f.why}")
            lines.append("")
        if f.fix:
            lines.append(f"**How to fix it:** `{f.fix}`")
            lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)


def _render_html(result: AuditResult, task: dict) -> str:
    esc = html.escape
    findings_html = []
    for f in result.findings:
        color = _SEV_COLORS.get(f.severity, "#888888")
        findings_html.append(f"""
        <div class="finding" style="border-left: 4px solid {color}; padding: 12px; margin: 8px 0;">
            <h4 style="color: {color}; margin: 0 0 8px 0;">[{esc(f.severity)}] {esc(f.title)}</h4>
            <p><strong>What:</strong> {esc(f.what)}</p>
            {f'<p><strong>Why:</strong> {esc(f.why)}</p>' if f.why else ''}
            {f'<p><strong>Fix:</strong> <code>{esc(f.fix)}</code></p>' if f.fix else ''}
        </div>""")
    warn = ("<div style=\"background:#664400;padding:8px;border-radius:6px;"
            "margin-bottom:12px;\">DEGRADED — some checks returned errors.</div>"
            if result.degraded else "")
    return f"""
    <html>
    <head><meta charset="utf-8"><title>{esc(task['label'])}</title></head>
    <body style="font-family: sans-serif; background: #1a1a1a; color: #e0e0e0;">
        <h1>{esc(task['label'])}</h1>
        <h2>Security Score: {result.score}/100</h2>
        {warn}
        {''.join(findings_html) if findings_html else '<p>No issues found.</p>'}
    </body>
    </html>"""