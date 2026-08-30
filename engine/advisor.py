"""
Autobahn Defender — Deterministic security advisor.

Replaces the AI worker (ai/worker.py) with a rule-based runbook engine.
Executes checks in order, scores findings, and renders reports in the
same [SEVERITY] Title / What / Why / How to fix format the AI produced.

No AI model, no Ollama, no streaming tokens. Pure deterministic.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from . import checks as check_mod
from . import cve as cve_mod
from . import patches as patch_mod

log = logging.getLogger(__name__)

# Severity weights for scoring (same as the v2 AI prompt rules)
_SEVERITY_WEIGHTS = {
    "critical": 20,
    "high": 10,
    "medium": 5,
    "low": 2,
    "info": 0,
}


@dataclass
class Finding:
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    what: str
    why: str
    fix: str
    source: str = ""


@dataclass
class AuditResult:
    task_id: str
    score: int
    findings: list[Finding] = field(default_factory=list)
    raw_results: dict[str, Any] = field(default_factory=dict)
    report_markdown: str = ""
    report_html: str = ""


# Task definitions — maps button IDs to ordered check lists
# Condensed from 6 to 4 to eliminate redundancy:
#   - full_audit: comprehensive (includes everything)
#   - vulnerability_scan: CVE + patch + update status (dedicated)
#   - network_audit: network-specific (no overlap with full_audit)
#   - hardening_audit: hardening-specific (no overlap with full_audit)
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
            report_markdown=f"Unknown task: {task_id}",
        )

    findings: list[Finding] = []
    raw_results: dict[str, Any] = {}

    for check_name in task["checks"]:
        if check_name == "vulnerability_scan":
            # Special handling: run CVE scan + patch check + update status
            result = _run_vulnerability_scan()
            raw_results["vulnerability_scan"] = result
            findings.extend(_analyze_vulnerability_scan(result))
        else:
            result = check_mod.run_check(f"check_{check_name}", {})
            raw_results[check_name] = result
            findings.extend(_analyze_check(check_name, result))

    # Deduplicate findings by (severity, title)
    seen = set()
    unique = []
    for f in findings:
        key = (f.severity, f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique

    # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: sev_order.get(f.severity, 99))

    # Calculate score
    score = 100
    has_perm_error = False
    for f in findings:
        weight = _SEVERITY_WEIGHTS.get(f.severity.lower(), 0)
        score -= weight
        if "permission" in f.what.lower() or "root" in f.what.lower():
            has_perm_error = True
    score = max(0, score)
    if has_perm_error and score > 89:
        score = 89

    result = AuditResult(
        task_id=task_id,
        score=score,
        findings=findings,
        raw_results=raw_results,
    )
    result.report_markdown = _render_markdown(result, task)
    result.report_html = _render_html(result, task)
    return result


def _run_vulnerability_scan() -> dict[str, Any]:
    """Run the composite vulnerability scan (CVE + patches + updates)."""
    result: dict[str, Any] = {}

    # CVE scan
    try:
        cve_result = cve_mod.scan_cves()
        result["cve"] = cve_result
    except Exception as e:
        result["cve"] = {"error": str(e)}

    # Patch availability
    try:
        patch_result = patch_mod.check_for_fixes()
        result["patches"] = patch_result
    except Exception as e:
        result["patches"] = {"error": str(e)}

    # Update status
    try:
        update_result = check_mod.run_check("check_update_status", {})
        result["updates"] = update_result
    except Exception as e:
        result["updates"] = {"error": str(e)}

    return result


def _analyze_vulnerability_scan(result: dict[str, Any]) -> list[Finding]:
    """Generate findings from the vulnerability scan results."""
    findings = []

    cve_data = result.get("cve", {})
    if cve_data.get("vulnerabilities_found", 0) > 0:
        vulns = cve_data.get("vulnerabilities", [])
        for v in vulns[:20]:  # Top 20
            cve_id = v.get("cve_id", "Unknown")
            pkg = v.get("app_name", "Unknown")
            installed = v.get("installed_version", "?")
            fixed_in = v.get("fixed_in", "")
            summary = v.get("summary", "")[:200]

            severity = "HIGH"
            if v.get("severity") and "CRITICAL" in str(v.get("severity", "")).upper():
                severity = "CRITICAL"
            elif v.get("severity") and "MEDIUM" in str(v.get("severity", "")).upper():
                severity = "MEDIUM"

            fix_cmd = ""
            if fixed_in:
                fix_cmd = f"sudo apt update && sudo apt upgrade {pkg}"
            else:
                fix_cmd = f"No patch available. Check https://nvd.nist.gov/vuln/detail/{cve_id}"

            findings.append(Finding(
                severity=severity,
                title=f"CVE: {cve_id} affects {pkg} {installed}",
                what=f"Package {pkg} (installed: {installed}) is vulnerable to {cve_id}. {summary}",
                why=f"This vulnerability could allow an attacker to compromise the system "
                    f"through {pkg}.",
                fix=fix_cmd,
                source="vulnerability_scan",
            ))
    elif cve_data.get("error"):
        findings.append(Finding(
            severity="LOW",
            title="CVE scan error",
            what=f"CVE scan failed: {cve_data['error']}",
            why="Unable to check for known vulnerabilities.",
            fix="Check network connectivity and try again.",
            source="vulnerability_scan",
        ))

    # Patch findings
    patch_data = result.get("patches", {})
    if patch_data.get("fixes_available", 0) > 0:
        for detail in patch_data.get("details", []):
            if detail.get("status") == "fix_available":
                findings.append(Finding(
                    severity="MEDIUM",
                    title=f"Patch available: {detail['package']} ({detail['cve_id']})",
                    what=f"Update available for {detail['package']}: "
                         f"{detail['installed']} -> {detail['available']}",
                    why="Installing this update will resolve the vulnerability.",
                    fix=detail.get("fix_command", f"sudo apt upgrade {detail['package']}"),
                    source="vulnerability_scan",
                ))

    # Update status findings
    update_data = result.get("updates", {})
    if update_data.get("status") == "ok":
        data = update_data.get("data", {})
        sec_updates = data.get("security_updates", 0)
        if sec_updates > 0:
            findings.append(Finding(
                severity="HIGH",
                title=f"{sec_updates} security updates available",
                what=f"There are {sec_updates} pending security updates.",
                why="Security updates patch known vulnerabilities. "
                    "Delaying installation leaves the system exposed.",
                fix="sudo apt update && sudo apt upgrade",
                source="vulnerability_scan",
            ))

    return findings


def _analyze_check(check_name: str, result: dict[str, Any]) -> list[Finding]:
    """Generate findings from a check result.

    This is a heuristic analyzer that looks at the check output and
    generates findings based on common patterns. Each check's output
    is analyzed for error conditions and known issue patterns.
    """
    findings = []

    if result.get("status") != "ok":
        # Check failed — report as LOW finding
        findings.append(Finding(
            severity="LOW",
            title=f"Check failed: {check_name}",
            what=f"Check {check_name} returned an error: {result.get('error', 'unknown')}",
            why="Unable to complete this security check. The system may have "
                "an issue that prevents analysis.",
            fix="Try running: sudo autobahn-defender",
            source=check_name,
        ))
        return findings

    data = result.get("data", {})

    # System audit specific analysis
    if check_name == "system_audit":
        findings.extend(_analyze_system_audit(data))
    elif check_name == "scan_persistence":
        findings.extend(_analyze_persistence(data))
    elif check_name == "check_hosts":
        findings.extend(_analyze_hosts(data))
    elif check_name == "network_security":
        findings.extend(_analyze_network_security(data))
    elif check_name == "ssh_audit":
        findings.extend(_analyze_ssh(data))
    elif check_name == "hardening_audit":
        findings.extend(_analyze_hardening(data))
    elif check_name == "privacy_hardening":
        findings.extend(_analyze_privacy(data))
    elif check_name == "dns_check":
        findings.extend(_analyze_dns(data))
    elif check_name == "disk_encryption":
        findings.extend(_analyze_disk_encryption(data))
    elif check_name == "startup_manager":
        findings.extend(_analyze_startup(data))

    return findings


def _analyze_system_audit(data: dict) -> list[Finding]:
    """Analyze system audit results and generate findings."""
    findings = []

    # Firewall
    fw = data.get("firewall", {})
    if fw.get("status") == "ok":
        output = fw.get("data", {}).get("output", "")
        if "inactive" in output.lower() or "Status: inactive" in output:
            findings.append(Finding(
                severity="HIGH",
                title="Firewall is inactive",
                what="The system firewall (UFW/iptables) is not active.",
                why="Without a firewall, all ports are exposed to network traffic. "
                    "Any listening service is accessible from the network.",
                fix="sudo ufw enable && sudo ufw default deny incoming",
                source="system_audit",
            ))

    # AppArmor
    aa = data.get("apparmor", {})
    if aa.get("status") == "ok":
        output = aa.get("data", {}).get("output", "")
        if "complain" in output.lower():
            findings.append(Finding(
                severity="MEDIUM",
                title="AppArmor profiles in complain mode",
                what="Some AppArmor profiles are in complain mode (logging only, not enforcing).",
                why="Complain mode means policy violations are logged but not blocked. "
                    "An attacker could exploit what should be blocked.",
                fix="sudo aa-enforce /etc/apparmor.d/*",
                source="system_audit",
            ))

    # Open ports
    ports = data.get("ports", {})
    if ports.get("status") == "ok":
        output = ports.get("data", {}).get("output", "")
        if "0.0.0.0" in output or "0.0.0.0:*" in output:
            findings.append(Finding(
                severity="MEDIUM",
                title="Services listening on all interfaces",
                what="Some services are bound to 0.0.0.0 (all network interfaces).",
                why="Services accessible on all interfaces are exposed to any "
                    "network the machine is connected to.",
                fix="Review the ports list and bind services to 127.0.0.1 if "
                    "they don't need external access.",
                source="system_audit",
            ))

    # Pending updates
    updates = data.get("updates", {})
    if updates.get("status") == "ok":
        output = updates.get("data", {}).get("output", "")
        if output.strip() and "upgradable" not in output.split("\n")[0].lower():
            count = len([l for l in output.splitlines() if l.strip()])
            if count > 0:
                findings.append(Finding(
                    severity="MEDIUM",
                    title=f"{count} pending updates",
                    what=f"There are {count} packages with available updates.",
                    why="Outdated packages may contain known vulnerabilities.",
                    fix="sudo apt update && sudo apt upgrade",
                    source="system_audit",
                ))

    # SSH config
    ssh = data.get("ssh_config", {})
    if ssh.get("status") == "ok":
        content = ssh.get("data", {}).get("content", "")
        if "PermitRootLogin yes" in content or "PermitRootLogin prohibit-password" in content:
            findings.append(Finding(
                severity="HIGH",
                title="SSH root login enabled",
                what="SSH permits root login. This is a security risk.",
                why="Direct root login via SSH allows brute-force attacks against "
                    "the most privileged account.",
                fix="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart SSH.",
                source="system_audit",
            ))
        if "PasswordAuthentication yes" in content or "PasswordAuthentication" not in content:
            findings.append(Finding(
                severity="MEDIUM",
                title="SSH password authentication enabled",
                what="SSH accepts password authentication.",
                why="Password authentication is vulnerable to brute-force attacks. "
                    "Key-based authentication is more secure.",
                fix="Set 'PasswordAuthentication no' in /etc/ssh/sshd_config",
                source="system_audit",
            ))

    # Auth log
    auth = data.get("auth_log", {})
    if auth.get("status") == "ok":
        tail = auth.get("data", {}).get("tail", "")
        failed_count = tail.lower().count("failed password")
        if failed_count > 5:
            findings.append(Finding(
                severity="MEDIUM",
                title=f"{failed_count} failed login attempts in recent log",
                what=f"Auth log shows {failed_count} failed password attempts.",
                why="Multiple failed logins may indicate a brute-force attack.",
                fix="Consider installing fail2ban: sudo apt install fail2ban",
                source="system_audit",
            ))

    return findings


def _analyze_persistence(data: dict) -> list[Finding]:
    """Analyze persistence scan results."""
    findings = []
    if isinstance(data, dict):
        suspicious = data.get("suspicious_entries", [])
        for entry in suspicious:
            findings.append(Finding(
                severity="HIGH",
                title=f"Suspicious persistence: {entry.get('type', 'unknown')}",
                what=entry.get("detail", "Suspicious persistence mechanism found."),
                why="This could be malware maintaining persistence across reboots.",
                fix=f"Review and remove if unwanted: {entry.get('path', '')}",
                source="scan_persistence",
            ))
    return findings


def _analyze_hosts(data: dict) -> list[Finding]:
    """Analyze hosts file check results."""
    findings = []
    if isinstance(data, dict):
        tampered = data.get("tampered", False)
        if tampered:
            redirects = data.get("redirects", [])
            for r in redirects:
                findings.append(Finding(
                    severity="HIGH",
                    title=f"Hosts file redirect: {r.get('domain', '?')} -> {r.get('ip', '?')}",
                    what=f"The hosts file redirects {r.get('domain')} to {r.get('ip')}.",
                    why="This could redirect legitimate traffic to a malicious server "
                        "(phishing, credential theft).",
                    fix="Edit /etc/hosts and remove the suspicious entry.",
                    source="check_hosts",
                ))
    return findings


def _analyze_network_security(data: dict) -> list[Finding]:
    """Analyze network security results."""
    findings = []
    if isinstance(data, dict):
        threats = data.get("threats", [])
        for t in threats:
            findings.append(Finding(
                severity="HIGH",
                title=f"Network threat: {t.get('ip', '?')} ({t.get('reason', 'blacklisted')})",
                what=f"Connection to suspicious IP {t.get('ip')} by process {t.get('process', '?')}.",
                why="This IP is on a threat blacklist. The connection may be malicious.",
                fix=f"Investigate the process and block the IP: sudo ufw deny out to {t.get('ip', '')}",
                source="network_security",
            ))
    return findings


def _analyze_ssh(data: dict) -> list[Finding]:
    """Analyze SSH audit results."""
    findings = []
    if isinstance(data, dict):
        issues = data.get("issues", [])
        for issue in issues:
            sev = "HIGH" if issue.get("severity", "").upper() in ("CRITICAL", "HIGH") else "MEDIUM"
            findings.append(Finding(
                severity=sev,
                title=f"SSH: {issue.get('setting', 'unknown')}",
                what=issue.get("detail", "SSH configuration issue."),
                why=issue.get("why", "This setting weakens SSH security."),
                fix=issue.get("fix", "Review and harden SSH configuration."),
                source="ssh_audit",
            ))
    return findings


def _analyze_hardening(data: dict) -> list[Finding]:
    """Analyze hardening audit results."""
    findings = []
    if isinstance(data, dict):
        issues = data.get("issues", [])
        for issue in issues:
            sev = issue.get("severity", "MEDIUM").upper()
            findings.append(Finding(
                severity=sev,
                title=f"Hardening: {issue.get('setting', 'unknown')}",
                what=issue.get("detail", "System hardening issue."),
                why=issue.get("why", "This setting leaves the system less protected."),
                fix=issue.get("fix", "Apply the recommended hardening setting."),
                source="hardening_audit",
            ))
    return findings


def _analyze_privacy(data: dict) -> list[Finding]:
    """Analyze privacy hardening results."""
    findings = []
    if isinstance(data, dict):
        issues = data.get("issues", [])
        for issue in issues:
            findings.append(Finding(
                severity="LOW",
                title=f"Privacy: {issue.get('setting', 'unknown')}",
                what=issue.get("detail", "Privacy setting issue."),
                why=issue.get("why", "This setting may leak usage data."),
                fix=issue.get("fix", "Adjust the privacy setting."),
                source="privacy_hardening",
            ))
    return findings


def _analyze_dns(data: dict) -> list[Finding]:
    """Analyze DNS check results."""
    findings = []
    if isinstance(data, dict):
        issues = data.get("issues", [])
        for issue in issues:
            findings.append(Finding(
                severity="MEDIUM",
                title=f"DNS: {issue.get('setting', 'unknown')}",
                what=issue.get("detail", "DNS configuration issue."),
                why=issue.get("why", "DNS misconfiguration can cause leaks or spoofing."),
                fix=issue.get("fix", "Adjust DNS configuration."),
                source="dns_check",
            ))
    return findings


def _analyze_disk_encryption(data: dict) -> list[Finding]:
    """Analyze disk encryption results."""
    findings = []
    if isinstance(data, dict):
        unencrypted = data.get("unencrypted_volumes", [])
        for vol in unencrypted:
            findings.append(Finding(
                severity="MEDIUM",
                title=f"Unencrypted volume: {vol.get('name', '?')}",
                what=f"Volume {vol.get('name')} is not encrypted.",
                why="Without encryption, data is accessible if the drive is physically "
                    "removed or the system is booted from external media.",
                fix="Consider enabling LUKS encryption (requires reinstall or reformat).",
                source="disk_encryption",
            ))
    return findings


def _analyze_startup(data: dict) -> list[Finding]:
    """Analyze startup manager results."""
    findings = []
    if isinstance(data, dict):
        suspicious = data.get("suspicious", [])
        for item in suspicious:
            findings.append(Finding(
                severity="MEDIUM",
                title=f"Suspicious startup: {item.get('name', '?')}",
                what=item.get("detail", "Suspicious startup item found."),
                why="This item runs at boot/login and may be unwanted software.",
                fix=f"Disable with: {item.get('disable_command', 'review manually')}",
                source="startup_manager",
            ))
    return findings


def _render_markdown(result: AuditResult, task: dict) -> str:
    """Render the audit result as markdown — same format as the AI output."""
    lines = []
    lines.append(f"# {task['label']}")
    lines.append("")
    lines.append(f"**Security Score: {result.score}/100**")
    lines.append("")

    if not result.findings:
        lines.append("No issues found. System appears secure.")
        return "\n".join(lines)

    lines.append(f"**{len(result.findings)} findings:**")
    lines.append("")

    for f in result.findings:
        lines.append(f"### [{f.severity}] {f.title}")
        lines.append("")
        lines.append(f"**What this means:** {f.what}")
        lines.append("")
        lines.append(f"**Why it matters:** {f.why}")
        lines.append("")
        lines.append(f"**How to fix it:** `{f.fix}`")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def _render_html(result: AuditResult, task: dict) -> str:
    """Render the audit result as HTML for the report template."""
    findings_html = []
    for f in result.findings:
        color = {
            "CRITICAL": "#FF4444",
            "HIGH": "#FF8800",
            "MEDIUM": "#FFCC00",
            "LOW": "#88AA00",
            "INFO": "#888888",
        }.get(f.severity, "#888888")
        findings_html.append(f"""
        <div class="finding" style="border-left: 4px solid {color}; padding: 12px; margin: 8px 0;">
            <h4 style="color: {color}; margin: 0 0 8px 0;">[{f.severity}] {f.title}</h4>
            <p><strong>What:</strong> {f.what}</p>
            <p><strong>Why:</strong> {f.why}</p>
            <p><strong>Fix:</strong> <code>{f.fix}</code></p>
        </div>""")

    return f"""
    <html>
    <head><meta charset="utf-8"><title>{task['label']}</title></head>
    <body style="font-family: sans-serif; background: #1a1a1a; color: #e0e0e0;">
        <h1>{task['label']}</h1>
        <h2>Security Score: {result.score}/100</h2>
        {''.join(findings_html) if findings_html else '<p>No issues found.</p>'}
    </body>
    </html>"""