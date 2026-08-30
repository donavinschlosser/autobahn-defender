"""Advisor schema + scoring tests (audit A-5/B-1 regression guards)."""
import pytest

from engine import advisor
from engine.advisor import _findings_from_vuln_scan, result_to_dict


def _fake_run_check_factory(findings_by_check):
    def fake_run_check(name, args=None):
        short = name.replace("check_", "")
        return {"status": "ok", "data": findings_by_check.get(short, {"findings": []})}
    return fake_run_check


def test_hardening_audit_yields_findings_and_score(isolated_env, monkeypatch):
    data = {
        "privacy_hardening": {"findings": [
            {"severity": "high", "setting": "kernel.kptr_restrict",
             "issue": "Kernel pointer restriction too permissive",
             "fix": "sysctl -w kernel.kptr_restrict=2"},
            {"severity": "low", "setting": "fs.protected_fifos",
             "issue": "Protected FIFOs disabled", "fix": "sysctl -w fs.protected_fifos=2"},
        ]},
        "ssh_audit": {"installed": False, "note": "no sshd"},
        "mac_status": {"findings": []},
        "screen_lock": {"findings": [
            {"severity": "high", "issue": "Screen lock is disabled",
             "fix": "gsettings set org.gnome.desktop.screensaver lock-enabled true"}]},
        "password_policy": {"findings": []},
        "disk_encryption": {"findings": [
            {"severity": "high", "issue": "Root filesystem is NOT encrypted",
             "fix": "Consider LUKS"}]},
    }
    monkeypatch.setattr(advisor.check_mod, "run_check", _fake_run_check_factory(data))
    result = advisor.run_audit("hardening_audit")
    assert len(result.findings) >= 2
    assert any("Kernel pointer" in f.title for f in result.findings)
    assert not result.degraded
    # score = 100 - 10(H) - 2(L) = 88
    assert result.score <= 90
    assert "[HIGH]" in result.report_markdown
    # to_dict is JSON-safe
    d = advisor.result_to_dict(result)
    assert d["findings"][0]["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def test_unknown_task(isolated_env):
    result = advisor.run_audit("definitely_not_a_task")
    assert result.score == 0
    assert "Unknown task" in result.report_markdown


def test_dedup_and_order(isolated_env, monkeypatch):
    from engine import checks as check_mod

    def fake_run_check(name, args=None):
        if name == "check_dns_check":
            return {"status": "ok", "data": {"findings": [
                {"severity": "high", "issue": "dup finding"},
                {"severity": "high", "issue": "other high"},
                {"severity": "low", "issue": "low finding"},
            ]}}
        return {"status": "ok", "data": {}}

    monkeypatch.setattr(advisor.check_mod, "run_check", fake_run_check)
    result = advisor.run_audit("network_audit")
    titles = [f.title for f in result.findings]
    assert titles.count("dup finding") == 1, "dedup failed"
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
    ranks = [rank[f.severity] for f in result.findings]
    assert ranks == sorted(ranks)


def test_vuln_scan_cvss_becomes_critical():
    """B-1: a 9.8 CVSS vector must yield CRITICAL, not str-match HIGH."""
    res = {
        "cve": {
            "vulnerabilities": [{
                "cve_id": "CVE-2026-1000", "app_name": "openssl",
                "installed_version": "3.0.13", "fixed_in": "3.0.14",
                "summary": "test",
                "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }],
            "vulnerabilities_found": 1,
        },
    }
    out = advisor._findings_from_vuln_scan(res)
    assert len(out) == 1
    assert out[0].severity == "CRITICAL"
    assert "openssl" in out[0].fix


def test_vuln_scan_no_cvss_defaults_high():
    from engine.advisor import _findings_from_vuln_scan
    res = {"cve": {"vulnerabilities": [{
        "cve_id": "CVE-2026-1001", "app_name": "bash",
        "installed_version": "5.1", "fixed_in": "",
        "summary": "no vector",
        "severity": "",
    }]}}
    out = advisor._findings_from_vuln_scan(res)
    assert out[0].severity == "HIGH"  # default when no severity info


def test_patch_available_finding():
    res = {"cve": {}, "patches": {"fixes_available": 1, "details": [{
        "package": "curl", "cve_id": "CVE-2026-1001", "status": "fix_available",
        "installed": "1.0", "available": "1.1",
        "fix_command": "sudo apt upgrade curl",
    }]}}
    out = advisor._findings_from_vuln_scan(res)
    patch_findings = [f for f in out if f.check_id == "AD-PATCH-AVAIL"]
    assert len(patch_findings) == 1
    assert "Patch available" in patch_findings[0].title
    assert patch_findings[0].severity == "MEDIUM"