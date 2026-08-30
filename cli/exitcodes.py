"""CLI exit codes (Phase 2.1) — the ClamAV/osv-scanner tri-state contract.

Documented in --help, the man page, and docs/AGENTS.md. Scripts and AI agents
branch on these. NEVER emit 126-255 (shell-owned codes).

    0   completed, no findings
    1   completed, findings present (or --fail-on threshold met)
    2   operational failure (I/O, network, engine timeout)
    64  usage error (bad arguments — sysexits EX_USAGE)
    130 interrupted by SIGINT
"""
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EX_USAGE = 64
EX_DATAERR = 65
EXIT_INTERRUPT = 130

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 0}


def exits_with_findings(findings, fail_on: str | None = None) -> int:
    """Decide the exit code for a completed scan/audit with findings.

    fail_on semantics (trivy-style opt-in gate): when set, exit 1 only if at
    least one finding meets or exceeds that severity.
    """
    if not findings:
        return EXIT_CLEAN
    if fail_on:
        threshold = _SEV_RANK.get(str(fail_on).upper(), 4)
        for f in findings:
            sev = str(f.get("severity", "UNKNOWN")).upper()
            if _SEV_RANK.get(sev, 0) >= threshold:
                return EXIT_FINDINGS
        return EXIT_CLEAN
    return EXIT_FINDINGS