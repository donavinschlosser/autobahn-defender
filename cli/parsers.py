"""Autobahn Defender CLI — subcommand parsers (Phase 2.2).

Pure argparse, zero third-party deps. Each verb maps 1:1 onto an
engine.runner function (see runner.py). Exit codes live in cli/exitcodes.py
and are documented in the top-level help + man page.
"""
from __future__ import annotations

import argparse

from .exitcodes import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, EX_USAGE
from . import __version__

GLOBAL_FLAGS = [
    argparse.ArgumentParser(add_help=False),  # placeholder replaced below
]


def _global_parent() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--format", default="table",
                   choices=["table", "json", "ndjson", "markdown", "html"],
                   help="output format (default: table; json/ndjson for machines)")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="write output to FILE instead of stdout")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress on stderr")
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="verbose logging (repeatable)")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                   help="colorize table output (default: auto)")
    p.add_argument("--timeout", type=int, default=None,
                   help="seconds before aborting a network operation")
    p.add_argument("--yes", "-y", action="store_true",
                   help="non-interactive confirm (refused for privileged verbs)")
    p.add_argument("--no-input", action="store_true",
                   help="fail instead of prompting (agent-safe)")
    return p


def build_parser() -> argparse.ArgumentParser:
    parent = _global_parent()
    parser = argparse.ArgumentParser(
        prog="autobahn-defender",
        description=(
            "Autobahn Defender — Linux antivirus + security engine (CLI).\n\n"
            "Exit codes: 0 = completed, no findings · 1 = completed, findings present · "
            "2 = operational failure · 64 = usage error.\n"
            "JSON output carries the ground-truth status field; exit codes are a "
            "coarse signal (see `autobahn-defender help contract`)."
        ),
        parents=[parent],
        epilog=("Examples:\n"
                "  autobahn-defender audit hardening --format markdown\n"
                "  autobahn-defender cve --format json | jq -r '.results[].cve_id'\n"
                "  autobahn-defender scan ~/Downloads --fail-on CRITICAL\n"),
    )
    parser.add_argument("--version", "-V", action="version",
                        version=f"autobahn-defender {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # ── scan ──────────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", parents=[parent],
                            help="run a malware scan (YARA + ClamAV)")
    p_scan.add_argument("paths", nargs="*", default=None,
                        help="paths to scan (default: $HOME)")
    p_scan.add_argument("--quick", action="store_true",
                        help="quick scan (extension whitelist)")
    p_scan.add_argument("--fail-on", dest="fail_on",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        default=None, help="exit 1 when a finding >= severity exists")

    # ── scan-processes ────────────────────────────────────────────────────
    p_proc = sub.add_parser("scan-processes", parents=[parent],
                            help="scan running processes for miner/backdoor signs")

    # ── cve ───────────────────────────────────────────────────────────────
    p_cve = sub.add_parser("cve", parents=[parent],
                           help="scan installed packages against OSV.dev")
    p_cve.add_argument("--offline", action="store_true",
                       help="use cached results only (no network)")
    p_cve.add_argument("--fail-on", dest="fail_on",
                       choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None)

    # ── patches ───────────────────────────────────────────────────────────
    p_patch = sub.add_parser("patches", parents=[parent],
                             help="patch tracking: check | verify PKG | apply")
    p_patch.add_argument("action", choices=["check", "verify", "apply"])
    p_patch.add_argument("package", nargs="?", default=None)

    # ── audit ─────────────────────────────────────────────────────────────
    p_audit = sub.add_parser("audit", parents=[parent],
                             help="run a deterministic audit profile")
    p_audit.add_argument("profile",
                         choices=["full", "vuln", "network", "hardening"],
                         help="audit profile (full = everything)")

    # ── checks ────────────────────────────────────────────────────────────
    p_checks = sub.add_parser("checks", parents=[parent],
                              help="list or run registered security checks")
    p_checks.add_argument("action", choices=["list", "run"])
    p_checks.add_argument("check_name", nargs="?", default=None)

    # ── alerts ────────────────────────────────────────────────────────────
    p_alerts = sub.add_parser("alerts", parents=[parent],
                              help="alert lifecycle")
    p_alerts.add_argument("action", choices=["list", "resolve", "dismiss", "clear"])
    p_alerts.add_argument("alert_id", nargs="?", default=None)

    # ── quarantine ────────────────────────────────────────────────────────
    p_q = sub.add_parser("quarantine", parents=[parent], help="quarantine management")
    p_q.add_argument("action", choices=["list", "restore", "delete"])
    p_q.add_argument("quarantine_name", nargs="?", default=None)

    # ── network ───────────────────────────────────────────────────────────
    p_net = sub.add_parser("network", parents=[parent],
                           help="network watch: connections + blacklist + persistence")
    p_net.add_argument("action", choices=["connections", "download-blacklist",
                                          "persistence", "hosts"])

    # ── intel ─────────────────────────────────────────────────────────────
    p_intel = sub.add_parser("intel", parents=[parent],
                             help="threat-intel pipeline: KEV/USN/EPSS/PoC watch")
    p_intel.add_argument("action", choices=["poll", "show", "status"])
    p_intel.add_argument("--source", default=None,
                         choices=[None, "kev", "usn", "epss", "poc"],
                         help="restrict to one feed")

    # ── watch ─────────────────────────────────────────────────────────────
    p_watch = sub.add_parser("watch", parents=[parent],
                             help="active monitor lifecycle (inotify + pollers)")
    p_watch.add_argument("action", choices=["once", "status"])
    p_watch.add_argument("--interval", type=int, default=900,
                         help="poll interval seconds for daemon mode (default 900)")

    # ── remediation lifecycle ─────────────────────────────────────────────
    p_rem = sub.add_parser("remediate", parents=[parent],
                           help="contain/update/verify/restore lifecycle")
    p_rem.add_argument("action", choices=["plan", "execute"])
    p_rem.add_argument("--cve-id", dest="cve_id", default="",
                       help="CVE of the alert to remediate")
    p_rem.add_argument("--package", default="",
                       help="installed package the CVE affects")
    p_rem.add_argument("--fixed-in", dest="fixed_in", default="",
                       help="fixed version (empty = no patch published)")
    p_rem.add_argument("--exploited", action="store_true",
                       help="CVE is actively exploited (CISA KEV)")
    p_rem.add_argument("--ransomware", action="store_true",
                       help="known ransomware campaign (raises urgency)")
    p_rem.add_argument("--step", default="update",
                       choices=["contain", "update", "verify", "restore"],
                       help="step to execute after plan review")
    p_rem.add_argument("--token", default=None,
                       help="one-time confirm token from 'remediate plan'")

    # ── defs / rules ──────────────────────────────────────────────────────
    p_defs = sub.add_parser("defs", parents=[parent],
                            help="ClamAV definitions: update | status")
    p_defs.add_argument("action", choices=["update", "status"])

    p_rules = sub.add_parser("rules", parents=[parent],
                             help="YARA rules: update | status")
    p_rules.add_argument("action", choices=["update", "status"])

    # ── apply (hardening) ─────────────────────────────────────────────────
    p_apply = sub.add_parser("apply", parents=[parent],
                             help="apply hardening (privileged, review-first)")
    p_apply.add_argument("action",
                         choices=["apparmor", "fw-enable", "fw-disable",
                                  "sysctl", "ssh", "privacy"])
    p_apply.add_argument("--yes-required", action="store_true",
                         help=argparse.SUPPRESS)  # internal friction flag

    # ── doctor ────────────────────────────────────────────────────────────
    sub.add_parser("doctor", parents=[parent],
                   help="environment/deps self-check (JSON)")

    return parser