"""
Autobahn Defender v2.0 — Deterministic security checks.

Replaces the v2.0 AI tool functions (ai/tools.py) with plain Python
functions that produce the same output schemas. No AI model required.

Each check returns {"status": "ok", "data": {...}} or 
{"status": "error", "error": "..."} — identical to the AI tools.

CVE-related checks are in engine/cve.py (not here).

Contact: XMPP digitalautobahn@xmpp.brax.me
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import ipaddress
import socket
import subprocess
import unicodedata
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

MAX_RESULT_CHARS = 16000
SUBPROCESS_TIMEOUT = 20

# Audit 2026-08-31 A-2 fix: these frozensets were referenced by
# check_network_threat_monitor but defined only in the removed ai/tools.py —
# NameError on first established connection. Values ported verbatim from
# ai/tools.py (SUSPICIOUS_REMOTE_PORTS + HIGH_RISK_PORTS definitions there).
SUSPICIOUS_REMOTE_PORTS = frozenset({
    "1337",   # Common reverse shell port
    "4444",   # Metasploit default
    "5555",   # Android debug bridge / AhMyth
    "6666",   # Various backdoors
    "6667",   # IRC-based C2
    "7777",   # Various backdoors
    "8888",   # Various C2
    "9999",   # Various backdoors
    "31337",  # Back Orifice / Elite
    "12345",  # NetBus
    "27374",  # SubSeven
    "65535",  # Some backdoors
})
HIGH_RISK_PORTS = frozenset({
    "4444", "1337", "31337", "6667", "9999",
})


def _truncate(text: str, limit: int = MAX_RESULT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated, " + str(len(text) - limit) + " more chars]"


def _sanitize(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    text = "".join(ch for ch in text if ch in "\n\t" or unicodedata.category(ch)[0] != "C")
    return text


def _ok(data: Any) -> dict[str, Any]:
    return {"status": "ok", "data": data}


def _err(msg: str) -> dict[str, Any]:
    return {"status": "error", "error": str(msg)[:2000]}


def _run(cmd: list[str], timeout: int = SUBPROCESS_TIMEOUT) -> dict[str, Any]:
    try:
        if not cmd or not isinstance(cmd[0], str):
            return _err("Invalid command")
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
        out = (r.stdout or "") + (("\n[stderr]\n" + r.stderr) if r.stderr else "")
        return _ok({"exit_code": r.returncode, "output": _truncate(_sanitize(out))})
    except subprocess.TimeoutExpired:
        return _err(f"Command timed out after {timeout}s: {' '.join(cmd[:3])}")
    except FileNotFoundError:
        return _err(f"Command not found: {cmd[0]}")
    except Exception as e:
        return _err(f"Command failed: {e}")


def _run_text(cmd: list[str], timeout: int = SUBPROCESS_TIMEOUT) -> str:
    res = _run(cmd, timeout)
    if res["status"] == "ok":
        return res["data"]["output"]
    return f"[error: {res.get('error', 'unknown')}]"


def check_system_audit(_: dict) -> dict:
    """Full system security audit. Runs 5-10 commands, returns combined JSON.

    Each sub-result is capped to keep the aggregate manageable within the
    128K context window.
    """
    _SUB_LIMIT = 4000  # chars per sub-result

    def _run_capped(cmd, timeout=SUBPROCESS_TIMEOUT):
        r = _run(cmd, timeout)
        if r["status"] == "ok" and len(r["data"]["output"]) > _SUB_LIMIT:
            r["data"]["output"] = r["data"]["output"][:_SUB_LIMIT] + "\n...[truncated]"
        return r

    results = {}
    results["firewall"] = _run_capped(["ufw", "status", "verbose"])
    if results["firewall"]["status"] != "ok":
        results["firewall"] = _run_capped(["iptables", "-L", "-n", "-v"])
    results["apparmor"] = _run_capped(["aa-status"])
    results["processes"] = _run_capped(["ps", "auxf", "--sort=-%cpu"])
    results["ports"] = _run_capped(["ss", "-tulpn"])
    results["updates"] = _run_capped(["apt", "list", "--upgradable"])
    results["suid"] = _run_capped(["find", "/usr", "-perm", "-4000", "-type", "f"])
    try:
        ssh_cfg = Path("/etc/ssh/sshd_config")
        if ssh_cfg.exists():
            content = ssh_cfg.read_text(errors="replace")
            # Only send non-comment lines to save context space
            lines = [l for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
            results["ssh_config"] = _ok({"content": _truncate("\n".join(lines), _SUB_LIMIT)})
        else:
            results["ssh_config"] = _err("No sshd_config found")
    except Exception as e:
        results["ssh_config"] = _err(str(e))
    results["kernel"] = _run_capped(["uname", "-a"])
    auth_log = Path("/var/log/auth.log")
    if auth_log.exists():
        try:
            tail = subprocess.run(["tail", "-20", str(auth_log)], capture_output=True, text=True, timeout=10)
            results["auth_log"] = _ok({"tail": _truncate(tail.stdout or "", _SUB_LIMIT)})
        except Exception as e:
            results["auth_log"] = _err(str(e))
    else:
        results["auth_log"] = _run_capped(["journalctl", "-u", "ssh", "-n", "20", "--no-pager"])
    return _ok(results)



def check_firewall_check(_: dict) -> dict:
    """Get current firewall rules from iptables, nftables, and ufw.

    NOTE: ufw requires root. If not root, the user is told to run
    'sudo autobahn-defender' for full firewall analysis.
    """
    if os.geteuid() != 0:
        return _ok({
            "note": "Firewall analysis requires root privileges. "
                    "Run 'sudo autobahn-defender' for full firewall analysis. "
                    "You will be asked for your password.",
            "iptables": _run(["iptables", "-L", "-n", "-v"]),
            "nftables": _run(["nft", "list", "ruleset"]),
        })
    return _ok({
        "ufw": _run(["ufw", "status", "verbose"]),
        "iptables": _run(["iptables", "-L", "-n", "-v"]),
        "nftables": _run(["nft", "list", "ruleset"]),
    })



def check_apparmor_status(_: dict) -> dict:
    """Get AppArmor status. Runs aa-status, checks complain vs enforce mode.

    NOTE: aa-status requires root for full profile listing. If not root,
    tells the user to run 'sudo autobahn-defender'.
    """
    if os.geteuid() != 0:
        return _ok({
            "note": "AppArmor profile listing requires root privileges. "
                    "Run 'sudo autobahn-defender' for full analysis.",
            "basic": _run(["aa-status"]),
        })
    return _ok({
        "aa_status": _run(["aa-status"]),
        "profiles": _run(["ls", "-la", "/etc/apparmor.d/"]),
    })



def check_running_processes(_: dict) -> dict:
    """Get running processes with full command lines."""
    return _run(["ps", "auxf", "--sort=-%cpu"])



def check_installed_packages(_: dict) -> dict:
    """Get installed packages. Runs dpkg -l."""
    return _run(["dpkg", "-l"])



def check_pending_updates(_: dict) -> dict:
    """Get pending system updates. Runs apt list --upgradable."""
    return _run(["apt", "list", "--upgradable"])



def check_network_connections(_: dict) -> dict:
    """Get network connections. Runs ss -tulpn and ss -tup."""
    return _ok({
        "listening": _run(["ss", "-tulpn"]),
        "established": _run(["ss", "-tup"]),
    })



def check_ssh_config_check(_: dict) -> dict:
    """Check SSH configuration. Reads /etc/ssh/sshd_config."""
    try:
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return _err("No sshd_config found")
        return _ok({"content": _truncate(_sanitize(p.read_text(errors="replace")))})
    except Exception as e:
        return _err(str(e))



def check_suid_binaries(_: dict) -> dict:
    """Find SUID/SGID binaries."""
    return _ok({
        "suid": _run(["find", "/", "-xdev", "-perm", "-4000", "-type", "f"], timeout=30),
        "sgid": _run(["find", "/", "-xdev", "-perm", "-2000", "-type", "f"], timeout=30),
    })



def check_startup_items(_: dict) -> dict:
    """List startup/persistence items. systemd units, cron, timers, autostart."""
    return _ok({
        "systemd_services": _run(["systemctl", "list-unit-files", "--state=enabled", "--no-pager"]),
        "systemd_timers": _run(["systemctl", "list-timers", "--all", "--no-pager"]),
        "cron_user": _run(["crontab", "-l"]),
        "cron_system": _run(["ls", "-la", "/etc/cron.d/"]),
        "autostart_user": _run(["ls", "-la", str(Path.home() / ".config" / "autostart")]),
        "autostart_system": _run(["ls", "-la", "/etc/xdg/autostart"]),
    })



def check_kernel_info(_: dict) -> dict:
    """Get kernel security info. uname, sysctl kernel, KASLR/SMEP/SMAP."""
    # Check if we can run dmesg (requires CAP_SYSLOG or root)
    dmesg_result = _err("dmesg requires root/CAP_SYSLOG -- skipping kernel log")
    try:
        r = subprocess.run(["dmesg"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            dmesg_result = _ok({"output": _truncate(_sanitize(r.stdout or ""))})
        else:
            dmesg_result = _err(f"dmesg permission denied (returncode {r.returncode})")
    except Exception as e:
        dmesg_result = _err(f"dmesg failed: {e}")
    return _ok({
        "uname": _run(["uname", "-a"]),
        "kernel_sysctl": _run(["sysctl", "kernel"]),
        "kaslr": _run(["cat", "/proc/cmdline"]),
        "dmesg": dmesg_result,
    })



def check_auth_log_check(_: dict) -> dict:
    """Check auth logs. Reads /var/log/auth.log tail or journalctl sshd."""
    auth_log = Path("/var/log/auth.log")
    if auth_log.exists():
        try:
            r = subprocess.run(
                ["tail", "-100", str(auth_log)],
                capture_output=True, text=True, timeout=10,
            )
            return _ok({"tail": _truncate(_sanitize(r.stdout or ""))})
        except Exception as e:
            return _err(str(e))
    return _run(["journalctl", "-u", "ssh", "-n", "100", "--no-pager"])


def _ddg_search(query: str, max_results: int) -> list[dict]:
    """Search DuckDuckGo HTML endpoint. Returns parsed results.

    DDG sometimes returns 202 (challenge page) when rate-limited.
    In that case, returns empty list so the caller can try the fallback.
    """
    import requests as req
    from bs4 import BeautifulSoup
    from urllib.parse import urlparse, parse_qs, unquote

    base = "https://html.duckduckgo.com/html/"
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
            "Gecko/20100101 Firefox/128.0"
        ),
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://duckduckgo.com/",
    }
    params = {"q": query}

    try:
        r = req.get(base, params=params, headers=headers, timeout=15)
        if r.status_code == 202:
            import time
            time.sleep(1)
            r = req.post(base, data=params, headers=headers, timeout=15)
        if r.status_code == 202:
            return []  # Rate-limited, let caller try fallback
        r.raise_for_status()
    except Exception:
        return []

    soup = BeautifulSoup(r.text, "html.parser")
    results = []
    for div in soup.find_all("div", class_="result"):
        if len(results) >= max_results:
            break
        link = div.find("a", class_="result__a")
        snippet_el = div.find("a", class_="result__snippet")
        if not link:
            continue
        href = link.get("href", "")
        if "duckduckgo.com/l/" in href or "/l/?uddg=" in href:
            parsed = urlparse(href)
            qs = parse_qs(parsed.query)
            href = unquote(qs.get("uddg", [href])[0])
        results.append({
            "title": link.get_text(strip=True),
            "url": href,
            "snippet": snippet_el.get_text(strip=True) if snippet_el else "",
        })
    return results


def _brave_search(query: str, max_results: int) -> list[dict]:
    """Fallback search via Brave Search HTML endpoint.

    Brave doesn't require an API key for basic HTML results.
    Returns empty list on failure.
    """
    import requests as req
    from bs4 import BeautifulSoup

    base = "https://search.brave.com/search"
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
            "Gecko/20100101 Firefox/128.0"
        ),
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.5",
    }
    params = {"q": query, "source": "web"}

    try:
        r = req.get(base, params=params, headers=headers, timeout=15)
        r.raise_for_status()
    except Exception:
        return []

    soup = BeautifulSoup(r.text, "html.parser")
    results = []
    # Brave uses div.svelte-... result containers; find by data-type
    for div in soup.find_all("div", attrs={"data-type": "web"}):
        if len(results) >= max_results:
            break
        link = div.find("a", class_="result-header")
        if not link:
            link = div.find("a")
        if not link:
            continue
        href = link.get("href", "")
        if not href.startswith("http"):
            continue
        title = link.get_text(strip=True)
        if not title:
            continue
        snippet_el = div.find("div", class_="snippet-description")
        if not snippet_el:
            snippet_el = div.find("p", class_="snippet")
        results.append({
            "title": title,
            "url": href,
            "snippet": snippet_el.get_text(strip=True) if snippet_el else "",
        })
    return results



# Local YARA compile cache (audit A-3 fix: previously referenced scanner's
# module globals, which do not exist in the headless engine).
import threading as _threading

_yara_cache: dict = {}
_yara_cache_lock = _threading.Lock()

# Neutral rules path (audit F-6 fix: no scanner/PyQt import).
from .paths import RULES_DIR as _RULES_DIR  # noqa: E402


def check_yara_scan_file(args: dict) -> dict:
    """Scan a file with YARA rules. Reuses Autobahn Defender YARA.

    Compiled rules are cached and only recompiled when source .yar
    files change (detected via mtime). This avoids recompiling the
    1.7MB rules file on every call.
    Audit 2026-08-31 A-3 fix: previously referenced the scanner module's
    _yara_cache globals (NameError every call); engine now keeps its own
    cache and uses the headless paths.RULES_DIR.
    """
    filepath = args.get("path", "").strip()
    if not filepath or not Path(filepath).is_file():
        return _err(f"File not found: {filepath}")
    try:
        import yara

        rules_dir = str(_RULES_DIR)

        # Check cache: recompile only if rules dir mtime changed (thread-safe)
        dir_mtime = Path(rules_dir).stat().st_mtime
        with _yara_cache_lock:
            cached = _yara_cache.get(rules_dir)
        if cached and cached[0] == dir_mtime:
            compiled = cached[1]
        else:
            rules_files = {}
            for yf in Path(rules_dir).glob("*.yar"):
                rules_files[yf.stem] = str(yf)
            if not rules_files:
                return _err("No YARA rules found")
            compiled = yara.compile(filepaths=rules_files)
            with _yara_cache_lock:
                _yara_cache[rules_dir] = (dir_mtime, compiled)

        matches = compiled.match(filepath)
        return _ok({
            "file": filepath,
            "matches": [m.rule for m in matches],
            "match_count": len(matches),
        })
    except ImportError:
        return _err("yara-python not installed")
    except Exception as e:
        return _err(f"YARA scan failed: {e}")



def check_file_info(args: dict) -> dict:
    """Get file metadata and type info. stat, file command, sha256sum."""
    filepath = args.get("path", "").strip()
    if not filepath or not Path(filepath).exists():
        return _err(f"File not found: {filepath}")
    p = Path(filepath)
    info = {"path": str(p), "size": p.stat().st_size}
    info["stat"] = _run_text(["stat", str(p)])
    info["file_type"] = _run_text(["file", str(p)])
    # sha256
    try:
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        info["sha256"] = h.hexdigest()
    except Exception as e:
        info["sha256"] = f"[error: {e}]"
    # entropy (quick check for packed/encrypted content)
    try:
        with p.open("rb") as f:
            data = f.read(1024 * 1024)  # first 1MB
        if data:
            import math
            from collections import Counter
            counts = Counter(data)
            total = len(data)
            entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
            info["entropy"] = round(entropy, 3)
    except Exception:
        pass
    return _ok(info)



def check_whois_lookup(args: dict) -> dict:
    """WHOIS lookup for IP/domain. Uses whois command or python-whois."""
    target = args.get("target", "").strip()
    if not target:
        return _err("target is required")
    # Try the whois command first
    if shutil.which("whois"):
        return _run(["whois", target], timeout=20)
    # Fall back to python-whois
    try:
        import whois  # python-whois
        w = whois.whois(target)
        return _ok({"data": str(w)[:MAX_RESULT_CHARS]})
    except ImportError:
        return _err("whois command not found and python-whois not installed")
    except Exception as e:
        return _err(f"WHOIS failed: {e}")



def check_investigate_process(args: dict) -> dict:
    """Collect full info about a running process by PID.

    SECURITY: Only processes owned by the current user (or running as
    root) can be investigated. This prevents a non-root user from
    hashing or reading binaries of other users' processes.
    """
    pid = str(args.get("pid", "")).strip()
    if not pid or not pid.isdigit():
        return _err("pid (integer) is required")
    pid_int = int(pid)

    # Access control: check if the process is owned by the current user
    import os as _os
    try:
        proc_uid = _os.stat(f"/proc/{pid_int}").st_uid
        current_uid = _os.getuid()
        if proc_uid != current_uid and current_uid != 0:
            return _err(
                f"Permission denied: process {pid_int} is owned by uid "
                f"{proc_uid}, not you (uid {current_uid}). "
                "You can only investigate your own processes."
            )
    except (FileNotFoundError, PermissionError, OSError) as e:
        return _err(f"Cannot access process {pid_int}: {e}")

    info = {}
    info["ps"] = _run_text(["ps", "-p", pid, "-o", "pid,ppid,user,%cpu,%mem,cmd"])
    info["cwd"] = _run_text(["ls", "-la", f"/proc/{pid}/cwd"])
    info["exe"] = _run_text(["readlink", f"/proc/{pid}/exe"])
    info["open_files"] = _run_text(["ls", "-la", f"/proc/{pid}/fd/"])
    info["net"] = _run_text(["ss", "-tupn", "-p", f"pid={pid}"])
    # binary hash
    try:
        exe = Path(f"/proc/{pid}/exe").resolve()
        if exe.exists() and os.access(exe, os.R_OK):
            h = hashlib.sha256()
            with exe.open("rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            info["binary_sha256"] = h.hexdigest()
        else:
            info["binary_sha256"] = "[no read permission on binary]"
    except Exception as e:
        info["binary_sha256"] = f"[error: {e}]"
    return _ok(info)


# ---------------------------------------------------------------------------
# New tools ported/adapted from Kudu (AdventDevInc/kudu, MIT license)
# Attribution: persistence scan, hosts-file check, script analysis, SSH audit,
# MAC status -- detection logic adapted from Kudu's TypeScript engine.
# ---------------------------------------------------------------------------


def check_scan_persistence(_: dict) -> dict:
    """Linux persistence scan. Parses user crontab and systemd user services
    for download-and-execute, /tmp execution, base64-decode-and-run patterns.

    Adapted from Kudu's scanLinuxPersistence() (MIT, AdventDevInc/kudu).
    """
    findings = []

    # --- Crontab analysis ---
    cron_result = _run(["crontab", "-l"])
    cron_text = ""
    if cron_result["status"] == "ok":
        cron_text = cron_result["data"]["output"]
    # Also check /etc/cron.d, /etc/crontab
    for cron_path in ["/etc/crontab"]:
        p = Path(cron_path)
        if p.exists():
            try:
                cron_text += "\n" + p.read_text(errors="replace")
            except OSError:
                pass
    cron_d = Path("/etc/cron.d")
    if cron_d.is_dir():
        for f in cron_d.iterdir():
            if f.is_file():
                try:
                    cron_text += "\n" + f.read_text(errors="replace")
                except OSError:
                    pass

    # Suspicious crontab patterns
    cron_patterns = [
        (r'(curl|wget)\s+.*\|\s*(bash|sh|python|python3)', "download-and-execute via curl/wget piped to shell"),
        (r'/tmp/\S+\.(sh|py|pl|rb)', "execution from /tmp directory"),
        (r'base64\s+-d\s.*\|\s*(bash|sh|python)', "base64-decode-and-execute"),
        (r'python\s+-c\s+import\s+base64', "Python base64 inline execution"),
        (r'(curl|wget)\s+.*&&\s*(bash|sh)', "download-and-run with && operator"),
        (r'\|\s*perl\s+-e', "piped to Perl one-liner"),
    ]
    if cron_text.strip():
        for line in cron_text.splitlines():
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#"):
                continue
            for pattern, desc in cron_patterns:
                if re.search(pattern, line_stripped, re.IGNORECASE):
                    findings.append({
                        "source": "crontab",
                        "line": _truncate(line_stripped, 500),
                        "indicator": desc,
                        "severity": "high",
                    })
                    break  # one finding per line

    # --- systemd user services ---
    systemd_user_dir = Path.home() / ".config" / "systemd" / "user"
    systemd_patterns = [
        (r'/tmp/\S+', "ExecStart references /tmp"),
        (r'(curl|wget)\s+.*\|\s*(bash|sh)', "download-and-execute in service"),
        (r'base64\s+-d', "base64 decode in service"),
        (r'Restart\s*=\s*always', "auto-restart persistence"),
    ]
    if systemd_user_dir.is_dir():
        for svc_file in systemd_user_dir.glob("*.service"):
            try:
                content = svc_file.read_text(errors="replace")
            except OSError:
                continue
            # Extract ExecStart lines
            for line in content.splitlines():
                line_stripped = line.strip()
                if not line_stripped.startswith("ExecStart="):
                    continue
                exec_cmd = line_stripped[len("ExecStart="):]
                for pattern, desc in systemd_patterns:
                    if re.search(pattern, exec_cmd, re.IGNORECASE):
                        # Skip Restart=always alone (common for legit services)
                        if "auto-restart" in desc:
                            # Only flag if combined with /tmp or download
                            if not re.search(r'/tmp/|(curl|wget)', exec_cmd, re.IGNORECASE):
                                continue
                        findings.append({
                            "source": "systemd_user",
                            "file": str(svc_file),
                            "line": _truncate(line_stripped, 500),
                            "indicator": desc,
                            "severity": "high",
                        })
                        break

    # --- systemd system services (if accessible) ---
    systemd_system_dir = Path("/etc/systemd/system")
    if systemd_system_dir.is_dir():
        for svc_file in systemd_system_dir.glob("*.service"):
            try:
                content = svc_file.read_text(errors="replace")
            except (OSError, PermissionError):
                continue
            for line in content.splitlines():
                line_stripped = line.strip()
                if not line_stripped.startswith("ExecStart="):
                    continue
                exec_cmd = line_stripped[len("ExecStart="):]
                for pattern, desc in systemd_patterns:
                    if re.search(pattern, exec_cmd, re.IGNORECASE):
                        if "auto-restart" in desc:
                            if not re.search(r'/tmp/|(curl|wget)', exec_cmd, re.IGNORECASE):
                                continue
                        findings.append({
                            "source": "systemd_system",
                            "file": str(svc_file),
                            "line": _truncate(line_stripped, 500),
                            "indicator": desc,
                            "severity": "critical" if "download" in desc else "high",
                        })
                        break

    return _ok({
        "findings": findings,
        "total": len(findings),
        "scanned_crontab": bool(cron_text.strip()),
        "scanned_systemd_user": systemd_user_dir.is_dir(),
    })



def check_check_hosts(_: dict) -> dict:
    """Check /etc/hosts for tampering. Flags redirections of major domains
    (Google, PayPal, banks, etc.) to non-safe IPs.

    Adapted from Kudu's checkHostsFile() (MIT, AdventDevInc/kudu).
    """
    hosts_path = Path("/etc/hosts")
    if not hosts_path.exists():
        return _err("/etc/hosts not found")

    try:
        content = hosts_path.read_text(errors="replace")
    except OSError as e:
        return _err(f"Cannot read /etc/hosts: {e}")

    # Domains that should never be redirected to a custom IP
    # (attackers redirect these to phishing/proxy servers)
    PROTECTED_DOMAINS = {
        "google.com", "www.google.com", "gmail.com",
        "microsoft.com", "www.microsoft.com", "login.live.com",
        "paypal.com", "www.paypal.com",
        "apple.com", "www.apple.com", "icloud.com",
        "amazon.com", "www.amazon.com",
        "facebook.com", "www.facebook.com",
        "twitter.com", "x.com",
        "github.com",
        "linkedin.com",
        "dropbox.com",
        "bankofamerica.com", "www.bankofamerica.com",
        "chase.com", "www.chase.com",
        "wellsfargo.com", "www.wellsfargo.com",
        "citibank.com", "www.citibank.com",
        "ebay.com", "www.ebay.com",
        "netflix.com",
        "spotify.com",
        "steampowered.com", "steamcommunity.com",
    }

    # IPs that are legitimate for these domains (Cloudflare, Google DNS, etc.)
    SAFE_IPS = {
        "0.0.0.0",      # blocking (ad-blockers use this, not malicious)
        "127.0.0.1",    # localhost (common for ad-blocking, not malicious)
        "::1",          # IPv6 localhost
        "fe80::1",      # link-local
    }

    findings = []
    for line in content.splitlines():
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("#"):
            continue
        # hosts file format: IP  domain1  domain2  ...
        parts = line_stripped.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        domains = parts[1:]
        for domain in domains:
            domain_lower = domain.lower()
            if domain_lower in PROTECTED_DOMAINS:
                if ip not in SAFE_IPS:
                    findings.append({
                        "domain": domain_lower,
                        "redirected_to": ip,
                        "line": _truncate(line_stripped, 300),
                        "severity": "critical",
                        "indicator": f"Protected domain {domain_lower} redirected to {ip}",
                    })

    # Also check for suspicious patterns
    suspicious_patterns = [
        (r'^\s*\d+\.\d+\.\d+\.\d+\s+.*\s+.*\s+.*\s+.*\s+', "many domains on one IP (possible bulk redirect)"),
    ]
    for line in content.splitlines():
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("#"):
            continue
        parts = line_stripped.split()
        if len(parts) >= 2:
            domains = parts[1:]
            if len(domains) > 5 and parts[0] not in SAFE_IPS:
                findings.append({
                    "line": _truncate(line_stripped, 300),
                    "severity": "medium",
                    "indicator": f"Single IP {parts[0]} mapped to {len(domains)} domains",
                })

    return _ok({
        "findings": findings,
        "total": len(findings),
        "hosts_file": str(hosts_path),
    })



def check_analyze_script(args: dict) -> dict:
    """Analyze a script file for malicious behavior patterns.

    Detects: encoded PowerShell, download cradles, AMSI bypass,
    base64-embedded PE headers, reflective loading, mimikatz references.

    Adapted from Kudu's analyzeScriptContent() (MIT, AdventDevInc/kudu).
    Requires >=2 indicators to flag (reduces false positives), EXCEPT
    base64-embedded-PE which is sufficient alone.
    """
    filepath = args.get("path", "").strip()
    if not filepath or not Path(filepath).is_file():
        return _err(f"File not found: {filepath}")

    try:
        content = Path(filepath).read_text(errors="replace")
    except OSError as e:
        return _err(f"Cannot read file: {e}")

    if not content.strip():
        return _ok({"file": filepath, "indicators": [], "verdict": "empty", "indicator_count": 0})

    # Script indicator patterns (language-agnostic malicious behaviors)
    INDICATORS = [
        # Encoded PowerShell
        (r'-enc(?:odedCommand)?\s+[A-Za-z0-9+/]{20,}={0,2}', "encoded PowerShell command (-enc + base64)"),
        # Download cradle: iwr/curl + iex
        (r'(?:iwr|Invoke-WebRequest|curl|wget)\s+.*\|\s*(?:iex|Invoke-Expression)', "download cradle (fetch + execute)"),
        # AMSI bypass
        (r'(?:amsi|AMSI).*(?:bypass|fail|initFailed|SetContent)', "AMSI bypass attempt"),
        # Reflective assembly loading
        (r'(?:Reflection\.Assembly|Load\(\[Convert\]::FromBase64)', "reflective .NET assembly loading"),
        # Base64-embedded PE header (MZ + base64)
        (r'TVqQAAMAAAAEAAAA|TVqQAAIAAAAEAA', "base64-embedded PE header (executable hidden in script)"),
        # mimikatz reference
        (r'mimikatz|sekurlsa|lsadump', "mimikatz/credential theft reference"),
        # PowerShell download string patterns
        (r'(?:Net\.WebClient|DownloadString|DownloadFile)\s*\(', ".NET WebClient download"),
        # Shell execution
        (r'(?:cmd\.exe|/bin/sh|/bin/bash)\s+.*-c\s', "shell execution via cmd/sh"),
        # Suspicious piping
        (r'\|\s*(?:bash|sh|perl|python|ruby)\s', "piped to interpreter"),
        # base64 decode + execute
        (r'base64\s+--?d(?:ecode)?\s.*\|\s*(?:bash|sh|perl|python)', "base64 decode and execute"),
        # Certutil for download (living-off-the-land)
        (r'certutil\s+.*-urlcache\s+.*-split', "certutil used for file download"),
        # Bitsadmin for download
        (r'bitsadmin\s+.*\/transfer\s+.*\/download', "bitsadmin used for download"),
        # WMI execution
        (r'wmic\s+.*process\s+call\s+create', "WMI process creation"),
        # Encoded JScript/VBScript
        (r'(?:JScript|VBScript|ExecuteGlobal)\s*\(|eval\s*\(', "script engine eval/execute"),
    ]

    found_indicators = []
    for pattern, desc in INDICATORS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            found_indicators.append({
                "indicator": desc,
                "pattern": pattern[:80],
                "match_count": len(matches),
                "sample": _truncate(matches[0][:200], 200),
            })

    # Verdict logic: >=2 indicators = suspicious, base64-PE alone = malicious
    has_pe_header = any("PE header" in i["indicator"] for i in found_indicators)
    if has_pe_header:
        verdict = "malicious"
        severity = "critical"
    elif len(found_indicators) >= 2:
        verdict = "suspicious"
        severity = "high"
    elif len(found_indicators) == 1:
        verdict = "review"
        severity = "medium"
    else:
        verdict = "clean"
        severity = "info"

    return _ok({
        "file": filepath,
        "indicators": found_indicators,
        "indicator_count": len(found_indicators),
        "verdict": verdict,
        "severity": severity,
    })



def check_ssh_audit(_: dict) -> dict:
    """SSH hardening audit. Parses sshd_config + drop-in configs with
    Match-block awareness. Checks for weak ciphers, protocols, settings.

    Adapted from Kudu's collectSshHardening() (MIT, AdventDevInc/kudu).
    """
    sshd_path = Path("/etc/ssh/sshd_config")
    sshd_d = Path("/etc/ssh/sshd_config.d")

    if not sshd_path.exists():
        return _ok({"installed": False, "note": "SSH server not installed"})

    # Parse main config + all drop-ins
    config_lines = []
    try:
        config_lines.extend(sshd_path.read_text(errors="replace").splitlines())
    except OSError:
        pass

    if sshd_d.is_dir():
        for f in sorted(sshd_d.iterdir()):
            if f.is_file() and f.suffix == ".conf":
                try:
                    config_lines.extend(f.read_text(errors="replace").splitlines())
                except OSError:
                    pass

    # Parse into key-value pairs, respecting Match blocks
    settings = {}
    current_match = None
    match_settings = {}

    for line in config_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) < 2:
            continue
        key = parts[0].lower()
        val = parts[1].strip()
        if key == "match":
            current_match = val
            match_settings[current_match] = {}
            continue
        if current_match:
            match_settings.setdefault(current_match, {})[key] = val
        else:
            settings[key] = val

    findings = []

    # Security checks (global settings only; Match blocks are context-specific)
    checks = [
        ("permitrootlogin", "yes", "critical", "Root SSH login is enabled"),
        ("permitrootlogin", "without-password", "high", "Root SSH login allows key auth (should be 'no')"),
        ("passwordauthentication", "yes", "high", "Password authentication is enabled (use keys)"),
        ("permitemptypasswords", "yes", "critical", "Empty passwords are allowed"),
        ("protocol", "1", "critical", "SSH protocol 1 is enabled (insecure, use protocol 2)"),
        ("x11forwarding", "yes", "low", "X11 forwarding is enabled (unnecessary risk)"),
        ("allowtcpforwarding", "yes", "low", "TCP forwarding is enabled"),
        ("permittunnel", "yes", "low", "Tunneling is enabled"),
        ("maxauthtries", None, "medium", "MaxAuthTries not set (default 6 is high)"),
        ("clientaliveinterval", None, "low", "ClientAliveInterval not set (no idle timeout)"),
        ("logingracetime", None, "low", "LoginGraceTime not set (default 120s allows brute force)"),
    ]

    for key, bad_val, severity, desc in checks:
        val = settings.get(key)
        if bad_val is None:
            # Check for missing setting
            if val is None:
                findings.append({
                    "setting": key,
                    "current_value": "(not set)",
                    "severity": severity,
                    "issue": desc,
                    "fix": f"Add '{key} <recommended-value>' to sshd_config",
                })
        else:
            if val and val.lower() == bad_val.lower():
                findings.append({
                    "setting": key,
                    "current_value": val,
                    "severity": severity,
                    "issue": desc,
                    "fix": f"Set '{key} no' in /etc/ssh/sshd_config",
                })

    # Check for weak ciphers/MACs/KexAlgorithms
    weak_ciphers = ["3des-cbc", "blowfish-cbc", "cast128-cbc", "arcfour"]
    weak_macs = ["hmac-md5", "hmac-sha1", "hmac-md5-96", "hmac-sha1-96"]
    for cipher in weak_ciphers:
        if any(c in settings.get("ciphers", "").lower() for c in [cipher]):
            findings.append({
                "setting": "ciphers",
                "current_value": settings.get("ciphers", ""),
                "severity": "medium",
                "issue": f"Weak cipher {cipher} is allowed",
                "fix": f"Remove {cipher} from Ciphers in sshd_config",
            })
    for mac in weak_macs:
        if mac in settings.get("macs", "").lower():
            findings.append({
                "setting": "macs",
                "current_value": settings.get("macs", ""),
                "severity": "medium",
                "issue": f"Weak MAC {mac} is allowed",
                "fix": f"Remove {mac} from MACs in sshd_config",
            })

    # Check for non-standard port (good practice, note it)
    port = settings.get("port", "22")
    if port != "22":
        findings.append({
            "setting": "port",
            "current_value": port,
            "severity": "info",
            "issue": f"SSH running on non-standard port {port}",
            "fix": "Non-standard port is good for reducing automated scans",
        })

    return _ok({
        "installed": True,
        "settings": settings,
        "match_blocks": match_settings,
        "findings": findings,
        "total_findings": len(findings),
    })



def check_network_threat_monitor(args: dict) -> dict:
    """Live network threat monitor. Parses ss output for established
    connections, matches remote IPs against suspicious CIDR ranges and
    high-risk ports, flags connections to non-standard ports used by
    reverse shells and C2 beacons.

    Optionally downloads a threat intelligence feed (Emerging Threats
    compromised IP list) and matches against it.

    Adapted from Kudu's network monitoring concepts (MIT, AdventDevInc/kudu).
    """
    download_blacklist = args.get("download_blacklist", False)

    findings = []
    connections_parsed = 0

    # --- Parse established connections via ss ---
    try:
        proc = subprocess.run(
            ["ss", "-tupn", "--no-header"],
            capture_output=True, text=True, timeout=10
        )
        ss_output = proc.stdout
    except (OSError, subprocess.TimeoutExpired):
        return _err("Failed to run ss command")

    for line in ss_output.splitlines():
        line = line.strip()
        if not line:
            continue
        # ss output format:
        # udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:...
        # tcp ESTAB  0 0 192.168.1.5:443 93.184.216.34:443 users:...
        parts = line.split()
        if len(parts) < 5:
            continue
        state = parts[0]  # tcp/udp
        conn_state = parts[1]  # ESTAB, UNCONN, TIME-WAIT, etc.
        local = parts[4]   # local addr:port
        remote = parts[5]  # remote addr:port (may be * for listening)

        # Only analyze ESTABLISHED connections
        if conn_state != "ESTAB":
            continue

        connections_parsed += 1

        # Parse remote IP and port
        remote_ip_str = remote.rsplit(":", 1)[0] if ":" in remote else ""
        remote_port_str = remote.rsplit(":", 1)[1] if ":" in remote else ""
        # Handle IPv6 format [::1]:443
        if remote_ip_str.startswith("[") and "]" in remote_ip_str:
            remote_ip_str = remote_ip_str[1:remote_ip_str.index("]")]

        # Skip wildcard/unresolved
        if remote_ip_str in ("*", "0.0.0.0", "::", ""):
            continue

        # Skip link-local and localhost
        try:
            remote_ip = ipaddress.ip_address(remote_ip_str)
        except ValueError:
            continue
        if remote_ip.is_loopback or remote_ip.is_link_local:
            continue

        # Check for suspicious ports
        if remote_port_str in SUSPICIOUS_REMOTE_PORTS:
            findings.append({
                "type": "suspicious_port",
                "remote_ip": remote_ip_str,
                "remote_port": remote_port_str,
                "local": local,
                "severity": "critical",
                "indicator": f"Connection to known backdoor/C2 port {remote_port_str}",
            })
        elif remote_port_str in HIGH_RISK_PORTS:
            findings.append({
                "type": "high_risk_port",
                "remote_ip": remote_ip_str,
                "remote_port": remote_port_str,
                "local": local,
                "severity": "high",
                "indicator": f"Connection to high-risk port {remote_port_str}",
            })

        # Check for outbound to private ranges (lateral movement)
        if remote_ip.is_private and not remote_ip.is_loopback:
            # Only flag if the remote port is not a common service
            if remote_port_str not in ("22", "53", "80", "443", "445",
                                       "139", "631", "5353", "1900",
                                       "67", "68", "123", "514"):
                findings.append({
                    "type": "lateral_movement",
                    "remote_ip": remote_ip_str,
                    "remote_port": remote_port_str,
                    "local": local,
                    "severity": "medium",
                    "indicator": f"Outbound connection to private IP {remote_ip_str}:{remote_port_str}",
                })

    # --- Optionally download a threat feed (with caching) ---
    blacklist_hits = []
    if download_blacklist:
        try:
            # Caching: store the blacklist in the AI data dir for 24h.
            # If cached copy is < 24h old, use it instead of re-downloading.
            # (Kudu-inspired: atomic replace + versioned blacklist)
            import time as _time
            blacklist_text = None
            cache_path = None
            try:
                from . import BLACKLIST_DIR as _BL_DIR
                cache_dir = _BL_DIR
                cache_dir.mkdir(parents=True, exist_ok=True)
                cache_path = cache_dir / "blacklist_cache.txt"
                if cache_path.exists():
                    import os as _os
                    age_hours = (_time.time() - _os.path.getmtime(str(cache_path))) / 3600
                    if age_hours < 24:
                        blacklist_text = cache_path.read_text(errors="replace")
            except Exception:
                pass

            if blacklist_text is None:
                import urllib.request
                # Emerging Threats compromised IP list (free, no key)
                url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
                req = urllib.request.Request(url, headers={"User-Agent": "Autobahn-Defender/2.0"})
                resp = urllib.request.urlopen(req, timeout=15)
                blacklist_text = resp.read().decode("utf-8", errors="replace")
                # Cache the downloaded blacklist atomically
                if cache_path:
                    try:
                        cache_path.parent.mkdir(parents=True, exist_ok=True)
                        tmp = cache_path.with_suffix(".tmp")
                        tmp.write_text(blacklist_text)
                        tmp.replace(cache_path)
                    except OSError:
                        pass

            # Parse IPs from the feed
            blacklist_ips = set()
            for line in blacklist_text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    ipaddress.ip_address(line)
                    blacklist_ips.add(line)
                except ValueError:
                    pass

            # Check established connections against the blacklist
            for line in ss_output.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 6 or parts[1] != "ESTAB":
                    continue
                remote = parts[5]
                remote_ip_str = remote.rsplit(":", 1)[0] if ":" in remote else ""
                if remote_ip_str.startswith("[") and "]" in remote_ip_str:
                    remote_ip_str = remote_ip_str[1:remote_ip_str.index("]")]
                if remote_ip_str in blacklist_ips:
                    blacklist_hits.append({
                        "type": "blacklist_hit",
                        "remote_ip": remote_ip_str,
                        "severity": "critical",
                        "indicator": f"Connection to known-compromised IP {remote_ip_str}",
                    })

        except Exception as e:
            findings.append({
                "type": "blacklist_download_error",
                "severity": "info",
                "indicator": f"Could not download threat feed: {e}",
            })

    findings.extend(blacklist_hits)

    return _ok({
        "connections_analyzed": connections_parsed,
        "findings": findings,
        "total_findings": len(findings),
        "blacklist_downloaded": download_blacklist,
        "critical_count": sum(1 for f in findings if f.get("severity") == "critical"),
        "high_count": sum(1 for f in findings if f.get("severity") == "high"),
        "medium_count": sum(1 for f in findings if f.get("severity") == "medium"),
    })


# ---------------------------------------------------------------------------
# v2.1 tools -- privacy hardening, service management, DNS, disk encryption,
# screen lock, password policy, update status, event log, startup manager,
# browser cleaner. All read-only (no system modifications).
# ---------------------------------------------------------------------------



def check_privacy_hardening(args: dict) -> dict:
    """Check kernel and network privacy/security hardening settings via sysctl."""
    findings = []

    checks = [
        # (sysctl key, expected value, description, severity if wrong)
        ("net.ipv4.tcp_syncookies", "1", "SYN flood protection", "high"),
        ("net.ipv4.conf.all.accept_redirects", "0", "ICMP redirect acceptance (all)", "medium"),
        ("net.ipv4.conf.default.accept_redirects", "0", "ICMP redirect acceptance (default)", "medium"),
        ("net.ipv4.conf.all.send_redirects", "0", "ICMP redirect sending", "medium"),
        ("net.ipv4.conf.all.accept_source_route", "0", "Source routing acceptance", "high"),
        ("net.ipv4.conf.default.accept_source_route", "0", "Source routing acceptance (default)", "high"),
        ("net.ipv4.conf.all.log_martians", "1", "Log martian packets", "low"),
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "Ignore broadcast ICMP", "medium"),
        ("net.ipv4.tcp_rfc1337", "1", "RFC 1337 TIME-WAIT hazard protection", "low"),
        ("net.ipv6.conf.all.accept_ra", "0", "IPv6 router advertisements", "low"),
        ("net.ipv6.conf.all.accept_redirects", "0", "IPv6 redirect acceptance", "medium"),
        ("kernel.randomize_va_space", "2", "ASLR (address space randomization)", "high"),
        ("kernel.dmesg_restrict", "1", "Restrict dmesg to root", "medium"),
        ("kernel.kptr_restrict", "1", "Restrict kernel pointer exposure", "medium"),
        ("kernel.yama_ptrace_scope", "1", "Restrict ptrace (process tracing)", "high"),
        ("fs.suid_dumpable", "0", "Disable SUID core dumps", "medium"),
        ("fs.protected_hardlinks", "1", "Protected hard links", "medium"),
        ("fs.protected_symlinks", "1", "Protected symlinks", "medium"),
        ("fs.protected_fifos", "2", "Protected FIFOs", "low"),
        ("fs.protected_regular", "2", "Protected regular files", "low"),
    ]

    for key, expected, desc, severity in checks:
        try:
            r = subprocess.run(
                ["sysctl", "-n", key],
                capture_output=True, text=True, timeout=5,
            )
            value = r.stdout.strip()
            status = "ok" if value == expected else "weak"
            if status == "weak":
                findings.append({
                    "setting": key,
                    "current_value": value,
                    "recommended_value": expected,
                    "description": desc,
                    "severity": severity,
                    "fix": f"echo '{key} = {expected}' | sudo tee -a /etc/sysctl.d/99-autobahn.conf && sudo sysctl -p",
                })
        except Exception as e:
            findings.append({"setting": key, "error": str(e), "severity": "low"})

    return _ok({
        "total_checks": len(checks),
        "weak_count": sum(1 for f in findings if f.get("status", "weak") == "weak"),
        "findings": findings,
        "summary": (
            f"Checked {len(checks)} kernel/network hardening settings. "
            f"{sum(1 for f in findings if f.get('status', 'weak') == 'weak')} need attention."
        ),
    })



def check_service_manager(args: dict) -> dict:
    """List systemd services, their status, and security posture.
    Identifies exposed services, unnecessary services, and services
    running with excessive privileges."""
    action = args.get("action", "list")
    service_name = args.get("service", "")

    if action == "list":
        try:
            r = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--state=running",
                 "--no-pager", "--no-legend"],
                capture_output=True, text=True, timeout=15,
            )
            services = []
            for line in (r.stdout or "").strip().splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    name = parts[0].replace(".service", "")
                    load = parts[1]
                    active = parts[2]
                    sub = parts[3]
                    services.append({
                        "name": name,
                        "load_state": load,
                        "active_state": active,
                        "sub_state": sub,
                    })

            # Check for risky exposed services
            risky_services = {
                "telnet", "rsh", "rlogin", "rexec", "tftp", "xinetd",
                "chargen", "daytime", "discard", "echo", "time",
                "samba", "nfs-server", "vsftpd", "proftpd",
                "sshd", "apache2", "nginx", "mariadb", "mysql", "postgresql",
                "redis", "mongodb", "docker", "postfix", "dovecot",
            }
            running_names = {s["name"] for s in services}
            exposed = []
            for risky in risky_services:
                if risky in running_names or risky.replace("-", "") in running_names:
                    exposed.append(risky)

            return _ok({
                "running_count": len(services),
                "services": services[:50],
                "potentially_exposed": exposed,
                "summary": (
                    f"{len(services)} services running. "
                    f"{len(exposed)} potentially risky services found: "
                    f"{', '.join(exposed) if exposed else 'none'}."
                ),
            })
        except Exception as e:
            return _err(f"Failed to list services: {e}")

    elif action == "status" and service_name:
        try:
            r = subprocess.run(
                ["systemctl", "status", service_name, "--no-pager"],
                capture_output=True, text=True, timeout=10,
            )
            return _ok({
                "service": service_name,
                "active": "active" in r.stdout.lower(),
                "output": r.stdout[:2000],
            })
        except Exception as e:
            return _err(f"Failed to check service: {e}")

    elif action == "security" and service_name:
        # Get the security posture of a service
        try:
            r = subprocess.run(
                ["systemd-analyze", "security", service_name, "--no-pager"],
                capture_output=True, text=True, timeout=10,
            )
            return _ok({
                "service": service_name,
                "security_report": r.stdout[:3000],
            })
        except Exception as e:
            return _err(f"Failed to get security report: {e}")

    return _err("Invalid action. Use 'list', 'status', or 'security'.")



def check_dns_check(args: dict) -> dict:
    """Check DNS configuration for security issues: DNS leak detection,
    DNSSEC status, and DNS server identity."""
    findings = []

    # Check /etc/resolv.conf
    try:
        with open("/etc/resolv.conf") as f:
            resolv_content = f.read()
        nameservers = []
        for line in resolv_content.splitlines():
            line = line.strip()
            if line.startswith("nameserver "):
                ns = line.split()[1]
                nameservers.append(ns)
                # Flag private DNS servers that might be intercepting
                if ns.startswith("10.") or ns.startswith("192.168.") or ns.startswith("172.16."):
                    findings.append({
                        "issue": "Private DNS server in resolv.conf",
                        "value": ns,
                        "severity": "low",
                        "note": "This is normal for home networks but verify it's your intended DNS.",
                    })
        if not nameservers:
            findings.append({
                "issue": "No nameservers in resolv.conf",
                "severity": "medium",
                "fix": "Check your network manager DNS settings.",
            })
    except Exception as e:
        findings.append({"issue": f"Cannot read resolv.conf: {e}", "severity": "low"})

    # Check if systemd-resolved is running
    try:
        r = subprocess.run(
            ["resolvectl", "status", "--no-pager"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            # Check DNSSEC status
            for line in r.stdout.splitlines():
                if "DNSSEC" in line:
                    if "no" in line.lower():
                        findings.append({
                            "issue": "DNSSEC is disabled",
                            "severity": "medium",
                            "fix": "sudo resolvectl dnssec yes",
                        })
                    elif "yes" in line.lower():
                        findings.append({
                            "issue": "DNSSEC is enabled",
                            "severity": "info",
                        })
        else:
            # systemd-resolved not running
            pass
    except Exception:
        pass

    # Check /etc/hosts for suspicious entries
    try:
        with open("/etc/hosts") as f:
            hosts_content = f.read()
        suspicious_hosts = []
        for line in hosts_content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    hostname = parts[1]
                    # Flag known-bad patterns (redirecting major sites)
                    major_sites = ["google.com", "facebook.com", "twitter.com",
                                   "amazon.com", "microsoft.com", "apple.com",
                                   "github.com", "linkedin.com"]
                    if any(site in hostname for site in major_sites):
                        suspicious_hosts.append({
                            "ip": ip,
                            "hostname": hostname,
                            "issue": f"Major site redirected to {ip}",
                            "severity": "critical",
                        })
        if suspicious_hosts:
            findings.extend(suspicious_hosts)
    except Exception as e:
        findings.append({"issue": f"Cannot read /etc/hosts: {e}", "severity": "low"})

    return _ok({
        "nameservers": nameservers if "nameservers" in dir() else [],
        "findings": findings,
        "summary": (
            f"DNS check complete. {len(findings)} finding(s)."
        ),
    })



def check_disk_encryption(args: dict) -> dict:
    """Check disk encryption status (LUKS) and identify unencrypted volumes."""
    findings = []

    # Check for LUKS encrypted devices
    try:
        r = subprocess.run(
            ["lsblk", "-o", "NAME,FSTYPE,SIZE,MOUNTPOINT,TYPE", "--no-pager"],
            capture_output=True, text=True, timeout=10,
        )
        devices = []
        encrypted = []
        unencrypted = []
        for line in (r.stdout or "").strip().splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 3:
                name, fstype = parts[0], parts[1]
                size = parts[2] if len(parts) > 2 else "?"
                mount = parts[3] if len(parts) > 3 else ""
                dev = {"name": name, "fstype": fstype, "size": size, "mountpoint": mount}
                devices.append(dev)
                if fstype == "crypto_LUKS":
                    encrypted.append(dev)
                elif fstype in ("ext4", "ext3", "ext2", "btrfs", "xfs", "ntfs", "vfat") and mount:
                    # Only flag mounted filesystems (not swap)
                    unencrypted.append(dev)

        if unencrypted:
            for dev in unencrypted:
                findings.append({
                    "device": dev["name"],
                    "fstype": dev["fstype"],
                    "mountpoint": dev["mountpoint"],
                    "issue": "Unencrypted filesystem",
                    "severity": "medium",
                    "note": "Consider encrypting with LUKS if this device stores sensitive data.",
                })
    except Exception as e:
        findings.append({"issue": f"lsblk failed: {e}", "severity": "low"})

    # Check if root filesystem is encrypted
    root_encrypted = False
    try:
        r = subprocess.run(
            ["findmnt", "-n", "-o", "SOURCE", "/"],
            capture_output=True, text=True, timeout=5,
        )
        root_source = r.stdout.strip()
        if "mapper" in root_source or "LUKS" in root_source:
            root_encrypted = True
    except Exception:
        pass

    if not root_encrypted:
        findings.append({
            "device": "root",
            "issue": "Root filesystem is NOT encrypted",
            "severity": "high",
            "fix": "Consider full disk encryption (LUKS) for the root filesystem.",
        })

    return _ok({
        "encrypted_devices": encrypted if "encrypted" in dir() else [],
        "unencrypted_devices": unencrypted if "unencrypted" in dir() else [],
        "root_encrypted": root_encrypted,
        "findings": findings,
        "summary": (
            f"Disk encryption check: root {'encrypted' if root_encrypted else 'NOT encrypted'}. "
            f"{len(findings)} finding(s)."
        ),
    })



def check_screen_lock(args: dict) -> dict:
    """Check screen lock settings for various desktop environments."""
    findings = []

    # Detect desktop environment
    de = os.environ.get("XDG_CURRENT_DESKTOP", "").lower()
    session = os.environ.get("XDG_SESSION_DESKTOP", "")

    # Check for GNOME/gsettings
    try:
        r = subprocess.run(
            ["gsettings", "get", "org.gnome.desktop.session", "idle-delay"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            idle_delay = r.stdout.strip()
            if idle_delay == "uint32 0":
                findings.append({
                    "issue": "Screen lock idle delay is disabled (0)",
                    "severity": "medium",
                    "fix": "gsettings set org.gnome.desktop.session idle-delay 300",
                })
            else:
                findings.append({
                    "setting": "idle_delay",
                    "value": idle_delay,
                    "status": "ok",
                })

        # Check if lock screen is enabled
        r2 = subprocess.run(
            ["gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled"],
            capture_output=True, text=True, timeout=5,
        )
        if r2.returncode == 0:
            lock_enabled = r2.stdout.strip()
            if "false" in lock_enabled.lower():
                findings.append({
                    "issue": "Screen lock is disabled",
                    "severity": "high",
                    "fix": "gsettings set org.gnome.desktop.screensaver lock-enabled true",
                })
    except FileNotFoundError:
        # gsettings not available, try other DEs
        pass

    # Check for xscreensaver/light-locker (XFCE/Mate)
    try:
        r = subprocess.run(
            ["which", "xscreensaver-command"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            r2 = subprocess.run(
                ["xscreensaver-command", "-time"],
                capture_output=True, text=True, timeout=5,
            )
            if r2.returncode == 0:
                findings.append({"setting": "xscreensaver", "status": "installed"})
    except Exception:
        pass

    if not findings:
        findings.append({
            "issue": "Could not determine screen lock status",
            "severity": "low",
            "note": f"Desktop: {de or session or 'unknown'}. Manual check recommended.",
        })

    return _ok({
        "desktop": de or session or "unknown",
        "findings": findings,
        "summary": f"Screen lock check for {de or session or 'unknown'}: {len(findings)} finding(s).",
    })



def check_password_policy(args: dict) -> dict:
    """Check password policy and authentication settings."""
    findings = []

    # Check PAM configuration for password quality
    try:
        pam_files = ["/etc/pam.d/common-password", "/etc/pam.d/common-auth",
                     "/etc/pam.d/system-auth", "/etc/pam.d/login"]
        for pf in pam_files:
            if not os.path.exists(pf):
                continue
            with open(pf) as f:
                content = f.read()
            if "pam_pwquality" in content or "pam_cracklib" in content:
                findings.append({
                    "file": pf,
                    "setting": "password_quality_module",
                    "status": "ok",
                    "note": "Password quality module is configured.",
                })
            elif "password" in pf:
                findings.append({
                    "file": pf,
                    "issue": "No password quality module found",
                    "severity": "medium",
                    "fix": "Install libpam-pwquality and configure in /etc/pam.d/common-password",
                })

            # Check for password reuse prevention
            if "remember=" in content:
                for line in content.splitlines():
                    if "remember=" in line:
                        findings.append({
                            "file": pf,
                            "setting": "password_history",
                            "value": line.strip(),
                            "status": "ok",
                        })
            elif "password" in pf:
                findings.append({
                    "file": pf,
                    "issue": "No password history/reuse prevention",
                    "severity": "low",
                    "fix": "Add remember=5 to pam_unix.so in common-password",
                })
    except Exception as e:
        findings.append({"issue": f"Cannot read PAM config: {e}", "severity": "low"})

    # Check login.defs for password aging
    try:
        if os.path.exists("/etc/login.defs"):
            with open("/etc/login.defs") as f:
                content = f.read()
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("PASS_MAX_DAYS"):
                    val = int(line.split()[-1])
                    if val > 90:
                        findings.append({
                            "setting": "PASS_MAX_DAYS",
                            "value": val,
                            "severity": "low",
                            "fix": "Set PASS_MAX_DAYS to 90 in /etc/login.defs",
                        })
                elif line.startswith("PASS_MIN_LEN"):
                    val = int(line.split()[-1])
                    if val < 12:
                        findings.append({
                            "setting": "PASS_MIN_LEN",
                            "value": val,
                            "severity": "medium",
                            "fix": "Set PASS_MIN_LEN to 12 in /etc/login.defs",
                        })
    except Exception as e:
        findings.append({"issue": f"Cannot read login.defs: {e}", "severity": "low"})

    # Check for empty passwords
    try:
        r = subprocess.run(
            ["awk", "-F:", "($2==\"\") {print $1}", "/etc/shadow"],
            capture_output=True, text=True, timeout=5,
        )
        empty_pw_users = r.stdout.strip().splitlines() if r.stdout.strip() else []
        if empty_pw_users:
            findings.append({
                "issue": f"Users with empty passwords: {', '.join(empty_pw_users)}",
                "severity": "critical",
                "fix": f"sudo passwd {empty_pw_users[0]}",
            })
    except Exception:
        pass

    return _ok({
        "findings": findings,
        "summary": f"Password policy check: {len(findings)} finding(s).",
    })



def check_update_status(args: dict) -> dict:
    """Check for available security updates and system update status."""
    findings = []

    # Check for available updates
    try:
        # First apt update (may need root, try without)
        subprocess.run(
            ["apt-get", "check"],
            capture_output=True, text=True, timeout=30,
        )
        r = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True, text=True, timeout=30,
        )
        upgradable = []
        for line in (r.stdout or "").splitlines()[1:]:  # skip "Listing..." header
            if "/" in line:
                parts = line.split("/")
                pkg = parts[0]
                info = parts[1] if len(parts) > 1 else ""
                upgradable.append({"package": pkg, "info": info})

        security_updates = [u for u in upgradable if "security" in u.get("info", "").lower()]
        regular_updates = [u for u in upgradable if u not in security_updates]

        if security_updates:
            findings.append({
                "issue": f"{len(security_updates)} security updates available",
                "severity": "high",
                "packages": [u["package"] for u in security_updates[:20]],
                "fix": "sudo apt update && sudo apt upgrade",
            })

        if regular_updates:
            findings.append({
                "issue": f"{len(regular_updates)} regular updates available",
                "severity": "low",
                "packages": [u["package"] for u in regular_updates[:10]],
                "fix": "sudo apt update && sudo apt upgrade",
            })

        if not upgradable:
            findings.append({"status": "ok", "message": "System is up to date."})

    except Exception as e:
        findings.append({"issue": f"Cannot check updates: {e}", "severity": "low"})

    # Check last apt update timestamp
    try:
        update_file = "/var/lib/apt/lists/partial"
        if os.path.exists(update_file):
            mtime = os.path.getmtime(update_file)
            from datetime import datetime
            age_days = (datetime.now().timestamp() - mtime) / 86400
            if age_days > 7:
                findings.append({
                    "issue": f"Last apt update was {age_days:.0f} days ago",
                    "severity": "medium",
                    "fix": "sudo apt update",
                })
    except Exception:
        pass

    # Check if automatic updates are enabled
    try:
        if os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades"):
            with open("/etc/apt/apt.conf.d/20auto-upgrades") as f:
                content = f.read()
            if '"1"' in content and "APT::Periodic::Update-Package-Lists" in content:
                findings.append({"setting": "auto_update", "status": "enabled"})
            else:
                findings.append({
                    "setting": "auto_update",
                    "status": "disabled",
                    "severity": "low",
                    "fix": "sudo dpkg-reconfigure -plow unattended-upgrades",
                })
    except Exception:
        pass

    return _ok({
        "upgradable_count": len(upgradable) if "upgradable" in dir() else 0,
        "security_updates": len(security_updates) if "security_updates" in dir() else 0,
        "findings": findings,
        "summary": (
            f"{len(security_updates) if 'security_updates' in dir() else 0} security updates, "
            f"{len(upgradable) if 'upgradable' in dir() else 0} total upgradable."
        ),
    })



def check_event_log(args: dict) -> dict:
    """Check system auth log and journal for security events: failed logins,
    sudo usage, SSH brute force attempts, and suspicious activity."""
    max_lines = int(args.get("max_lines", 50))
    max_lines = min(max_lines, 200)
    findings = []

    # Check auth log for failed logins
    try:
        auth_log = "/var/log/auth.log"
        if not os.path.exists(auth_log):
            auth_log = "/var/log/secure"
        if os.path.exists(auth_log):
            r = subprocess.run(
                ["tail", "-n", str(max_lines), auth_log],
                capture_output=True, text=True, timeout=10,
            )
            lines = (r.stdout or "").splitlines()
            failed_logins = [l for l in lines if "Failed password" in l]
            successful_logins = [l for l in lines if "Accepted password" in l or "session opened" in l]
            sudo_usage = [l for l in lines if "sudo" in l.lower() and "COMMAND" in l]
            ssh_brute = [l for l in lines if "Failed password" in l and "ssh" in l.lower()]
            invalid_users = [l for l in lines if "Invalid user" in l]

            if failed_logins:
                # Extract unique IPs
                import re
                ips = set()
                for l in failed_logins:
                    m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", l)
                    if m:
                        ips.add(m.group(1))
                findings.append({
                    "issue": f"{len(failed_logins)} failed login attempts",
                    "severity": "high" if len(failed_logins) > 10 else "medium",
                    "unique_ips": list(ips)[:10],
                    "fix": "Install fail2ban: sudo apt install fail2ban",
                })

            if invalid_users:
                findings.append({
                    "issue": f"{len(invalid_users)} attempts with invalid usernames",
                    "severity": "medium",
                    "note": "Possible username enumeration or brute force attack.",
                })

            if ssh_brute and len(ssh_brute) > 5:
                findings.append({
                    "issue": f"SSH brute force detected: {len(ssh_brute)} attempts",
                    "severity": "high",
                    "fix": "sudo apt install fail2ban && sudo systemctl enable fail2ban",
                })

            return _ok({
                "failed_logins": len(failed_logins),
                "successful_logins": len(successful_logins),
                "sudo_commands": len(sudo_usage),
                "ssh_brute_force": len(ssh_brute),
                "unique_attacker_ips": list(ips)[:10] if "ips" in dir() else [],
                "findings": findings,
                "recent_events": lines[-20:] if lines else [],
                "summary": (
                    f"Auth log: {len(failed_logins)} failed logins, "
                    f"{len(successful_logins)} successful, "
                    f"{len(ssh_brute)} SSH brute force attempts."
                ),
            })
    except PermissionError:
        findings.append({
            "issue": "Cannot read auth log (permission denied)",
            "severity": "medium",
            "fix": "Run: sudo autobahn-defender",
        })
    except Exception as e:
        findings.append({"issue": f"Cannot read auth log: {e}", "severity": "low"})

    # Fallback: try journalctl
    try:
        r = subprocess.run(
            ["journalctl", "-n", str(max_lines), "--no-pager", "-p", "warning"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0 and r.stdout:
            lines = r.stdout.splitlines()
            security_events = [l for l in lines if any(
                kw in l.lower() for kw in ["failed", "denied", "error", "warning", "attack"]
            )]
            return _ok({
                "source": "journalctl",
                "total_events": len(lines),
                "security_events": len(security_events),
                "findings": findings,
                "recent_events": security_events[-20:],
                "summary": f"Journal: {len(security_events)} security events in last {max_lines} lines.",
            })
    except Exception:
        pass

    return _ok({"findings": findings, "summary": "No auth log or journal available."})



def check_startup_manager(args: dict) -> dict:
    """List and analyze startup programs (systemd units, cron, autostart).
    Identifies suspicious persistence mechanisms."""
    findings = []
    startup_items = []

    # Check systemd user services
    try:
        r = subprocess.run(
            ["systemctl", "list-unit-files", "--type=service",
             "--state=enabled", "--no-pager", "--no-legend"],
            capture_output=True, text=True, timeout=10,
        )
        for line in (r.stdout or "").strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                startup_items.append({
                    "name": parts[0],
                    "type": "systemd-service",
                    "state": parts[1],
                })
    except Exception:
        pass

    # Check autostart directories
    autostart_dirs = [
        os.path.expanduser("~/.config/autostart"),
        "/etc/xdg/autostart",
    ]
    for d in autostart_dirs:
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.endswith(".desktop"):
                    filepath = os.path.join(d, f)
                    try:
                        with open(filepath) as fh:
                            content = fh.read()
                        # Extract the Exec line
                        exec_line = ""
                        for line in content.splitlines():
                            if line.startswith("Exec="):
                                exec_line = line[5:].strip()
                                break
                        startup_items.append({
                            "name": f,
                            "type": "autostart",
                            "path": filepath,
                            "exec": exec_line[:200],
                        })
                        # Check for suspicious patterns
                        if any(kw in exec_line.lower() for kw in
                               ["curl", "wget", "nc ", "nc.", "python -c", "bash -c",
                                "base64", "/tmp/", "/dev/shm/"]):
                            findings.append({
                                "issue": f"Suspicious autostart: {f}",
                                "exec": exec_line[:200],
                                "severity": "high",
                                "fix": f"Review and remove if unwanted: rm '{filepath}'",
                            })
                    except Exception:
                        pass

    # Check user crontab
    try:
        r = subprocess.run(
            ["crontab", "-l"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            for line in r.stdout.strip().splitlines():
                if line and not line.startswith("#"):
                    startup_items.append({
                        "name": "user-crontab",
                        "type": "cron",
                        "exec": line[:200],
                    })
                    if any(kw in line.lower() for kw in
                           ["curl", "wget", "nc ", "python", "bash -c", "base64"]):
                        findings.append({
                            "issue": "Suspicious crontab entry",
                            "exec": line[:200],
                            "severity": "high",
                        })
    except Exception:
        pass

    # Check /etc/crontab and /etc/cron.d
    try:
        for cron_file in ["/etc/crontab"] + (
            os.listdir("/etc/cron.d") if os.path.isdir("/etc/cron.d") else []
        ):
            full_path = cron_file if cron_file.startswith("/etc/") else f"/etc/cron.d/{cron_file}"
            if os.path.exists(full_path):
                with open(full_path) as f:
                    for line in f:
                        if line.strip() and not line.startswith("#"):
                            startup_items.append({
                                "name": full_path,
                                "type": "system-cron",
                                "exec": line.strip()[:200],
                            })
    except Exception:
        pass

    return _ok({
        "total_items": len(startup_items),
        "startup_items": startup_items[:80],
        "findings": findings,
        "summary": (
            f"{len(startup_items)} startup items found. "
            f"{len(findings)} suspicious item(s)."
        ),
    })



def check_browser_cleaner(args: dict) -> dict:
    """Check browser privacy and security settings, identify tracking cookies,
    suspicious extensions, and cached data. Supports Firefox and Chrome/Chromium."""
    findings = []
    browsers_found = []

    # Firefox profiles
    firefox_dir = os.path.expanduser("~/.mozilla/firefox")
    if os.path.isdir(firefox_dir):
        browsers_found.append("firefox")
        try:
            for profile_name in os.listdir(firefox_dir):
                profile_path = os.path.join(firefox_dir, profile_name)
                if not os.path.isdir(profile_path):
                    continue
                prefs_file = os.path.join(profile_path, "prefs.js")
                if os.path.exists(prefs_file):
                    with open(prefs_file) as f:
                        prefs_content = f.read()
                    # Check tracking protection
                    if '"privacy.trackingprotection.enabled", true' not in prefs_content:
                        findings.append({
                            "browser": "firefox",
                            "profile": profile_name,
                            "issue": "Tracking protection is not enabled",
                            "severity": "medium",
                            "fix": "Enable in Firefox: Preferences > Privacy > Tracking Protection",
                        })
                    # Check third-party cookies
                    if '"network.cookie.cookieBehavior", 1' not in prefs_content:
                        findings.append({
                            "browser": "firefox",
                            "profile": profile_name,
                            "issue": "Third-party cookies may be allowed",
                            "severity": "low",
                            "fix": "Set network.cookie.cookieBehavior to 1 in about:config",
                        })
                    # Check telemetry
                    if '"datareporting.healthreport.uploadEnabled", true' in prefs_content:
                        findings.append({
                            "browser": "firefox",
                            "profile": profile_name,
                            "issue": "Telemetry/data collection is enabled",
                            "severity": "low",
                            "fix": "Set datareporting.healthreport.uploadEnabled to false",
                        })

                # Check extensions
                ext_dir = os.path.join(profile_path, "extensions")
                if os.path.isdir(ext_dir):
                    exts = [f for f in os.listdir(ext_dir) if f.endswith(".xpi")]
                    if len(exts) > 20:
                        findings.append({
                            "browser": "firefox",
                            "profile": profile_name,
                            "issue": f"Large number of extensions ({len(exts)})",
                            "severity": "low",
                            "note": "Review extensions for privacy/security implications.",
                        })

                # Check cache size
                cache_dir = os.path.join(profile_path, "cache2")
                if os.path.isdir(cache_dir):
                    total_size = 0
                    for dirpath, dirnames, filenames in os.walk(cache_dir):
                        for fn in filenames:
                            try:
                                total_size += os.path.getsize(os.path.join(dirpath, fn))
                            except OSError:
                                pass
                    if total_size > 500 * 1024 * 1024:  # >500MB
                        findings.append({
                            "browser": "firefox",
                            "profile": profile_name,
                            "issue": f"Large cache: {total_size / (1024*1024):.0f}MB",
                            "severity": "low",
                            "fix": "Clear cache in Firefox: Preferences > Privacy > Clear Cache",
                        })
        except Exception as e:
            findings.append({"browser": "firefox", "issue": f"Error: {e}", "severity": "low"})

    # Chrome/Chromium profiles
    for chrome_base in ["~/.config/google-chrome", "~/.config/chromium",
                        "~/.config/brave", "~/.snap/chromium"]:
        chrome_dir = os.path.expanduser(chrome_base)
        if os.path.isdir(chrome_dir):
            browsers_found.append(os.path.basename(chrome_dir))
            try:
                # Check preferences file
                prefs_file = os.path.join(chrome_dir, "Default", "Preferences")
                if os.path.exists(prefs_file):
                    import json as _json
                    with open(prefs_file) as f:
                        prefs = _json.load(f)
                    # Check Safe Browsing
                    safe_browsing = (prefs.get("safebrowsing", {})
                                     .get("enabled", True))
                    if not safe_browsing:
                        findings.append({
                            "browser": os.path.basename(chrome_dir),
                            "issue": "Safe Browsing is disabled",
                            "severity": "high",
                            "fix": "Enable in Settings > Privacy > Safe Browsing",
                        })
                    # Check extensions
                    exts = prefs.get("extensions", {}).get("settings", {})
                    if len(exts) > 20:
                        findings.append({
                            "browser": os.path.basename(chrome_dir),
                            "issue": f"Large number of extensions ({len(exts)})",
                            "severity": "low",
                        })
            except Exception as e:
                findings.append({
                    "browser": os.path.basename(chrome_dir),
                    "issue": f"Error: {e}",
                    "severity": "low",
                })

    if not browsers_found:
        findings.append({
            "issue": "No supported browsers found",
            "severity": "info",
        })

    return _ok({
        "browsers_found": browsers_found,
        "findings": findings,
        "summary": (
            f"Browser check: {', '.join(browsers_found) or 'none found'}. "
            f"{len(findings)} finding(s)."
        ),
    })


# ---------------------------------------------------------------------------
# Composite tools -- combine multiple checks into single calls
# ---------------------------------------------------------------------------



def check_mac_status(_: dict) -> dict:
    """MAC (Mandatory Access Control) status: AppArmor/SELinux probing.

    Audit 2026-08-31 A-1 fix: the composite hardening audit referenced
    _t_mac_status, which was never ported from ai/tools.py. Ported from
    Kudu src/main/platform/linux/security.ts (MIT, AdventDevInc/kudu).
    """
    result: dict[str, Any] = {"apparmor": {"installed": False}, "selinux": {"installed": False}}

    # --- AppArmor ---
    if shutil.which("aa-status"):
        aa = _run(["aa-status"], timeout=10)
        profiles_enforce = profiles_complain = 0
        if aa.get("status") == "ok":
            out = aa.get("data", {}).get("output", "")
            m_enforce = re.search(r"(\d+)\s+profiles are in enforce mode", out)
            m_complain = re.search(r"(\d+)\s+profiles are in complain mode", out)
            if m_enforce:
                profiles_enforce = int(m_enforce.group(1))
            if m_complain:
                profiles_complain = int(m_complain.group(1))
        result["apparmor"] = {
            "installed": True,
            "profiles_enforcing": profiles_enforce,
            "profiles_complain": profiles_complain,
            "raw": aa,
        }

    # --- SELinux ---
    getenforce = shutil.which("getenforce")
    if getenforce:
        r = _run(["getenforce"], timeout=5)
        state = ""
        if r.get("status") == "ok":
            state = r.get("data", {}).get("output", "").strip()
        result["selinux"] = {
            "installed": True,
            "mode": state.splitlines()[0].strip() if state else "unknown",
        }

    # Findings for the unified schema
    findings = []
    if result["apparmor"].get("installed"):
        n_enforce = result["apparmor"].get("profiles_enforce", 0)
        n_complain = result["apparmor"].get("profiles_complain", 0)
        if n_enforce == 0 and (n_complain or 0) > 0:
            findings.append({
                "severity": "medium",
                "check_id": "AD-MAC-002",
                "title": "AppArmor profiles in complain mode only",
                "what": f"{n_complain} AppArmor profiles are in complain mode; none enforcing.",
                "why": "Complain mode logs violations but does not block them.",
                "fix": "sudo aa-enforce /etc/apparmor.d/*",
                "fix_command": ["aa-enforce", "/etc/apparmor.d/*"],
            })
    elif result["selinux"].get("installed") is False:
        # Neither MAC system detected
        if not Path("/sys/kernel/security/apparmor").exists() and not Path("/sys/fs/selinux").exists():
            result["note"] = ("No MAC (AppArmor/SELinux) enforcement information available; "
                              "profiles may still be managed by the distro.")
    return _ok({**result, "findings": findings})


def check_network_security(args: dict) -> dict:
    """Composite network security scan. Combines network connections,
    threat monitor, DNS check, and firewall check.

    Each sub-check has its own try/except so one failure doesn't break the scan.
    Audit 2026-08-31 A-1 fix: previously called undefined _t_* names (every
    sub-check always errored); now dispatches through the check registry.
    """
    # --- Network connections ---
    connections_result = None
    try:
        connections_result = run_check("check_network_connections", {})
    except Exception as e:
        connections_result = _err(f"network_connections failed: {e}")

    # --- Network threat monitor ---
    threat_result = None
    try:
        threat_result = run_check("check_network_threat_monitor",
                                  {"download_blacklist": False})
    except Exception as e:
        threat_result = _err(f"network_threat_monitor failed: {e}")

    # --- DNS check ---
    dns_result = None
    try:
        dns_result = run_check("check_dns_check", {})
    except Exception as e:
        dns_result = _err(f"dns_check failed: {e}")

    # --- Firewall check ---
    firewall_result = None
    try:
        firewall_result = run_check("check_firewall_check", {})
    except Exception as e:
        firewall_result = _err(f"firewall_check failed: {e}")

    # --- Aggregate ---
    connections_summary = "unavailable"
    if connections_result and connections_result.get("status") == "ok":
        conn_data = connections_result.get("data", {})
        listening_ok = conn_data.get("listening", {}).get("status") == "ok"
        established_ok = conn_data.get("established", {}).get("status") == "ok"
        connections_summary = (
            f"Listening ports: {'retrieved' if listening_ok else 'failed'}, "
            f"Established connections: {'retrieved' if established_ok else 'failed'}"
        )

    threat_findings = []
    if threat_result and threat_result.get("status") == "ok":
        threat_findings = threat_result.get("data", {}).get("findings", [])

    dns_findings = []
    if dns_result and dns_result.get("status") == "ok":
        dns_findings = dns_result.get("data", {}).get("findings", [])

    # Firewall status: truncate output strings to prevent context overflow
    firewall_status = {}
    if firewall_result and firewall_result.get("status") == "ok":
        firewall_status = firewall_result.get("data", {})
        for key in list(firewall_status.keys()):
            val = firewall_status[key]
            if isinstance(val, dict) and val.get("status") == "ok":
                data = val.get("data", {})
                if isinstance(data, dict) and "output" in data:
                    data["output"] = _truncate(data["output"], 2000)

    # Count findings across checks
    total_findings = len(threat_findings) + len(dns_findings)
    critical_count = (
        sum(1 for f in threat_findings if f.get("severity") == "critical")
        + sum(1 for f in dns_findings if f.get("severity") == "critical")
    )
    high_count = (
        sum(1 for f in threat_findings if f.get("severity") == "high")
        + sum(1 for f in dns_findings if f.get("severity") == "high")
    )

    # Unified schema (P0, audit A-1/A-5): one findings key + per-sub check status
    # so the advisor/CLI consume a single shape.
    sub_checks = {
        "network_connections": connections_result or _err("unavailable"),
        "network_threat_monitor": threat_result or _err("unavailable"),
        "dns_check": dns_result or _err("unavailable"),
        "firewall_check": firewall_result or _err("unavailable"),
    }
    degraded = any(r.get("status") != "ok" for r in sub_checks.values())

    return _ok({
        "connections_summary": connections_summary,
        "threat_findings": threat_findings[:50],
        "dns_findings": dns_findings[:50],
        "firewall_status": firewall_status,
        "total_findings": total_findings,
        "critical_count": critical_count,
        "high_count": high_count,
        "findings": threat_findings + dns_findings,
        "sub_checks": sub_checks,
        "degraded": degraded,
    })



def check_hardening_audit(args: dict) -> dict:
    """Composite hardening audit. Combines privacy hardening, SSH audit,
    MAC status, screen lock, password policy, and disk encryption checks.

    Each sub-check has its own try/except so one failure doesn't break the audit.
    Audit 2026-08-31 A-1 fix: previously called undefined _t_* names.
    """
    checks = {}

    # --- Privacy hardening ---
    try:
        checks["privacy_hardening"] = run_check("check_privacy_hardening", {})
    except Exception as e:
        checks["privacy_hardening"] = _err(f"privacy_hardening failed: {e}")

    # --- SSH audit ---
    try:
        checks["ssh_audit"] = run_check("check_ssh_audit", {})
    except Exception as e:
        checks["ssh_audit"] = _err(f"ssh_audit failed: {e}")

    # --- MAC status ---
    try:
        checks["mac_status"] = run_check("check_mac_status", {})
    except Exception as e:
        checks["mac_status"] = _err(f"mac_status failed: {e}")

    # --- Screen lock ---
    try:
        checks["screen_lock"] = run_check("check_screen_lock", {})
    except Exception as e:
        checks["screen_lock"] = _err(f"screen_lock failed: {e}")

    # --- Password policy ---
    try:
        checks["password_policy"] = run_check("check_password_policy", {})
    except Exception as e:
        checks["password_policy"] = _err(f"password_policy failed: {e}")

    # --- Disk encryption ---
    try:
        checks["disk_encryption"] = run_check("check_disk_encryption", {})
    except Exception as e:
        checks["disk_encryption"] = _err(f"disk_encryption failed: {e}")

    # --- Aggregate ---
    total_checks = len(checks)
    all_findings = []
    summaries = {}

    for name, result in checks.items():
        if result.get("status") != "ok":
            summaries[name] = f"error: {result.get('error', 'unknown')}"
            continue
        data = result.get("data", {})
        # Extract summary if available
        summary = data.get("summary", "")
        if not summary:
            findings = data.get("findings", [])
            summary = f"{len(findings)} finding(s)"
        summaries[name] = _truncate(summary, 300)
        all_findings.extend(data.get("findings", []))

    total_findings = len(all_findings)
    critical_count = sum(1 for f in all_findings if f.get("severity") == "critical")
    high_count = sum(1 for f in all_findings if f.get("severity") == "high")
    medium_count = sum(1 for f in all_findings if f.get("severity") == "medium")

    # Unified schema (P0): findings + sub_checks + degraded flag, so the
    # advisor and CLI consume the same keys as every other check.
    return _ok({
        "total_checks": total_checks,
        "total_findings": total_findings,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "summaries": summaries,
        "findings": all_findings,
        "sub_checks": checks,
        "degraded": any(r.get("status") != "ok" for r in checks.values()),
    })


# ---------------------------------------------------------------------------
# Check registry -- maps name -> callable
# ---------------------------------------------------------------------------

def _tool(name: str, desc: str, params: dict, impl: Callable) -> dict:
    """Compatibility wrapper — returns a minimal descriptor.
    The old TOOL_REGISTRY is removed; checks are registered in CHECKS below.
    """
    return {"name": name, "description": desc, "impl": impl}


CHECKS: dict[str, Callable] = {
    "_t_system_audit": check_system_audit,
    "check_system_audit": check_system_audit,
    "_t_firewall_check": check_firewall_check,
    "check_firewall_check": check_firewall_check,
    "_t_apparmor_status": check_apparmor_status,
    "check_apparmor_status": check_apparmor_status,
    "_t_running_processes": check_running_processes,
    "check_running_processes": check_running_processes,
    "_t_installed_packages": check_installed_packages,
    "check_installed_packages": check_installed_packages,
    "_t_pending_updates": check_pending_updates,
    "check_pending_updates": check_pending_updates,
    "_t_network_connections": check_network_connections,
    "check_network_connections": check_network_connections,
    "_t_ssh_config_check": check_ssh_config_check,
    "check_ssh_config_check": check_ssh_config_check,
    "_t_suid_binaries": check_suid_binaries,
    "check_suid_binaries": check_suid_binaries,
    "_t_startup_items": check_startup_items,
    "check_startup_items": check_startup_items,
    "_t_kernel_info": check_kernel_info,
    "check_kernel_info": check_kernel_info,
    "_t_auth_log_check": check_auth_log_check,
    "check_auth_log_check": check_auth_log_check,
    "_t_yara_scan_file": check_yara_scan_file,
    "check_yara_scan_file": check_yara_scan_file,
    "_t_file_info": check_file_info,
    "check_file_info": check_file_info,
    "_t_whois_lookup": check_whois_lookup,
    "check_whois_lookup": check_whois_lookup,
    "_t_investigate_process": check_investigate_process,
    "check_investigate_process": check_investigate_process,
    "_t_scan_persistence": check_scan_persistence,
    "check_scan_persistence": check_scan_persistence,
    "_t_check_hosts": check_check_hosts,
    "check_check_hosts": check_check_hosts,
    "_t_analyze_script": check_analyze_script,
    "check_analyze_script": check_analyze_script,
    "_t_ssh_audit": check_ssh_audit,
    "check_ssh_audit": check_ssh_audit,
    "_t_network_threat_monitor": check_network_threat_monitor,
    "check_network_threat_monitor": check_network_threat_monitor,
    "_t_privacy_hardening": check_privacy_hardening,
    "check_privacy_hardening": check_privacy_hardening,
    "_t_service_manager": check_service_manager,
    "check_service_manager": check_service_manager,
    "_t_dns_check": check_dns_check,
    "check_dns_check": check_dns_check,
    "_t_disk_encryption": check_disk_encryption,
    "check_disk_encryption": check_disk_encryption,
    "_t_screen_lock": check_screen_lock,
    "check_screen_lock": check_screen_lock,
    "_t_password_policy": check_password_policy,
    "check_password_policy": check_password_policy,
    "_t_update_status": check_update_status,
    "check_update_status": check_update_status,
    "_t_event_log": check_event_log,
    "check_event_log": check_event_log,
    "_t_startup_manager": check_startup_manager,
    "check_startup_manager": check_startup_manager,
    "_t_browser_cleaner": check_browser_cleaner,
    "check_browser_cleaner": check_browser_cleaner,
    "_t_mac_status": check_mac_status,
    "check_mac_status": check_mac_status,
    "_t_network_security": check_network_security,
    "check_network_security": check_network_security,
    "_t_hardening_audit": check_hardening_audit,
    "check_hardening_audit": check_hardening_audit,
}


def get_check(name: str) -> Callable | None:
    """Look up a check function by name."""
    return CHECKS.get(name)


def run_check(name: str, args: dict | None = None) -> dict:
    """Run a check by name. Returns the check's result dict."""
    fn = CHECKS.get(name)
    if not fn:
        return _err(f"Unknown check: {name}")
    try:
        return fn(args or {})
    except Exception as e:
        return _err(f"Check {name} failed: {e}")


def list_checks() -> list[str]:
    """List all available check names."""
    return sorted(set(CHECKS.keys()))
