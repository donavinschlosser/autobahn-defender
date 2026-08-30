"""
Autobahn Defender v2.1 -- Whitelisted tool functions + registry.

Each tool is a Python dict in the OpenAI tool format:
  {
    "type": "function",
    "function": {
      "name": "...",
      "description": "...",
      "parameters": { JSON schema },
    },
    "_impl": <python callable>   # stripped before sending to Ollama
  }

Safety rules enforced here:
  - Every tool is a whitelisted Python function. The model NEVER gets
    raw shell access.
  - Tool results are truncated to ~4K tokens to prevent context overflow.
  - All tool output is sanitized (no control chars, no binary data).
  - The model can only request tool calls; the app validates and executes.
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

# Max characters per tool result (~4K tokens ~= 16K chars). With 64K
# context, this allows ~16 tool results before hitting the cap.
MAX_RESULT_CHARS = 16000                    # ~4K tokens per tool result

# Timeout for any single subprocess a tool spawns.
SUBPROCESS_TIMEOUT = 20


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _truncate(text: str, limit: int = MAX_RESULT_CHARS) -> str:
    """Truncate text to limit chars, appending a notice if cut."""
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated, " + str(len(text) - limit) + " more chars]"


def _sanitize(text: str) -> str:
    """Strip control characters and non-printable junk from text."""
    if not isinstance(text, str):
        text = str(text)
    # Keep newlines, tabs; strip other control chars
    text = "".join(ch for ch in text if ch in "\n\t" or unicodedata.category(ch)[0] != "C")
    return text


def _ok(data: Any) -> dict[str, Any]:
    return {"status": "ok", "data": data}


def _err(msg: str) -> dict[str, Any]:
    return {"status": "error", "error": str(msg)[:2000]}


def _run(cmd: list[str], timeout: int = SUBPROCESS_TIMEOUT) -> dict[str, Any]:
    """Run a command safely and return captured output. Never raises."""
    try:
        # Validate command is whitelisted (defensive -- callers already use
        # hardcoded commands, but this guards against accidental injection)
        if not cmd or not isinstance(cmd[0], str):
            return _err("Invalid command")
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        out = (r.stdout or "") + (("\n[stderr]\n" + r.stderr) if r.stderr else "")
        return _ok({
            "exit_code": r.returncode,
            "output": _truncate(_sanitize(out)),
        })
    except subprocess.TimeoutExpired:
        return _err(f"Command timed out after {timeout}s: {' '.join(cmd[:3])}")
    except FileNotFoundError:
        return _err(f"Command not found: {cmd[0]}")
    except Exception as e:
        return _err(f"Command failed: {e}")


def _run_text(cmd: list[str], timeout: int = SUBPROCESS_TIMEOUT) -> str:
    """Convenience: run command, return just the stdout text (sanitized)."""
    res = _run(cmd, timeout)
    if res["status"] == "ok":
        return res["data"]["output"]
    return f"[error: {res.get('error', 'unknown')}]"


# ---------------------------------------------------------------------------
# Tool implementations
# Each returns {"status": "ok", "data": {...}} or {"status": "error", "error": ...}
# ---------------------------------------------------------------------------

def _t_system_audit(_: dict) -> dict:
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


def _t_firewall_check(_: dict) -> dict:
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


def _t_apparmor_status(_: dict) -> dict:
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


def _t_running_processes(_: dict) -> dict:
    """Get running processes with full command lines."""
    return _run(["ps", "auxf", "--sort=-%cpu"])


def _t_installed_packages(_: dict) -> dict:
    """Get installed packages. Runs dpkg -l."""
    return _run(["dpkg", "-l"])


def _t_pending_updates(_: dict) -> dict:
    """Get pending system updates. Runs apt list --upgradable."""
    return _run(["apt", "list", "--upgradable"])


def _t_network_connections(_: dict) -> dict:
    """Get network connections. Runs ss -tulpn and ss -tup."""
    return _ok({
        "listening": _run(["ss", "-tulpn"]),
        "established": _run(["ss", "-tup"]),
    })


def _t_ssh_config_check(_: dict) -> dict:
    """Check SSH configuration. Reads /etc/ssh/sshd_config."""
    try:
        p = Path("/etc/ssh/sshd_config")
        if not p.exists():
            return _err("No sshd_config found")
        return _ok({"content": _truncate(_sanitize(p.read_text(errors="replace")))})
    except Exception as e:
        return _err(str(e))


def _t_suid_binaries(_: dict) -> dict:
    """Find SUID/SGID binaries."""
    return _ok({
        "suid": _run(["find", "/", "-xdev", "-perm", "-4000", "-type", "f"], timeout=30),
        "sgid": _run(["find", "/", "-xdev", "-perm", "-2000", "-type", "f"], timeout=30),
    })


def _t_startup_items(_: dict) -> dict:
    """List startup/persistence items. systemd units, cron, timers, autostart."""
    return _ok({
        "systemd_services": _run(["systemctl", "list-unit-files", "--state=enabled", "--no-pager"]),
        "systemd_timers": _run(["systemctl", "list-timers", "--all", "--no-pager"]),
        "cron_user": _run(["crontab", "-l"]),
        "cron_system": _run(["ls", "-la", "/etc/cron.d/"]),
        "autostart_user": _run(["ls", "-la", str(Path.home() / ".config" / "autostart")]),
        "autostart_system": _run(["ls", "-la", "/etc/xdg/autostart"]),
    })


def _t_kernel_info(_: dict) -> dict:
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


def _t_auth_log_check(_: dict) -> dict:
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


def _t_web_search(args: dict) -> dict:
    """Search the web via DuckDuckGo HTML endpoint.

    Uses requests + BeautifulSoup to parse DDG's HTML results page.
    No external pip package needed -- works with system python3-requests
    and python3-bs4 (both are .deb dependencies).
    """
    query = args.get("query", "").strip()
    if not query:
        return _err("query is required")
    max_results = int(args.get("max_results", 5))
    max_results = max(1, min(max_results, 10))
    results = []
    try:
        import requests as req
        from bs4 import BeautifulSoup

        results = _ddg_search(query, max_results)
        if not results:
            # Fallback: Brave Search (no API key needed for HTML results)
            results = _brave_search(query, max_results)
        return _ok({"results": results, "count": len(results)})
    except Exception as e:
        msg = str(e)
        if "ratelimit" in msg.lower() or "202" in msg:
            return _ok({"results": [], "count": 0, "note": "Rate limited, try again later"})
        return _err(f"Search failed: {e}")


# Security-relevant domains for link extraction in fetch_url.
# Only same-domain links and these domains are extracted when
# extract_links=True, to keep results focused on security content.
SECURITY_DOMAINS = frozenset({
    "nvd.nist.gov", "cve.org", "ubuntu.com", "debian.org",
    "access.redhat.com", "security.archlinux.org",
    "github.com", "gitlab.com", "codeberg.org",
    "exploit-db.com", "seclists.org",
    "thehackernews.com", "bleepingcomputer.com",
    "blog.talosintelligence.com", "googleprojectzero.blogspot.com",
    "cisa.gov", "www.cisa.gov",
    "kernel.org", "www.kernel.org",
    "linuxsecurity.com",
})


def _t_fetch_url(args: dict) -> dict:
    """Fetch and extract text from a URL. Uses trafilatura.

    SECURITY: Only http/https schemes are allowed. Internal/private/loopback
    addresses are blocked to prevent SSRF (Server-Side Request Forgery).
    Redirects are NOT followed to prevent DNS-rebinding bypasses.
    """
    url = args.get("url", "").strip()
    if not url:
        return _err("url is required")
    extract_links = args.get("extract_links", False)

    # Validate scheme
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return _err(f"Only http/https URLs are allowed (got: {parsed.scheme})")
    if not parsed.hostname:
        return _err("URL has no hostname")

    # Block internal/private/loopback addresses (SSRF protection)
    # Also prevent DNS-rebinding by pinning the resolved IP
    import ipaddress
    import socket
    try:
        # Resolve the hostname and check all resulting IPs
        addrs = socket.getaddrinfo(parsed.hostname, None)
        safe_ip = None
        for family, _, _, _, sockaddr in addrs:
            ip = ipaddress.ip_address(sockaddr[0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved):
                return _err(
                    f"URL resolves to a private/internal address ({ip}). "
                    "External URLs only."
                )
            if safe_ip is None:
                safe_ip = sockaddr[0]
    except socket.gaierror:
        return _err(f"Could not resolve hostname: {parsed.hostname}")

    try:
        import requests as req
        from bs4 import BeautifulSoup
        # Pin the resolved IP to prevent DNS-rebinding: connect to the
        # IP we validated, but send the original Host header.
        pinned_url = url.replace(parsed.hostname, safe_ip)
        r = req.get(
            pinned_url,
            timeout=20,
            headers={
                "User-Agent": "AutobahnDefender/2.1",
                "Host": parsed.hostname,
            },
            allow_redirects=False,
            # Don't verify TLS for IP-pinned connection (cert is for hostname)
            verify=False,
        )
        if r.is_redirect or r.is_permanent_redirect:
            return _err(f"Redirect blocked (SSRF protection): {r.headers.get('Location', '?')}")
        r.raise_for_status()

        # Extract text using BeautifulSoup (no trafilatura dependency)
        soup = BeautifulSoup(r.text, "html.parser")
        # Remove script, style, and other non-content tags
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()
        # Get title
        title = soup.find("title")
        title_text = title.get_text(strip=True) if title else ""
        # Get main text content
        text = soup.get_text(separator="\n", strip=True)
        # Collapse excessive blank lines
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        text = "\n".join(lines)

        # Optionally extract relevant links (same domain or security domains)
        links = []
        if extract_links:
            from urllib.parse import urljoin, urlparse as _up
            base_domain = parsed.hostname or ""
            for a_tag in soup.find_all("a", href=True):
                href = a_tag.get("href", "").strip()
                if not href or href.startswith("#") or href.startswith("mailto:"):
                    continue
                abs_url = urljoin(url, href)
                try:
                    link_host = _up(abs_url).hostname or ""
                except Exception:
                    continue
                if not link_host:
                    continue
                # Only include same-domain or security-domain links
                if (link_host == base_domain
                        or link_host.endswith("." + base_domain)
                        or any(link_host == d or link_host.endswith("." + d)
                               for d in SECURITY_DOMAINS)):
                    link_text = a_tag.get_text(strip=True)[:200]
                    links.append({"url": abs_url, "text": link_text})
                    if len(links) >= 10:
                        break

        result = {
            "url": url,
            "text": _truncate(_sanitize(text)),
            "title": title_text,
        }
        if extract_links:
            result["links"] = links
        return _ok(result)
    except Exception as e:
        return _err(f"Fetch failed: {e}")


def _t_rss_poll(args: dict) -> dict:
    """Poll RSS feeds for new articles. Defaults to all 8 hardcoded feeds."""
    from . import rss_feeds
    feed_id = args.get("feed_id")
    if feed_id:
        # Poll a single feed
        feed = next((f for f in rss_feeds.FEEDS if f["id"] == feed_id), None)
        if not feed:
            return _err(f"Unknown feed_id: {feed_id}")
        articles = rss_feeds.poll_feed(feed)
        return _ok({"articles": articles[:20], "count": len(articles)})
    # Poll all feeds
    summary = rss_feeds.poll_all_feeds()
    return _ok(summary)


def _t_cve_check(args: dict) -> dict:
    """Check CVEs for installed packages. Uses OSV.dev API (free, no key)."""
    packages = args.get("packages")  # list of {"name":..., "version":...}
    ecosystem = args.get("ecosystem", "Ubuntu:24.04")
    if not packages:
        # Auto-detect installed packages
        try:
            r = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\n"],
                capture_output=True, text=True, timeout=30,
            )
            packages = []
            for line in (r.stdout or "").splitlines():
                if "\t" in line:
                    name, ver = line.split("\t", 1)
                    packages.append({"name": name, "version": ver})
        except Exception as e:
            return _err(f"Failed to list packages: {e}")
    if not packages:
        return _err("No packages to check")
    # Detect ecosystem from /etc/os-release
    try:
        osr = Path("/etc/os-release").read_text()
        if "Ubuntu 24.04" in osr or "Ubuntu 24.10" in osr:
            ecosystem = "Ubuntu:24.04"
        elif "Ubuntu 22.04" in osr:
            ecosystem = "Ubuntu:22.04"
        elif "Debian 12" in osr:
            ecosystem = "Debian:12"
    except Exception:
        pass

    # Batch query OSV.dev (max 1000 per batch) with retry/backoff
    try:
        import requests as req
        import time as _time
        all_results = []
        for i in range(0, len(packages), 1000):
            batch = packages[i:i + 1000]
            queries = [
                {"package": {"name": p["name"], "ecosystem": ecosystem},
                 "version": p["version"]}
                for p in batch
            ]
            # Retry with exponential backoff on transient failures
            for attempt in range(3):
                try:
                    r = req.post(
                        "https://api.osv.dev/v1/querybatch",
                        json={"queries": queries},
                        timeout=30,
                    )
                    if r.status_code == 429:
                        _time.sleep(2 ** attempt)
                        continue
                    r.raise_for_status()
                    all_results.extend(r.json().get("results", []))
                    break
                except req.RequestException:
                    if attempt < 2:
                        _time.sleep(2 ** attempt)
                    else:
                        raise
        # Tally vulns
        vulns = []
        for pkg, res in zip(packages, all_results):
            for v in res.get("vulns", []):
                vulns.append({
                    "package": pkg["name"],
                    "version": pkg["version"],
                    "cve": v.get("id", ""),
                    "summary": v.get("summary", "")[:500],
                    "severity": [s.get("score", "") for s in v.get("severity", [])],
                })
        return _ok({
            "ecosystem": ecosystem,
            "packages_checked": len(packages),
            "vulnerabilities_found": len(vulns),
            "vulnerabilities": vulns[:200],  # cap for context size
        })
    except Exception as e:
        return _err(f"OSV.dev query failed: {e}")


# YARA rules cache (compiled once, reused across calls)
# Thread-safe via _yara_cache_lock
import threading as _threading
_yara_cache: dict = {}  # {"rules_dir": (mtime, compiled_rules)}
_yara_cache_lock = _threading.Lock()


def _t_yara_scan_file(args: dict) -> dict:
    """Scan a file with YARA rules. Reuses Autobahn Defender YARA.

    Compiled rules are cached and only recompiled when source .yar
    files change (detected via mtime). This avoids recompiling the
    1.7MB rules file on every call.
    """
    filepath = args.get("path", "").strip()
    if not filepath or not Path(filepath).is_file():
        return _err(f"File not found: {filepath}")
    try:
        import yara
        from scanner import RULES_DIR
        rules_dir = str(RULES_DIR)

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


def _t_file_info(args: dict) -> dict:
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


def _t_read_intel_db(args: dict) -> dict:
    """Read the intelligence database. Reads JSONL file from disk."""
    from . import intel_db
    name = args.get("database", "security_news")
    # Map friendly name to filename
    mapping = {
        "vulnerabilities": intel_db.VULNS_FILE,
        "zero_day_alerts": intel_db.ZERO_DAY_FILE,
        "zero_day": intel_db.ZERO_DAY_FILE,
        "security_news": intel_db.NEWS_FILE,
        "news": intel_db.NEWS_FILE,
        "resolved": intel_db.RESOLVED_FILE,
    }
    fname = mapping.get(name, name)
    limit = int(args.get("limit", 20))
    records = intel_db.read_all(fname)[:limit]
    return _ok({"database": fname, "count": len(records), "records": records})


def _t_write_intel_db(args: dict) -> dict:
    """Update the intelligence database. Append new records only.

    SECURITY: The 'replace' action is disabled to prevent a
    prompt-injected AI from wiping the user's entire intel database.
    Only 'append' is allowed -- the AI can add new items but cannot
    delete or overwrite existing ones.
    """
    from . import intel_db
    name = args.get("database", "security_news")
    mapping = {
        "vulnerabilities": intel_db.VULNS_FILE,
        "zero_day_alerts": intel_db.ZERO_DAY_FILE,
        "zero_day": intel_db.ZERO_DAY_FILE,
        "security_news": intel_db.NEWS_FILE,
        "news": intel_db.NEWS_FILE,
        "resolved": intel_db.RESOLVED_FILE,
    }
    fname = mapping.get(name, name)
    action = args.get("action", "append")
    records = args.get("records", [])
    if action == "append":
        intel_db.append_many(fname, records)
        return _ok({"action": "append", "added": len(records)})
    elif action == "replace":
        # SECURITY: 'replace' is disabled to prevent data wipe attacks
        return _err(
            "Replace action is disabled for security. "
            "Use append to add new records."
        )
    else:
        return _err(f"Unknown action: {action}")


def _t_whois_lookup(args: dict) -> dict:
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


def _t_investigate_process(args: dict) -> dict:
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

def _t_scan_persistence(_: dict) -> dict:
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


def _t_check_hosts(_: dict) -> dict:
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


def _t_analyze_script(args: dict) -> dict:
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


def _t_ssh_audit(_: dict) -> dict:
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


def _t_mac_status(_: dict) -> dict:
    """Mandatory Access Control (MAC) status. Checks AppArmor and SELinux
    enforcement status, profile counts, and fail2ban jail status.

    Adapted from Kudu's AppArmor/SELinux/fail2ban probes
    (MIT, AdventDevInc/kudu).
    """
    results = {}

    # --- AppArmor ---
    apparmor = {}
    if Path("/sys/kernel/security/apparmor").exists():
        apparmor["loaded"] = True
        # Try aa-status for details
        aa = _run(["aa-status"])
        if aa["status"] == "ok":
            output = aa["data"]["output"]
            apparmor["raw"] = _truncate(output, 3000)
            # Parse key numbers
            for line in output.splitlines():
                if "profiles are loaded" in line:
                    try:
                        apparmor["profiles_loaded"] = int(line.split()[0])
                    except (ValueError, IndexError):
                        pass
                if "profiles are in enforce mode" in line:
                    try:
                        apparmor["enforcing"] = int(line.split()[0])
                    except (ValueError, IndexError):
                        pass
                if "profiles are in complain mode" in line:
                    try:
                        apparmor["complain"] = int(line.split()[0])
                    except (ValueError, IndexError):
                        pass
        else:
            apparmor["note"] = "aa-status requires root for full details"
    else:
        apparmor["loaded"] = False

    results["apparmor"] = apparmor

    # --- SELinux ---
    selinux = {}
    selinux_cfg = Path("/etc/selinux/config")
    if selinux_cfg.exists():
        selinux["installed"] = True
        try:
            content = selinux_cfg.read_text(errors="replace")
            for line in content.splitlines():
                if line.strip().startswith("SELINUX="):
                    selinux["mode"] = line.split("=", 1)[1].strip().lower()
        except OSError:
            pass
        # getenforce
        ge = _run(["getenforce"])
        if ge["status"] == "ok":
            selinux["runtime_mode"] = ge["data"]["output"].strip()
    else:
        selinux["installed"] = False
    results["selinux"] = selinux

    # --- fail2ban ---
    fail2ban = {}
    f2b = _run(["fail2ban-client", "status"])
    if f2b["status"] == "ok":
        fail2ban["running"] = True
        output = f2b["data"]["output"]
        fail2ban["raw"] = _truncate(output, 2000)
        # Parse jail list
        for line in output.splitlines():
            if "Jail list:" in line:
                jails = line.split("Jail list:", 1)[1].strip()
                fail2ban["jails"] = [j.strip() for j in jails.split(",") if j.strip()]
        # Get banned count per jail (up to 5 jails)
        jail_bans = {}
        for jail in fail2ban.get("jails", [])[:5]:
            jr = _run(["fail2ban-client", "status", jail])
            if jr["status"] == "ok":
                for jline in jr["data"]["output"].splitlines():
                    if "Currently banned" in jline:
                        try:
                            count = int(jline.split(":")[-1].strip())
                            jail_bans[jail] = count
                        except (ValueError, IndexError):
                            pass
        if jail_bans:
            fail2ban["banned_per_jail"] = jail_bans
    else:
        fail2ban["running"] = False
        fail2ban["note"] = "fail2ban not running or not installed"
    results["fail2ban"] = fail2ban

    return _ok(results)


# ---------------------------------------------------------------------------
# Network Threat Monitor (Kudu-inspired, MIT, AdventDevInc/kudu)
# ---------------------------------------------------------------------------

# Suspicious destination ports commonly used by reverse shells, C2, and
# malware beacons. These are NOT normal service ports for most desktops.
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

# Known-bad CIDR ranges (bogon, malware C2, Tor exit note).
# These are ranges a desktop should almost never connect to.
KNOWN_BAD_CIDRS = [
    ipaddress.ip_network("10.0.0.0/8"),       # private — suspicious for outbound
    ipaddress.ip_network("172.16.0.0/12"),    # private — suspicious for outbound
    ipaddress.ip_network("192.168.0.0/16"),   # private — suspicious for outbound
    # Note: we flag these only for ESTABLISHED OUTBOUND connections to
    # unexpected private ranges (possible lateral movement).
]

# High-risk destination ports for C2 communication
HIGH_RISK_PORTS = frozenset({
    "4444", "1337", "31337", "6667", "9999",
})


def _t_network_threat_monitor(args: dict) -> dict:
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
                from . import AI_DATA_DIR
                cache_path = AI_DATA_DIR / "blacklist_cache.txt"
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


def _t_privacy_hardening(args: dict) -> dict:
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


def _t_service_manager(args: dict) -> dict:
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


def _t_dns_check(args: dict) -> dict:
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


def _t_disk_encryption(args: dict) -> dict:
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


def _t_screen_lock(args: dict) -> dict:
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


def _t_password_policy(args: dict) -> dict:
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


def _t_update_status(args: dict) -> dict:
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


def _t_event_log(args: dict) -> dict:
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


def _t_startup_manager(args: dict) -> dict:
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


def _t_knowledge_lookup(args: dict) -> dict:
    """Query the built-in knowledge base for Linux security guidance."""
    from .knowledge_base import lookup
    category = args.get("category", "")
    topic = args.get("topic", "")
    return lookup(category=category, topic=topic)


def _t_browser_cleaner(args: dict) -> dict:
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


def _t_cve_detail(args: dict) -> dict:
    """Get detailed information about a specific CVE.

    Queries OSV.dev first, falls back to NVD if not found.
    Returns summary, CVSS severity, affected packages, and references.
    """
    cve_id = args.get("cve_id", "").strip().upper()
    if not cve_id:
        return _err("cve_id is required")

    # Validate CVE ID format (CVE-YYYY-NNNNN+)
    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
        return _err(f"Invalid CVE ID format: {cve_id} (expected CVE-YYYY-NNNNN)")

    import requests as req

    # --- Try OSV.dev first ---
    try:
        r = req.get(
            f"https://api.osv.dev/v1/vulns/{cve_id}",
            timeout=15,
            headers={"User-Agent": "AutobahnDefender/2.1"},
        )
        if r.status_code == 200:
            data = r.json()
            summary = data.get("summary", "")
            if not summary:
                summary = data.get("details", "")[:500]

            # Parse severity (CVSS vector string)
            severity = None
            for sev in data.get("severity", []):
                cvss = sev.get("score", "")
                if cvss:
                    severity = cvss
                    break

            # Parse affected packages
            affected_packages = []
            for affected in data.get("affected", []):
                pkg = affected.get("package", {})
                if pkg:
                    affected_packages.append({
                        "name": pkg.get("name", ""),
                        "ecosystem": pkg.get("ecosystem", ""),
                    })

            # Parse references
            references = [ref.get("url", "") for ref in data.get("references", []) if ref.get("url")]

            return _ok({
                "cve_id": cve_id,
                "source": "OSV.dev",
                "summary": _truncate(summary, 2000),
                "severity": severity,
                "affected_packages": affected_packages[:50],
                "references": references[:20],
                "published_date": data.get("published", ""),
                "last_modified": data.get("modified", ""),
            })
    except req.RequestException:
        pass  # Fall through to NVD
    except Exception as e:
        log.debug("OSV.dev lookup failed for %s: %s", cve_id, e)

    # --- Fallback: NVD ---
    try:
        r = req.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
            timeout=15,
            headers={"User-Agent": "AutobahnDefender/2.1"},
        )
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return _err(f"CVE not found: {cve_id}")
            cve_data = vulns[0].get("cve", {})

            # Summary from descriptions
            descriptions = cve_data.get("descriptions", [])
            summary = ""
            for desc in descriptions:
                if desc.get("lang", "") == "en":
                    summary = desc.get("value", "")
                    break
            if not summary and descriptions:
                summary = descriptions[0].get("value", "")

            # CVSS severity (numeric baseScore)
            severity = None
            metrics = cve_data.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss_data = metrics[key][0].get("cvssData", {})
                    severity = cvss_data.get("baseScore")
                    break

            # Affected packages (parse CPE URIs)
            affected_packages = []
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe = cpe_match.get("criteria", "")
                        if cpe:
                            parts = cpe.split(":")
                            if len(parts) >= 5:
                                affected_packages.append({
                                    "name": parts[4],
                                    "ecosystem": parts[3] if len(parts) > 3 else "",
                                })

            # References
            references = [ref.get("url", "") for ref in cve_data.get("references", []) if ref.get("url")]

            return _ok({
                "cve_id": cve_id,
                "source": "NVD",
                "summary": _truncate(summary, 2000),
                "severity": severity,
                "affected_packages": affected_packages[:50],
                "references": references[:20],
                "published_date": cve_data.get("published", ""),
                "last_modified": cve_data.get("lastModified", ""),
            })
        elif r.status_code == 404:
            return _err(f"CVE not found: {cve_id}")
    except Exception as e:
        return _err(f"CVE lookup failed: {e}")

    return _err(f"CVE not found: {cve_id}")


def _t_vulnerability_scan(args: dict) -> dict:
    """Composite vulnerability scan. Combines installed packages, CVE check,
    and update status into a single structured response.

    Each sub-check has its own try/except so one failure doesn't break the scan.
    """
    # --- Installed packages ---
    packages_result = None
    try:
        packages_result = _t_installed_packages({})
    except Exception as e:
        packages_result = _err(f"installed_packages failed: {e}")

    # --- CVE check ---
    cve_result = None
    try:
        cve_result = _t_cve_check({})
    except Exception as e:
        cve_result = _err(f"cve_check failed: {e}")

    # --- Update status ---
    update_result = None
    try:
        update_result = _t_update_status({})
    except Exception as e:
        update_result = _err(f"update_status failed: {e}")

    # --- Aggregate ---
    # packages_checked: prefer CVE check count, fall back to dpkg count
    packages_checked = 0
    if cve_result and cve_result.get("status") == "ok":
        packages_checked = cve_result.get("data", {}).get("packages_checked", 0)
    if packages_checked == 0 and packages_result and packages_result.get("status") == "ok":
        output = packages_result.get("data", {}).get("output", "")
        if isinstance(output, str):
            packages_checked = sum(1 for l in output.splitlines() if l.startswith("ii "))

    vulnerabilities_found = 0
    top_vulnerabilities = []
    if cve_result and cve_result.get("status") == "ok":
        cve_data = cve_result.get("data", {})
        vulnerabilities_found = cve_data.get("vulnerabilities_found", 0)
        # Top 10 vulnerabilities (already in order from OSV response)
        top_vulnerabilities = cve_data.get("vulnerabilities", [])[:10]

    security_updates_available = 0
    regular_updates_available = 0
    pending_security_updates = []
    if update_result and update_result.get("status") == "ok":
        update_data = update_result.get("data", {})
        security_updates_available = update_data.get("security_updates", 0)
        upgradable_count = update_data.get("upgradable_count", 0)
        regular_updates_available = max(0, upgradable_count - security_updates_available)
        # Extract pending security update package names from findings
        for finding in update_data.get("findings", []):
            if "security" in finding.get("issue", "").lower():
                pending_security_updates = finding.get("packages", [])
                break

    combined = {
        "packages_checked": packages_checked,
        "vulnerabilities_found": vulnerabilities_found,
        "security_updates_available": security_updates_available,
        "regular_updates_available": regular_updates_available,
        "top_vulnerabilities": top_vulnerabilities,
        "pending_security_updates": pending_security_updates,
    }

    # Truncate combined output to prevent context overflow
    combined_text = json.dumps(combined, ensure_ascii=False)
    if len(combined_text) > 10000:
        for v in top_vulnerabilities:
            if isinstance(v, dict) and isinstance(v.get("summary"), str):
                v["summary"] = _truncate(v["summary"], 200)
        combined["top_vulnerabilities"] = combined["top_vulnerabilities"][:5]

    return _ok(combined)


def _t_network_security(args: dict) -> dict:
    """Composite network security scan. Combines network connections,
    threat monitor, DNS check, and firewall check.

    Each sub-check has its own try/except so one failure doesn't break the scan.
    """
    # --- Network connections ---
    connections_result = None
    try:
        connections_result = _t_network_connections({})
    except Exception as e:
        connections_result = _err(f"network_connections failed: {e}")

    # --- Network threat monitor ---
    threat_result = None
    try:
        threat_result = _t_network_threat_monitor({"download_blacklist": False})
    except Exception as e:
        threat_result = _err(f"network_threat_monitor failed: {e}")

    # --- DNS check ---
    dns_result = None
    try:
        dns_result = _t_dns_check({})
    except Exception as e:
        dns_result = _err(f"dns_check failed: {e}")

    # --- Firewall check ---
    firewall_result = None
    try:
        firewall_result = _t_firewall_check({})
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

    return _ok({
        "connections_summary": connections_summary,
        "threat_findings": threat_findings[:50],
        "dns_findings": dns_findings[:50],
        "firewall_status": firewall_status,
        "total_findings": total_findings,
        "critical_count": critical_count,
        "high_count": high_count,
    })


def _t_hardening_audit(args: dict) -> dict:
    """Composite hardening audit. Combines privacy hardening, SSH audit,
    MAC status, screen lock, password policy, and disk encryption checks.

    Each sub-check has its own try/except so one failure doesn't break the audit.
    """
    checks = {}

    # --- Privacy hardening ---
    try:
        checks["privacy_hardening"] = _t_privacy_hardening({})
    except Exception as e:
        checks["privacy_hardening"] = _err(f"privacy_hardening failed: {e}")

    # --- SSH audit ---
    try:
        checks["ssh_audit"] = _t_ssh_audit({})
    except Exception as e:
        checks["ssh_audit"] = _err(f"ssh_audit failed: {e}")

    # --- MAC status ---
    try:
        checks["mac_status"] = _t_mac_status({})
    except Exception as e:
        checks["mac_status"] = _err(f"mac_status failed: {e}")

    # --- Screen lock ---
    try:
        checks["screen_lock"] = _t_screen_lock({})
    except Exception as e:
        checks["screen_lock"] = _err(f"screen_lock failed: {e}")

    # --- Password policy ---
    try:
        checks["password_policy"] = _t_password_policy({})
    except Exception as e:
        checks["password_policy"] = _err(f"password_policy failed: {e}")

    # --- Disk encryption ---
    try:
        checks["disk_encryption"] = _t_disk_encryption({})
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

    return _ok({
        "total_checks": total_checks,
        "total_findings": total_findings,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "summaries": summaries,
    })


# ---------------------------------------------------------------------------
# Tool registry -- maps name -> {schema + implementation}
# ---------------------------------------------------------------------------

def _tool(name: str, desc: str, params: dict, impl: Callable) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": desc,
            "parameters": params,
        },
        "_impl": impl,
    }


TOOL_REGISTRY: list[dict] = [
    _tool(
        "system_audit",
        "Full system security audit. Runs 5-10 commands (firewall, AppArmor, "
        "processes, ports, updates, SUID, SSH, kernel, auth log) and returns "
        "combined JSON. Use this for comprehensive security analysis.",
        {"type": "object", "properties": {}, "required": []},
        _t_system_audit,
    ),
    _tool(
        "firewall_check",
        "Get current firewall rules from iptables, nftables, and ufw.",
        {"type": "object", "properties": {}, "required": []},
        _t_firewall_check,
    ),
    _tool(
        "apparmor_status",
        "Get AppArmor status. Runs aa-status, checks complain vs enforce mode.",
        {"type": "object", "properties": {}, "required": []},
        _t_apparmor_status,
    ),
    _tool(
        "running_processes",
        "Get running processes with full command lines (ps auxf sorted by CPU).",
        {"type": "object", "properties": {}, "required": []},
        _t_running_processes,
    ),
    _tool(
        "installed_packages",
        "Get installed packages (dpkg -l).",
        {"type": "object", "properties": {}, "required": []},
        _t_installed_packages,
    ),
    _tool(
        "pending_updates",
        "Get pending system updates (apt list --upgradable).",
        {"type": "object", "properties": {}, "required": []},
        _t_pending_updates,
    ),
    _tool(
        "network_connections",
        "Get network connections: listening ports (ss -tulpn) and established "
        "connections (ss -tup).",
        {"type": "object", "properties": {}, "required": []},
        _t_network_connections,
    ),
    _tool(
        "ssh_config_check",
        "Read /etc/ssh/sshd_config for hardening analysis.",
        {"type": "object", "properties": {}, "required": []},
        _t_ssh_config_check,
    ),
    _tool(
        "suid_binaries",
        "Find all SUID/SGID binaries on the system.",
        {"type": "object", "properties": {}, "required": []},
        _t_suid_binaries,
    ),
    _tool(
        "startup_items",
        "List startup/persistence items: systemd services, cron jobs, "
        "systemd timers, autostart entries.",
        {"type": "object", "properties": {}, "required": []},
        _t_startup_items,
    ),
    _tool(
        "kernel_info",
        "Get kernel security info: uname, sysctl kernel, KASLR/SMEP/SMAP boot params.",
        {"type": "object", "properties": {}, "required": []},
        _t_kernel_info,
    ),
    _tool(
        "auth_log_check",
        "Check auth logs for brute force attempts, failed sudo, unusual logins.",
        {"type": "object", "properties": {}, "required": []},
        _t_auth_log_check,
    ),
    _tool(
        "web_search",
        "Search the web via DuckDuckGo (free, no API key). Returns titles, "
        "URLs, and snippets. Use for researching hashes, filenames, IPs, "
        "CVEs, or malware associations.",
        {"type": "object",
         "properties": {
             "query": {"type": "string", "description": "Search query"},
             "max_results": {"type": "integer", "description": "Max results (1-10)", "default": 5},
         },
         "required": ["query"]},
        _t_web_search,
    ),
    _tool(
        "fetch_url",
        "Fetch and extract main text content from a URL. Uses trafilatura.",
        {"type": "object",
         "properties": {
             "url": {"type": "string", "description": "URL to fetch"},
             "extract_links": {"type": "boolean", "default": False,
                 "description": "Extract up to 10 security-relevant links from the page (same domain or known security domains)"},
         },
         "required": ["url"]},
        _t_fetch_url,
    ),
    _tool(
        "rss_poll",
        "Poll RSS feeds for new Linux security articles. Pass feed_id to poll "
        "a single feed, or omit to poll all 8 hardcoded feeds.",
        {"type": "object",
         "properties": {
             "feed_id": {"type": "string", "description": "Optional: specific feed ID to poll"},
         },
         "required": []},
        _t_rss_poll,
    ),
    _tool(
        "cve_check",
        "Check CVEs for installed packages using the OSV.dev API (free, no key). "
        "Pass packages=[{name, version}] to check specific packages, or omit to "
        "auto-detect all installed packages.",
        {"type": "object",
         "properties": {
             "packages": {"type": "array", "items": {"type": "object", "properties": {"name": {"type": "string"}, "version": {"type": "string"}}}},
             "ecosystem": {"type": "string", "description": "e.g. Ubuntu:24.04, Debian:12"},
         },
         "required": []},
        _t_cve_check,
    ),
    _tool(
        "yara_scan_file",
        "Scan a file with Autobahn Defender's YARA rules. Returns matched rule names.",
        {"type": "object",
         "properties": {"path": {"type": "string", "description": "Absolute path to the file"}},
         "required": ["path"]},
        _t_yara_scan_file,
    ),
    _tool(
        "file_info",
        "Get file metadata: stat, file type, sha256 hash, entropy. Entropy > 7.5 "
        "suggests packed/encrypted content.",
        {"type": "object",
         "properties": {"path": {"type": "string", "description": "Absolute path"}},
         "required": ["path"]},
        _t_file_info,
    ),
    _tool(
        "read_intel_db",
        "Read the AI intelligence database. Databases: vulnerabilities, "
        "zero_day_alerts, security_news, resolved.",
        {"type": "object",
         "properties": {
             "database": {"type": "string", "description": "DB name", "enum": ["vulnerabilities", "zero_day_alerts", "security_news", "resolved"]},
             "limit": {"type": "integer", "default": 20},
         },
         "required": ["database"]},
        _t_read_intel_db,
    ),
    _tool(
        "write_intel_db",
        "Update the intelligence database. Append new records or replace all. "
        "The AI manages the lifecycle: adds items, marks resolved, prunes old.",
        {"type": "object",
         "properties": {
             "database": {"type": "string", "enum": ["vulnerabilities", "zero_day_alerts", "security_news", "resolved"]},
             "action": {"type": "string", "enum": ["append", "replace"], "default": "append"},
             "records": {"type": "array", "items": {"type": "object"}},
         },
         "required": ["database", "records"]},
        _t_write_intel_db,
    ),
    _tool(
        "whois_lookup",
        "WHOIS lookup for an IP address or domain name.",
        {"type": "object",
         "properties": {"target": {"type": "string", "description": "IP or domain"}},
         "required": ["target"]},
        _t_whois_lookup,
    ),
    _tool(
        "investigate_process",
        "Collect full info about a running process by PID: ps, cwd, exe, open "
        "files, network connections, binary sha256.",
        {"type": "object",
         "properties": {"pid": {"type": "integer", "description": "Process ID"}},
         "required": ["pid"]},
        _t_investigate_process,
    ),
    _tool(
        "scan_persistence",
        "Scan for malicious persistence mechanisms: crontab entries and systemd "
        "services that use download-and-execute, /tmp execution, or base64-decode-"
        "and-run patterns. No arguments needed -- scans the current user's "
        "crontab and systemd services automatically.",
        {"type": "object", "properties": {}, "required": []},
        _t_scan_persistence,
    ),
    _tool(
        "check_hosts",
        "Check /etc/hosts for tampering. Flags redirections of major domains "
        "(Google, PayPal, banks, etc.) to non-safe IPs. No arguments needed.",
        {"type": "object", "properties": {}, "required": []},
        _t_check_hosts,
    ),
    _tool(
        "analyze_script",
        "Analyze a script file for malicious behavior patterns: encoded "
        "PowerShell, download cradles, AMSI bypass, base64-embedded PE headers, "
        "mimikatz references, reflective loading. Requires >=2 indicators to "
        "flag (reduces FPs), except base64-PE which is sufficient alone.",
        {"type": "object",
         "properties": {"path": {"type": "string", "description": "Absolute path to script file"}},
         "required": ["path"]},
        _t_analyze_script,
    ),
    _tool(
        "ssh_audit",
        "Full SSH hardening audit. Parses sshd_config + all drop-in configs with "
        "Match-block awareness. Checks PermitRootLogin, PasswordAuthentication, "
        "weak ciphers/MACs, missing timeout settings, protocol version. "
        "No arguments needed.",
        {"type": "object", "properties": {}, "required": []},
        _t_ssh_audit,
    ),
    _tool(
        "mac_status",
        "Mandatory Access Control status: AppArmor enforcement, SELinux mode, "
        "and fail2ban jail status with banned IP counts. No arguments needed.",
        {"type": "object", "properties": {}, "required": []},
        _t_mac_status,
    ),
    _tool(
        "network_threat_monitor",
        "Live network threat monitor. Parses active connections (ss), flags "
        "connections to known backdoor/C2 ports (4444, 31337, etc.), detects "
        "outbound connections to private ranges (lateral movement), and optionally "
        "downloads the Emerging Threats compromised-IP blacklist for matching. "
        "Pass download_blacklist=true to fetch the threat feed (requires internet).",
        {"type": "object",
         "properties": {
             "download_blacklist": {"type": "boolean", "default": False,
                 "description": "Download Emerging Threats compromised IP list and match against active connections"},
         },
         "required": []},
        _t_network_threat_monitor,
    ),

    # --- v2.1 tools ---

    _tool(
        "privacy_hardening",
        "Check kernel and network privacy/security hardening settings via sysctl. "
        "Checks 20 settings: SYN flood, ICMP redirects, source routing, ASLR, ptrace, "
        "core dumps, protected links. Returns weak settings with fix commands.",
        {"type": "object", "properties": {}, "required": []},
        _t_privacy_hardening,
    ),
    _tool(
        "service_manager",
        "List systemd services, check status, or get security posture. "
        "Action 'list' shows all running services and flags risky ones. "
        "Action 'status' needs service name. Action 'security' gets systemd-analyze security report.",
        {"type": "object",
         "properties": {
             "action": {"type": "string", "enum": ["list", "status", "security"], "default": "list"},
             "service": {"type": "string", "description": "Service name (for status/security actions)"},
         },
         "required": []},
        _t_service_manager,
    ),
    _tool(
        "dns_check",
        "Check DNS configuration for security: resolv.conf, DNSSEC status, "
        "/etc/hosts for suspicious redirects of major websites.",
        {"type": "object", "properties": {}, "required": []},
        _t_dns_check,
    ),
    _tool(
        "disk_encryption",
        "Check disk encryption status. Identifies LUKS-encrypted and unencrypted "
        "filesystems, and checks if root is encrypted.",
        {"type": "object", "properties": {}, "required": []},
        _t_disk_encryption,
    ),
    _tool(
        "screen_lock",
        "Check screen lock settings for GNOME, XFCE, and other desktop environments. "
        "Verifies idle delay and lock-enabled status.",
        {"type": "object", "properties": {}, "required": []},
        _t_screen_lock,
    ),
    _tool(
        "password_policy",
        "Check password policy: PAM password quality, password aging in login.defs, "
        "password history/reuse prevention, and empty passwords in /etc/shadow.",
        {"type": "object", "properties": {}, "required": []},
        _t_password_policy,
    ),
    _tool(
        "update_status",
        "Check for available security updates and regular updates via apt. "
        "Also checks last apt update timestamp and unattended-upgrades status.",
        {"type": "object", "properties": {}, "required": []},
        _t_update_status,
    ),
    _tool(
        "event_log",
        "Check system auth log and journal for security events: failed logins, "
        "SSH brute force attempts, sudo usage, invalid users. Extracts attacker IPs.",
        {"type": "object",
         "properties": {
             "max_lines": {"type": "integer", "default": 50, "max": 200},
         },
         "required": []},
        _t_event_log,
    ),
    _tool(
        "startup_manager",
        "List and analyze startup programs: systemd services, autostart .desktop files, "
        "user crontab, system cron. Flags suspicious entries using curl/wget/base64/tmp paths.",
        {"type": "object", "properties": {}, "required": []},
        _t_startup_manager,
    ),
    _tool(
        "browser_cleaner",
        "Check browser privacy and security settings for Firefox and Chrome/Chromium/Brave. "
        "Checks tracking protection, cookies, telemetry, extensions, cache size, safe browsing.",
        {"type": "object", "properties": {}, "required": []},
        _t_browser_cleaner,
    ),

    # --- v2.1 knowledge base ---

    _tool(
        "knowledge_lookup",
        "Query the built-in Linux security knowledge base for best practices, "
        "remediation commands, and zero-day response playbooks. Call this BEFORE "
        "writing your final report to ensure your recommendations match established "
        "best practices. Categories: hardening, vulnerabilities, zero_day, network, privacy. "
        "Pass a topic to narrow results (e.g. topic='SSH' or topic='Firewall').",
        {"type": "object",
         "properties": {
             "category": {"type": "string",
                 "description": "Category to look up: hardening, vulnerabilities, zero_day, network, privacy. Empty = all categories summary."},
             "topic": {"type": "string",
                 "description": "Specific topic to look up within the category (e.g. 'SSH', 'Firewall', 'Kernel'). Empty = all topics in category."},
         },
         "required": []},
        _t_knowledge_lookup,
    ),

    # --- Composite tools ---

    _tool(
        "cve_detail",
        "Get detailed information about a specific CVE. Queries OSV.dev first, "
        "falls back to NVD. Returns summary, CVSS severity, affected packages, "
        "and references.",
        {"type": "object",
         "properties": {
             "cve_id": {"type": "string", "description": "CVE ID (format: CVE-YYYY-NNNNN)"},
         },
         "required": ["cve_id"]},
        _t_cve_detail,
    ),
    _tool(
        "vulnerability_scan",
        "Composite vulnerability scan. Combines installed packages, CVE check, "
        "and update status into a single response with top vulnerabilities and "
        "pending security updates. No arguments needed.",
        {"type": "object", "properties": {}, "required": []},
        _t_vulnerability_scan,
    ),
    _tool(
        "network_security",
        "Composite network security scan. Combines network connections, threat "
        "monitor, DNS check, and firewall check. Returns aggregated findings with "
        "severity counts. No arguments needed.",
        {"type": "object", "properties": {}, "required": []},
        _t_network_security,
    ),
    _tool(
        "hardening_audit",
        "Composite hardening audit. Combines privacy hardening, SSH audit, MAC "
        "status, screen lock, password policy, and disk encryption checks. "
        "Returns aggregated findings with severity counts. No arguments needed.",
        {"type": "object", "properties": {}, "required": []},
        _t_hardening_audit,
    ),
]


TASK_TOOLS = {
    "system_audit": ["system_audit", "firewall_check", "apparmor_status", "running_processes",
                     "installed_packages", "pending_updates", "network_connections",
                     "ssh_config_check", "suid_binaries", "startup_items", "kernel_info",
                     "auth_log_check", "cve_check", "write_intel_db", "read_intel_db",
                     "scan_persistence", "check_hosts", "mac_status",
                     "network_threat_monitor", "knowledge_lookup"],
    "firewall_check": ["firewall_check", "knowledge_lookup"],
    "apparmor_status": ["apparmor_status"],
    "running_processes": ["running_processes", "investigate_process"],
    "installed_packages": ["installed_packages", "cve_check", "web_search"],
    "pending_updates": ["pending_updates", "cve_check"],
    "network_connections": ["network_connections", "web_search", "whois_lookup",
                            "network_threat_monitor", "knowledge_lookup"],
    "network_threat_monitor": ["network_threat_monitor", "whois_lookup", "web_search"],
    "ssh_config_check": ["ssh_config_check", "knowledge_lookup"],
    "security_news": ["rss_poll", "read_intel_db", "write_intel_db", "fetch_url",
                     "cve_detail", "web_search", "knowledge_lookup"],
    "cve_matching": ["cve_check", "installed_packages", "read_intel_db", "write_intel_db"],
    "zero_day_watch": ["rss_poll", "read_intel_db", "fetch_url", "web_search",
                       "kernel_info", "installed_packages", "knowledge_lookup"],
    "threat_intel": ["read_intel_db", "rss_poll"],
    "investigate_file": ["file_info", "yara_scan_file", "analyze_script",
                         "web_search", "fetch_url"],
    "investigate_ip": ["whois_lookup", "web_search", "fetch_url"],
    "investigate_process": ["investigate_process", "web_search"],
    "generate_report": ["system_audit", "firewall_check", "running_processes",
                        "installed_packages", "pending_updates", "network_connections",
                        "ssh_config_check", "kernel_info", "read_intel_db",
                        "scan_persistence", "check_hosts", "mac_status",
                        "network_threat_monitor", "knowledge_lookup"],
    "view_history": ["read_intel_db"],
    # New task mappings
    "persistence_scan": ["scan_persistence", "web_search"],
    "hosts_check": ["check_hosts"],
    "script_analysis": ["analyze_script", "yara_scan_file", "file_info", "web_search"],
    "ssh_hardening": ["ssh_audit", "knowledge_lookup"],
    "mac_audit": ["mac_status", "apparmor_status"],
    # v2.1 task mappings
    "privacy_hardening": ["privacy_hardening", "knowledge_lookup"],
    "service_audit": ["service_manager", "network_connections", "knowledge_lookup"],
    "dns_audit": ["dns_check", "knowledge_lookup"],
    "disk_encryption_check": ["disk_encryption", "knowledge_lookup"],
    "screen_lock_check": ["screen_lock", "knowledge_lookup"],
    "password_audit": ["password_policy", "knowledge_lookup"],
    "update_check": ["update_status", "cve_check", "knowledge_lookup"],
    "event_log_check": ["event_log"],
    "startup_audit": ["startup_manager", "scan_persistence"],
    "browser_audit": ["browser_cleaner", "knowledge_lookup"],
    "auto_monitor": ["rss_poll", "read_intel_db", "installed_packages",
                     "cve_check", "web_search", "write_intel_db",
                     "update_status", "network_threat_monitor", "knowledge_lookup"],
    # Composite tool task mappings
    "full_audit": ["system_audit", "scan_persistence", "check_hosts",
                   "network_security", "hardening_audit", "vulnerability_scan",
                   "knowledge_lookup"],
    "vuln_check": ["vulnerability_scan", "cve_detail", "read_intel_db",
                   "write_intel_db", "knowledge_lookup"],
    "network_scan": ["network_security", "whois_lookup", "web_search",
                     "knowledge_lookup"],
    "hardening_audit": ["hardening_audit", "knowledge_lookup"],
    # v2.1 chat mode -- user can ask anything; AI has access to all tools
    "chat": ["system_audit", "firewall_check", "apparmor_status", "running_processes",
             "installed_packages", "pending_updates", "network_connections",
             "ssh_config_check", "suid_binaries", "startup_items", "kernel_info",
             "auth_log_check", "cve_check", "write_intel_db", "read_intel_db",
             "scan_persistence", "check_hosts", "mac_status",
             "network_threat_monitor", "web_search", "fetch_url", "whois_lookup",
             "investigate_process", "file_info", "yara_scan_file",
             "privacy_hardening", "service_manager", "dns_check", "disk_encryption",
             "screen_lock", "password_policy", "update_status", "event_log",
             "startup_manager", "browser_cleaner", "knowledge_lookup",
             "rss_poll", "analyze_script",
             "cve_detail", "vulnerability_scan", "network_security", "hardening_audit"],
}


def get_tools_for_api() -> list[dict]:
    """Return ALL tool definitions (for backward compatibility).
    Prefer get_tools_for_task() to reduce context size."""
    out = []
    for t in TOOL_REGISTRY:
        out.append({"type": t["type"], "function": t["function"]})
    return out


def get_tools_for_task(task_id: str) -> list[dict]:
    """Return only the tools relevant for a specific task.

    This reduces the context size significantly (from ~1600 tokens for
    all 22 tools to ~200-600 tokens for a task-specific subset), which
    speeds up prompt processing on CPU.
    """
    relevant_names = TASK_TOOLS.get(task_id, [])
    out = []
    for t in TOOL_REGISTRY:
        if t["function"]["name"] in relevant_names:
            out.append({"type": t["type"], "function": t["function"]})
    return out


def get_impl(name: str) -> Callable | None:
    """Return the Python callable for a tool name, or None if not found."""
    for t in TOOL_REGISTRY:
        if t["function"]["name"] == name:
            return t["_impl"]
    return None


def execute_tool(name: str, arguments: dict) -> dict:
    """Validate and execute a tool by name. Returns the tool's result dict."""
    impl = get_impl(name)
    if impl is None:
        return _err(f"Unknown tool: {name}")
    try:
        result = impl(arguments or {})
        # Final truncation of the serialized result
        text = json.dumps(result, ensure_ascii=False)
        if len(text) > MAX_RESULT_CHARS * 1.5:
            result = _ok({"truncated": True, "preview": text[:MAX_RESULT_CHARS]})
        return result
    except Exception as e:
        log.exception("Tool %s raised", name)
        return _err(f"Tool {name} crashed: {e}")