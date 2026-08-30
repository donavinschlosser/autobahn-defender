"""
Autobahn Defender v2.0 -- Hardcoded Linux security RSS feeds (14 curated).

14 free CVE- and Linux-security-focused feeds plus the CISA Known Exploited
Vulnerabilities (KEV) catalog (fetched as JSON from a community mirror, since
CISA killed the official RSS feed in May 2025). No API keys required.

Feed selection criteria:
  - Must be free (no API key)
  - Must have RSS/Atom output (or, for CISA KEV, a stable JSON mirror)
  - Must cover CVEs, zero-days, or Linux security
  - Must be actively maintained (every URL verified reachable Aug 2026)

The feed list is HARDCODED and NOT configurable by the user.
The application (not the AI) polls these feeds every 24 hours automatically
and stores new articles in security_news.jsonl. Users browse them in the
Security News tab; the AI can also read stored articles to determine whether
a CVE affects installed packages, whether it is a zero-day, whether a patch
is available, and what action is needed.

v2.0 changes:
  - Removed dead us-cert/CISA RSS feed (CISA killed official RSS May 2025)
  - Removed Kaspersky Securelist and SecurityWeek (less Linux-CVE specific)
  - Added NVD, Arch Linux, Red Hat, LinuxSecurity.com, GitHub Security
  - Added CISA KEV JSON polling via community mirror (poll_cisa_kev)
  - Poll interval changed from 6 hours to 24 hours (daily)

Categories:
  - Official distro security (Ubuntu, Debian, Arch, Red Hat) -- direct CVE patches
  - National vulnerability databases (NVD) -- authoritative CVE records
  - Linux advisory aggregators (LinuxSecurity.com)
  - Vulnerability disclosures (OSS-Security, Full Disclosure, Exploit-DB)
  - Security research (Project Zero, Talos)
  - Security news (The Hacker News, Bleeping Computer)
  - Supply chain / platform (GitHub Security)
  - Government exploitation catalog (CISA KEV)
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

import feedparser

from . import intel_db

log = logging.getLogger(__name__)

# Poll interval in seconds (24 hours / daily). HARDCODED, not configurable.
POLL_INTERVAL_SECONDS = 24 * 60 * 60

# Hardcoded feed list. NOT configurable by the user.
# 14 curated feeds -- verified working August 2026.
FEEDS = [
    # --- Official distro security advisories (CVE patches) ---

    {
        "id": "ubuntu_usn",
        "name": "Ubuntu Security Notices",
        "url": "https://ubuntu.com/security/notices/rss.xml",
        "covers": "Official Ubuntu CVEs patched in packages, severity ratings",
    },
    {
        "id": "debian_dsa",
        "name": "Debian Security Advisories",
        "url": "https://www.debian.org/security/dsa.rdf",
        "covers": "Official Debian security advisories, CVEs patched in stable. RSS 1.0/RDF format (feedparser handles natively).",
    },

    # --- National vulnerability database ---

    {
        "id": "nvd_recent",
        "name": "NVD Recent CVEs (via CVEFeed.io)",
        "url": "https://cvefeed.io/rssfeed/latest.xml",
        "covers": "Latest published CVE records with descriptions and CVSS context. NVD's own RSS feed was retired in April 2026 when NIST changed NVD operations; this community CVE feed mirrors the same NVD/CVE data as RSS 2.0.",
    },

    # --- More official distro security advisories ---

    {
        "id": "arch_advisory",
        "name": "Arch Linux Security Advisories",
        "url": "https://security.archlinux.org/advisory/feed.atom",
        "covers": "Arch Linux security advisories (ASA), package CVE fixes, affected versions and severity. Atom format (feedparser handles natively). Publication has been sparse since mid-2025 but the feed remains live.",
    },
    {
        "id": "redhat_rhsa",
        "name": "Red Hat Security Advisories",
        "url": "https://security.access.redhat.com/data/meta/v1/rhsa.rss",
        "covers": "Red Hat security advisories (RHSA) released in the last three days, CVE fixes for RHEL packages, severity ratings and affected products. Official RHSA RSS feed from the Red Hat Security Data portal.",
    },

    # --- Linux advisory aggregator ---

    {
        "id": "linuxsecurity_advisories",
        "name": "LinuxSecurity.com Advisories",
        "url": "https://linuxsecurity.com/linuxsecurity_advisories.xml",
        "covers": "Aggregated Linux distribution security advisories across distros (Debian, Ubuntu, Fedora, openSUSE, SUSE, Rocky, Oracle, Slackware, Mageia, Gentoo), CVE mappings and patch notices. RSS 2.0.",
    },

    # --- Vulnerability disclosure feeds ---

    {
        "id": "oss_sec",
        "name": "OSS-Security (seclists.org)",
        "url": "https://seclists.org/rss/oss-sec.rss",
        "covers": "Open source security vulnerability disclosures, CVE assignments, upstream patches",
    },
    {
        "id": "full_disclosure",
        "name": "Full Disclosure (seclists.org)",
        "url": "https://seclists.org/rss/fulldisclosure.rss",
        "covers": "Raw vulnerability disclosures, 0-day reports, exploit details from security researchers",
    },
    {
        "id": "exploit_db",
        "name": "Exploit-DB",
        "url": "https://www.exploit-db.com/rss.xml",
        "covers": "Public exploit code releases, proof-of-concept code for CVEs, zero-day exploits",
    },

    # --- Security research labs (zero-day analysis, deep technical) ---

    {
        "id": "project_zero",
        "name": "Google Project Zero",
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default",
        "covers": "Zero-day vulnerability research, exploit chain analysis, browser/kernel zero-days",
    },
    {
        "id": "talos",
        "name": "Cisco Talos Intelligence",
        "url": "https://blog.talosintelligence.com/rss/",
        "covers": "Threat intelligence, malware analysis, vulnerability research, exploit detection",
    },

    # --- Security news (broad coverage, AI filters for Linux relevance) ---

    {
        "id": "thn_linux",
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "covers": "Major cybersecurity news, CVE announcements, zero-day reports, breach notifications",
    },
    {
        "id": "bleepingcomputer",
        "name": "Bleeping Computer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "covers": "Security news, malware outbreaks, vulnerability disclosures, Linux security coverage",
    },

    # --- Supply chain / platform security ---

    {
        "id": "github_security",
        "name": "GitHub Security Advisories",
        "url": "https://github.blog/security.atom",
        "covers": "GitHub Security blog: GHSA-reviewed security advisories, dependency/CVE vulnerability disclosures, coordinated disclosures, and product security announcements. GitHub's dedicated /security/advisories.atom endpoint was removed; the GitHub Blog security category feed (Atom) is the working replacement.",
    },
]

# Keywords that elevate an article to zero-day watch status.
ZERO_DAY_KEYWORDS = (
    "zero-day", "0-day", "zero day", "actively exploited",
    "emergency patch", "in-the-wild", "in the wild",
    "CVE-2025", "CVE-2026", "critical vulnerability",
    "urgent patch", "unpatched",
    "RCE", "remote code execution",
    "privilege escalation",
    "kernel exploit", "kernel vulnerability",
    "backdoor", "supply chain attack",
    "actively exploited vulnerability",
)

# CISA Known Exploited Vulnerabilities catalog -- community JSON mirror.
# CISA killed the official RSS feed in May 2025; this mirror keeps the KEV
# catalog available as a JSON Feed (https://jsonfeed.org) that we parse
# directly. NOTE: the file lives under output/CISA-KEV.json in the repo,
# not at the root -- a plain kev.json at root returns 404.
CISA_KEV_URL = (
    "https://raw.githubusercontent.com/CryptoGenNepal/"
    "CVE-KEV-RSS/main/output/CISA-KEV.json"
)


def poll_feed(feed: dict[str, str]) -> list[dict[str, Any]]:
    """Fetch and parse a single RSS feed. Returns list of article dicts.

    Uses requests.get with a timeout first, then feedparser on the
    downloaded content, to prevent a slow/hung feed from blocking
    the entire polling cycle.
    """
    import requests as req
    try:
        r = req.get(
            feed["url"],
            timeout=15,
            headers={"User-Agent": "AutobahnDefender/2.0 RSS Poller"},
        )
        r.raise_for_status()
        parsed = feedparser.parse(r.content)
    except Exception as e:
        log.warning("Failed to fetch feed %s: %s", feed["name"], e)
        return []

    articles = []
    now_iso = datetime.now(timezone.utc).isoformat()
    for entry in parsed.entries:
        url = getattr(entry, "link", "") or getattr(entry, "id", "")
        title = getattr(entry, "title", "") or "(untitled)"
        summary = getattr(entry, "summary", "") or getattr(entry, "description", "")
        published = getattr(entry, "published", "") or getattr(entry, "updated", "") or ""
        articles.append({
            "id": url,
            "url": url,
            "title": title,
            "summary": summary[:2000],  # truncate to keep DB small
            "published": published,
            "source": feed["name"],
            "source_id": feed["id"],
            "seen_at": now_iso,
        })
    return articles


def poll_cisa_kev() -> list[dict[str, Any]]:
    """Fetch the CISA Known Exploited Vulnerabilities (KEV) catalog.

    CISA discontinued the official RSS feed in May 2025. This function pulls
    the KEV catalog as JSON from a community mirror, parses it, and returns
    a list of article dicts with source "CISA KEV" -- one entry per CVE.

    The mirror publishes the catalog as a JSON Feed (https://jsonfeed.org):
    a top-level dict with an "items" list where each item has
    {id, url, title, content_text, date_published}. The CVE ID and a human
    description are embedded in the title (e.g. "CVE-2026-20349: <desc>") and
    the id/url point at the NVD detail page. We also defensively handle the
    raw CISA KEV schema ({"vulnerabilities": [{cveID, ...}]}) in case the
    mirror layout changes back.

    Returns an empty list on fetch/parse failure (logged at WARNING).
    """
    import requests as req
    try:
        r = req.get(
            CISA_KEV_URL,
            timeout=30,
            headers={"User-Agent": "AutobahnDefender/2.0 KEV Poller"},
        )
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        log.warning("Failed to fetch CISA KEV catalog: %s", e)
        return []

    if not isinstance(data, dict):
        log.warning("CISA KEV JSON has unexpected top-level type: %s", type(data).__name__)
        return []

    # --- Pick the list of entries: JSON Feed "items" or raw CISA
    # "vulnerabilities". Also tolerate a bare top-level list. ---
    if isinstance(data, list):
        entries = data
    else:
        entries = data.get("items")
        if entries is None:
            entries = data.get("vulnerabilities") or data.get("vulns")
    if not isinstance(entries, list):
        log.warning("CISA KEV JSON has no usable items/vulnerabilities list")
        return []

    now_iso = datetime.now(timezone.utc).isoformat()
    articles: list[dict[str, Any]] = []
    for v in entries:
        if not isinstance(v, dict):
            continue

        # --- JSON Feed schema (the mirror's actual shape) ---
        if "title" in v and ("content_text" in v or "url" in v or "id" in v):
            item_url = v.get("url") or v.get("id") or ""
            title = v.get("title") or ""
            content = v.get("content_text") or v.get("content_html") or v.get("summary") or ""
            published = v.get("date_published") or v.get("date_modified") or ""

            # Extract the CVE ID from the title (e.g. "CVE-2026-20349: ...")
            # or from the id/url if absent.
            cve_id = ""
            for src in (title, item_url, v.get("id", "")):
                m = re.search(r"CVE-\d{4}-\d{4,7}", src or "")
                if m:
                    cve_id = m.group(0)
                    break

            if not cve_id:
                # Not a CVE-tagged entry; skip silently.
                continue

            # title is "CVE-XXXX: <human description>"; use it as-is so the
            # Security News tab shows the CVE plus a one-line description.
            articles.append({
                "id": f"cisa_kev:{cve_id}",
                "url": item_url or f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "title": title,
                "summary": content[:2000],
                "published": published,
                "source": "CISA KEV",
                "source_id": "cisa_kev",
                "cve_id": cve_id,
                "seen_at": now_iso,
            })
            continue

        # --- Raw CISA KEV schema (defensive fallback) ---
        cve_id = v.get("cveID") or v.get("cve_id") or v.get("id") or ""
        if not cve_id:
            continue
        name = v.get("vulnerabilityName") or v.get("name") or ""
        desc = v.get("shortDescription") or v.get("description") or ""
        vendor = v.get("vendorProject") or v.get("vendor") or ""
        product = v.get("product") or ""
        due = v.get("dueDate") or v.get("due_date") or ""
        ransomware = v.get("knownToBeUsedInRansomware") or v.get("known_ransomware") or ""

        title = f"{cve_id}: {name}" if name else cve_id
        summary_parts = []
        if desc:
            summary_parts.append(desc)
        if vendor or product:
            tag = f"[{vendor} {product}]".strip() if (vendor and product) else f"[{vendor or product}]"
            summary_parts.append(tag)
        if due:
            summary_parts.append(f"Due: {due}")
        if ransomware:
            summary_parts.append(f"Ransomware use: {ransomware}")
        summary = " | ".join(summary_parts) if summary_parts else cve_id

        articles.append({
            "id": f"cisa_kev:{cve_id}",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "title": title,
            "summary": summary[:2000],
            "published": due or "",
            "source": "CISA KEV",
            "source_id": "cisa_kev",
            "cve_id": cve_id,
            "vendor": vendor,
            "product": product,
            "due_date": due,
            "known_ransomware": ransomware,
            "seen_at": now_iso,
        })

    log.info("CISA KEV: parsed %d entries", len(articles))
    return articles


def poll_all_feeds() -> dict[str, Any]:
    """Poll all 14 hardcoded feeds plus the CISA KEV catalog, store new
    articles in security_news.jsonl, and flag potential zero-day articles
    into zero_day_alerts.jsonl.

    Returns a summary dict with counts: {new_articles, zero_day_flags, errors}.
    """
    all_new: list[dict[str, Any]] = []
    zero_day_candidates: list[dict[str, Any]] = []
    errors = 0

    # --- RSS / Atom feeds ---
    for feed in FEEDS:
        try:
            articles = poll_feed(feed)
        except Exception as e:
            log.warning("Error polling %s: %s", feed["name"], e)
            errors += 1
            continue
        all_new.extend(articles)

    # --- CISA KEV catalog (JSON, not RSS) ---
    try:
        kev_articles = poll_cisa_kev()
    except Exception as e:
        log.warning("Error polling CISA KEV: %s", e)
        errors += 1
        kev_articles = []
    all_new.extend(kev_articles)

    # --- Flag zero-day candidates across all articles (RSS + KEV) ---
    for art in all_new:
        blob = (art.get("title", "") + " " + art.get("summary", "")).lower()
        if any(kw.lower() in blob for kw in ZERO_DAY_KEYWORDS):
            art["flag"] = "zero_day_candidate"
            zero_day_candidates.append(art)

    # Dedup against existing news DB
    new_articles = intel_db.filter_new(intel_db.NEWS_FILE, all_new)
    if new_articles:
        intel_db.append_many(intel_db.NEWS_FILE, new_articles)

    # Dedup zero-day candidates against existing alerts DB
    new_zero_days = intel_db.filter_new(intel_db.ZERO_DAY_FILE, zero_day_candidates)
    if new_zero_days:
        intel_db.append_many(intel_db.ZERO_DAY_FILE, new_zero_days)

    # Prune old entries to keep DBs from growing unbounded
    try:
        intel_db.prune_old(intel_db.NEWS_FILE, age_days=intel_db.PRUNE_AGE_DAYS)
    except Exception:
        pass

    return {
        "new_articles": len(new_articles),
        "zero_day_flags": len(new_zero_days),
        "errors": errors,
        "feeds_polled": len(FEEDS) + 1,  # +1 for CISA KEV
    }


def get_recent_news(limit: int = 20) -> list[dict[str, Any]]:
    """Return the most recent N articles from the news DB."""
    all_news = intel_db.read_all(intel_db.NEWS_FILE)
    # Sort by seen_at desc
    all_news.sort(key=lambda r: r.get("seen_at", ""), reverse=True)
    return all_news[:limit]


def get_zero_day_alerts(limit: int = 20) -> list[dict[str, Any]]:
    """Return the most recent N zero-day alerts."""
    alerts = intel_db.read_all(intel_db.ZERO_DAY_FILE)
    alerts.sort(key=lambda r: r.get("seen_at", ""), reverse=True)
    return alerts[:limit]