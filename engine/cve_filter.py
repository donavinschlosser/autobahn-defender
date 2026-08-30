"""
Autobahn Defender — CVE false-positive filter.

Adapted from AdventDev/kudu cve-filter.ts (MIT license).
Philosophy: prefer silence over a false alert.

Filters out:
  1. Explicitly suppressed CVE+package pairs (disputed, retracted)
  2. Known misattributed packages (wrong package matched to a CVE)
  3. Installed version already >= fix version
  4. Ancient CVEs (>7 years old) with no fix version
  5. Cross-version-branch mismatches
  6. Duplicate CVE entries (DEBIAN-CVE + CVE, -dev/-dbg/-doc dupes)
"""

from __future__ import annotations

import re
from datetime import datetime

from .versions import (
    parse_debian_version,
    normalise_upstream,
    compare_numeric_version,
    compare_revision,
    is_version_at_least,
    is_cross_version_branch,
)

_CURRENT_YEAR = datetime.now().year

# Packages commonly misattributed CVEs belonging to their parent runtime
# or a different package with a similar name.
_MISATTRIBUTED_PACKAGES: list[re.Pattern] = [
    # PHP
    re.compile(r'^php-pear'),
    # Bash
    re.compile(r'^bash-completion$'),
    # Git
    re.compile(r'^git-(man|doc|el|email|gui|mediawiki|svn)$'),
    # Python — exclude core packages (dev/dbg/minimal/venv/etc)
    re.compile(r'^python3?-(?!(dev|dbg|minimal|venv|distutils|lib2to3|gdbm|tk|idle|full|all|examples|doc)$)[a-z]'),
    # Perl — CPAN modules named lib<name>-perl
    re.compile(r'^lib.+-perl$'),
    # Ruby — gems named ruby-<gemname>, excluding dev/full/doc
    re.compile(r'^ruby-(?!(dev|full|doc)$)[a-z]'),
    # Node.js — npm packages named node-<name>
    re.compile(r'^node-[a-z]'),
    # Linux kernel headers (not the kernel itself)
    re.compile(r'^linux-headers'),
    re.compile(r'^linux-libc-dev$'),
    # R — CRAN/Bioconductor packages
    re.compile(r'^r-(cran|bioc)-'),
    # Lua library modules
    re.compile(r'^lua-[a-z]'),
    # Emacs Lisp packages
    re.compile(r'^elpa-'),
    # Haskell library packages
    re.compile(r'^libghc-.+-dev$'),
    # Go library source packages
    re.compile(r'^golang-(?!(go|src|doc)$).+-dev$'),
    # Texlive macro/font packages
    re.compile(r'^texlive-(?!bin)'),
]

# Individually suppressed CVE+package pairs (disputed, retracted, won't-fix)
_SUPPRESSED_PAIRS: list[tuple[re.Pattern, re.Pattern]] = [
    # Disputed glibc CVEs — all major distros mark as "won't fix"
    (re.compile(r'2019-101002[2-5]'), re.compile(r'^libc')),
    # Hash table collision CPU DoS — inherent algorithmic property
    (re.compile(r'2016-20013'), re.compile(r'^libc')),
    # glibc glob() resource consumption — not a vuln per Debian/Ubuntu
    (re.compile(r'2010-4756'), re.compile(r'^libc')),
]

# Type for CVE entries passed to the filter
_CVEEntry = dict  # keys: cve_id, app_name, installed_version, fixed_in


def is_likely_false_positive(entry: _CVEEntry) -> bool:
    """Returns True if the CVE entry is a likely false positive.
    Errs on the side of suppression (prefer no alert over a wrong alert).
    """
    app = (entry.get('app_name') or '').lower()
    cve = (entry.get('cve_id') or '').upper()
    installed = entry.get('installed_version') or ''
    fixed_in = entry.get('fixed_in') or ''

    # 1. Explicitly suppressed CVE+package pairs
    for cve_pat, app_pat in _SUPPRESSED_PAIRS:
        if cve_pat.search(cve) and app_pat.search(app):
            return True

    # 2. Known misattributed packages
    for pattern in _MISATTRIBUTED_PACKAGES:
        if pattern.search(app):
            return True

    # 3. Installed version is already >= fix version
    has_fix_info = fixed_in and installed
    if has_fix_info:
        try:
            if is_version_at_least(installed, fixed_in):
                return True
        except Exception:
            pass  # If comparison fails, don't suppress — let user decide

    # 4. Ancient CVEs (>3 years old) with no fix version available.
    # If a modern distro hasn't issued a patch in 3+ years and OSV doesn't
    # list a fix version, the CVE was either silently fixed via a backport
    # (Ubuntu backports patches without changing the version number) or
    # is not applicable to this distro's build.
    year_match = re.search(r'CVE-(\d{4})-', cve)
    if year_match:
        cve_year = int(year_match.group(1))
        if not fixed_in and _CURRENT_YEAR - cve_year > 3:
            return True

    # 5. Cross-version-branch mismatch
    if has_fix_info:
        try:
            if is_cross_version_branch(app, installed, fixed_in):
                return True
        except Exception:
            pass

    return False


def _normalize_cve_id(cve_id: str) -> str:
    """Extract canonical CVE number from any tracker-prefixed ID."""
    m = re.search(r'(\d{4}-\d+)', cve_id)
    return m.group(1) if m else cve_id


def _get_base_package_name(name: str) -> str | None:
    """Strip -dev, -dbg, -doc, -udeb suffixes. Returns None if no suffix."""
    m = re.match(r'^(.+)-(dev|dbg|doc|udeb)$', name)
    return m.group(1) if m else None


def deduplicate_cves(entries: list[_CVEEntry]) -> list[_CVEEntry]:
    """Remove duplicate CVE entries that inflate vulnerability counts.

    1. DEBIAN-CVE-XXXX-YYYY when CVE-XXXX-YYYY exists for same package
    2. foo-dev / foo-dbg / foo-doc when foo has the same CVE
    """
    has_canonical: set[str] = set()
    all_pairs: set[str] = set()
    for e in entries:
        key = f"{_normalize_cve_id(e.get('cve_id', ''))}|{(e.get('app_name') or '').lower()}"
        all_pairs.add(key)
        if e.get('cve_id', '').upper().startswith('CVE-'):
            has_canonical.add(key)

    result = []
    for e in entries:
        norm_id = _normalize_cve_id(e.get('cve_id', ''))
        app = (e.get('app_name') or '').lower()

        # 1. Remove non-canonical when canonical exists
        if not e.get('cve_id', '').upper().startswith('CVE-'):
            if f"{norm_id}|{app}" in has_canonical:
                continue

        # 2. Remove -dev/-dbg/-doc when base package has same CVE
        base = _get_base_package_name(app)
        if base and f"{norm_id}|{base}" in all_pairs:
            continue

        result.append(e)
    return result