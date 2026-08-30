"""
Autobahn Defender — Debian/Ubuntu version parsing and comparison.

Adapted from AdventDev/kudu cve-filter.ts (MIT license).
Handles Debian epochs, +dfsg/+really/+ds suffixes, ~beta, and
Debian revision comparison (e.g. 0ubuntu8.1 vs 0ubuntu8.2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class ParsedVersion:
    epoch: int
    upstream: str
    revision: str


def parse_debian_version(v: str) -> ParsedVersion:
    """Parse a Debian/Ubuntu version string: [epoch:]upstream[-revision].

    Also handles RPM (1.2.3-4.el9) and Alpine (1.2.3-r4) since the
    epoch:upstream-revision structure is shared.
    """
    epoch = 0
    rest = v.strip()
    m = re.match(r'^(\d+):', rest)
    if m:
        epoch = int(m.group(1))
        rest = rest[m.end():]
    last_hyphen = rest.rfind('-')
    if last_hyphen > 0:
        return ParsedVersion(epoch, rest[:last_hyphen], rest[last_hyphen + 1:])
    return ParsedVersion(epoch, rest, '')


def normalise_upstream(raw: str) -> str:
    """Normalise upstream version for numeric comparison.

    Handles Debian conventions: +really<ver> means true upstream is <ver>,
    strips +dfsg, +ds, +repack, ~beta, and similar suffixes.
    """
    really = re.match(r'\+really(.+)', raw)
    if really:
        return really.group(1).replace(r'[+~].*$', '',)
    return re.sub(r'[+~].*$', '', raw)


def compare_numeric_version(a: str, b: str) -> int:
    """Compare two dot-separated numeric version strings.
    Returns >0 if a > b, <0 if a < b, 0 if equal.
    """
    pa = [int(x) if x.isdigit() else 0 for x in a.split('.')]
    pb = [int(x) if x.isdigit() else 0 for x in b.split('.')]
    length = max(len(pa), len(pb))
    for i in range(length):
        diff = (pa[i] if i < len(pa) else 0) - (pb[i] if i < len(pb) else 0)
        if diff != 0:
            return diff
    return 0


def compare_revision(a: str, b: str) -> int:
    """Compare two revision strings by extracting all numeric sequences.
    "0ubuntu8.1" -> [0, 8, 1], "0ubuntu8.2" -> [0, 8, 2] -> 8.1 < 8.2
    """
    if not a and not b:
        return 0
    if not a:
        return -1
    if not b:
        return 1
    na = [int(x) for x in re.findall(r'\d+', a)]
    nb = [int(x) for x in re.findall(r'\d+', b)]
    length = max(len(na), len(nb))
    for i in range(length):
        diff = (na[i] if i < len(na) else 0) - (nb[i] if i < len(nb) else 0)
        if diff != 0:
            return diff
    return 0


def is_version_at_least(installed: str, fixed_in: str) -> bool:
    """Check if the installed version is >= the fix version.

    Handles Debian epochs, +dfsg suffixes, +really conventions,
    and Debian revision comparison.
    """
    inst = parse_debian_version(installed)
    fix = parse_debian_version(fixed_in)
    if inst.epoch != fix.epoch:
        return inst.epoch > fix.epoch
    up_cmp = compare_numeric_version(
        normalise_upstream(inst.upstream),
        normalise_upstream(fix.upstream),
    )
    if up_cmp != 0:
        return up_cmp > 0
    return compare_revision(inst.revision, fix.revision) >= 0


def is_cross_version_branch(app: str, installed: str, fixed_in: str) -> bool:
    """Detect cross-version-branch false positives.

    When a package name embeds a major version (e.g. imagemagick-6-common,
    php8.1-xml) and the fix is for a different major branch, the CVE is
    not applicable or requires migrating to a different branch.
    """
    inst = parse_debian_version(installed)
    fix = parse_debian_version(fixed_in)
    if inst.epoch != fix.epoch:
        return False
    inst_up = normalise_upstream(inst.upstream)
    fix_up = normalise_upstream(fix.upstream)
    inst_major = int(inst_up.split('.')[0]) if inst_up.split('.')[0].isdigit() else 0
    fix_major = int(fix_up.split('.')[0]) if fix_up.split('.')[0].isdigit() else 0
    if inst_major == 0 or fix_major == 0 or inst_major == fix_major:
        return False
    # Check if package name contains the installed major version
    branch_pattern = re.compile(rf'(?:^|[^0-9]){inst_major}(?:[^0-9]|$)')
    return bool(branch_pattern.search(app))