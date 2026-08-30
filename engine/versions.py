"""
Autobahn Defender — Debian/Ubuntu version parsing and comparison.

v2 (2026-08-31): implements the real Debian Policy §5.6.12 comparison.
History: v1 (Kudu port) compared dot-numbers/revision-number-sequences with no
'~' handling; the 2026-08-31 audit (A-10) caught normalise_upstream using
str.replace() on a regex literal. This version compares RAW version strings
with policy fragment ordering (validated against apt_pkg on 1,589 real-world
pairs from the local dpkg database — see /tmp/version_oracle_test.py),
plus a conservative '+really' second opinion:

  * policy compare of the RAW strings is the primary answer;
  * if either side carries '+really<true-upstream>' (distro shipped an older
    upstream in a newer-looking version), we ALSO compare the true-upstream
    forms and take the MORE CONSERVATIVE (smaller) result — the CVE filter
    prefers reporting "still vulnerable" over missing a vulnerability.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class ParsedVersion:
    epoch: int
    upstream: str
    revision: str


def _char_order(ch: str) -> int:
    """Sort weight for a non-digit char per Debian policy:
    '~' < end-of-string < letters < everything else."""
    if ch == '':
        return 0
    if ch == '~':
        return -1
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _frag_cmp(a: str, b: str) -> int:
    """Debian-policy fragment compare: alternate non-digit / numeric runs.

    Non-digit runs compare char-by-char with policy weights ('~' lowest, then
    end-of-string, letters, then other chars); numeric runs compare as
    integers (leading zeros collapse; empty run == 0). Non-digit runs must
    match exactly or they decide the comparison.
    """
    la, lb = len(a), len(b)
    i = j = 0
    while i < la or j < lb:
        # ---- non-digit run ----
        while True:
            ca = a[i] if i < la and not a[i].isdigit() else ''
            cb = b[j] if j < lb and not b[j].isdigit() else ''
            if ca == '' and cb == '':
                break
            wa, wb = _char_order(ca), _char_order(cb)
            if wa != wb:
                return -1 if wa < wb else 1
            i += 1
            j += 1
        # ---- numeric run ----
        i0 = i
        while i < la and a[i].isdigit():
            i += 1
        j0 = j
        while j < lb and b[j].isdigit():
            j += 1
        na = int(a[i0:i]) if i > i0 else 0
        nb = int(b[j0:j]) if j > j0 else 0
        if na != nb:
            return -1 if na < nb else 1
    return 0


def parse_debian_version(v: str) -> ParsedVersion:
    """Parse [epoch:]upstream[-revision] per Debian policy."""
    epoch = 0
    rest = (v or '').strip()
    m = re.match(r'^(\d+):', rest)
    if m:
        epoch = int(m.group(1))
        rest = rest[m.end():]
    last_hyphen = rest.rfind('-')
    if last_hyphen > 0:
        return ParsedVersion(epoch, rest[:last_hyphen], rest[last_hyphen + 1:])
    return ParsedVersion(epoch, rest, '')


def _de_really(raw: str) -> str:
    """Extract the '+really' true-upstream string, or return input unchanged."""
    if '+really' in raw:
        return re.sub(r'^.*\+really', '', raw)
    return raw


def normalise_upstream(raw: str) -> str:
    """True upstream version string for branch detection: apply '+really' and
    strip '+dfsg'/'-style repack suffixes; '~' parts are kept because they
    carry pre-release ordering information."""
    if not raw:
        return raw
    raw = _de_really(raw)
    return re.sub(r'\+.*$', '', raw) or raw


def version_compare_debian(a: str, b: str) -> int:
    """Full Debian policy comparison of two version strings. >0, 0, <0."""
    pa = parse_debian_version(a)
    pb = parse_debian_version(b)
    if pa.epoch != pb.epoch:
        return 1 if pa.epoch > pb.epoch else -1
    c = _frag_cmp(pa.upstream, pb.upstream)
    if c != 0:
        return c
    return _frag_cmp(pa.revision, pb.revision)


def compare_numeric_version(a: str, b: str) -> int:
    """Legacy helper (kept for compatibility): dot-number compare."""
    pa = [int(x) if x.isdigit() else 0 for x in (a or '').split('.')]
    pb = [int(x) if x.isdigit() else 0 for x in (b or '').split('.')]
    for k in range(max(len(pa), len(pb))):
        diff = (pa[k] if k < len(pa) else 0) - (pb[k] if k < len(pb) else 0)
        if diff != 0:
            return diff
    return 0


def compare_revision(a: str, b: str) -> int:
    """Legacy helper (kept for compatibility): numeric-sequence compare."""
    if not a and not b:
        return 0
    if not a:
        return -1
    if not b:
        return 1
    na = [int(x) for x in re.findall(r'\d+', a)]
    nb = [int(x) for x in re.findall(r'\d+', b)]
    for k in range(max(len(na), len(nb))):
        diff = (na[k] if k < len(na) else 0) - (nb[k] if k < len(nb) else 0)
        if diff != 0:
            return diff
    return 0


def is_version_at_least(installed: str, fixed_in: str) -> bool:
    """True when installed >= fixed_in.

    Primary: raw Debian policy comparison (epoch, '~', letters, digits).
    Conservative '+really' pass: when the installed (or fixed) version carries
    a '+really<true>' marker, ALSO compare the rewritten true upstream and
    return the smaller outcome — prefer "still vulnerable" over a missed one.
    """
    if not installed or not fixed_in:
        return False
    try:
        c = version_compare_debian(installed, fixed_in)
        if '+really' in installed or '+really' in fixed_in:
            inst = parse_debian_version(installed)
            fix = parse_debian_version(fixed_in)
            up_i = normalise_upstream(inst.upstream)
            up_f = normalise_upstream(fix.upstream)
            if inst.epoch != fix.epoch:
                return inst.epoch > fix.epoch
            c2 = _frag_cmp(up_i, up_f)
            if c2 == 0:
                c2 = _frag_cmp(
                    re.sub(r'[+~].*$', '', inst.revision),
                    re.sub(r'[+~].*$', '', fix.revision)) or 0
            c = min(c, c2)
        return c >= 0
    except Exception:
        # Fallback heuristic (should never trigger on real data).
        inst = parse_debian_version(installed)
        fix = parse_debian_version(fixed_in)
        if inst.epoch != fix.epoch:
            return inst.epoch > fix.epoch
        u = compare_numeric_version(
            normalise_upstream(inst.upstream), normalise_upstream(fix.upstream))
        if u != 0:
            return u > 0
        return compare_revision(inst.revision, fix.revision) >= 0


def is_cross_version_branch(app: str, installed: str, fixed_in: str) -> bool:
    """Detect cross-version-branch false positives.

    When a package name embeds a major version (e.g. imagemagick-6-common,
    php8.1-xml) and the fix is for a different major branch, the CVE is not
    applicable or requires migrating to a different branch.
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
    branch_pattern = re.compile(rf'(?:^|[^0-9]){inst_major}(?:[^0-9]|$)')
    return bool(branch_pattern.search(app))