"""Oracle test: engine.versions vs apt_pkg (Debian's own comparator).

Skipped automatically when python3-apt is unavailable (e.g. the Hermes venv);
run under /usr/bin/python3 for the full oracle. Deterministic sample seeded.
"""
import random
import subprocess

import pytest

apt_pkg = pytest.importorskip("apt_pkg")

from engine.versions import is_version_at_least  # noqa: E402


def _perturb(v: str, rng: random.Random):
    out = []
    if v and v[-1].isdigit():
        out.append(v[:-1] + str(int(v[-1]) + 1))
        out.append(v[:-1] + str(max(0, int(v[-1]) - 1)))
    out.append(v + "~ppa1")
    out.append(v + "+dfsg1")
    out.append(v + "+really1.0")
    out.append("1:0.1-1" if ":" not in v else v)
    out.append("9.9.9-9" if "-" not in v else "9.9.9-1")
    return out


def test_policy_compare_matches_apt_pkg(isolated_env, monkeypatch):
    apt_pkg.init_system()
    rng = random.Random(20260831)
    res = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}\n"], capture_output=True, text=True)
    versions = sorted({v.strip() for v in res.stdout.splitlines() if v.strip()})
    assert versions, "no dpkg versions found"
    rng.shuffle(versions)
    mismatches = []
    checked = 0
    for base in versions[:300]:
        for other in _perturb(base, rng)[:4]:
            other = other.strip()
            if not other or other == base:
                continue
            try:
                expected = apt_pkg.version_compare(base, other) >= 0
            except Exception:
                continue
            checked += 1
            if is_version_at_least(base, other) != expected:
                mismatches.append((base, other))
    assert checked > 500, "oracle sample unexpectedly small"
    assert not mismatches, f"mismatches vs apt_pkg: {mismatches[:10]}"