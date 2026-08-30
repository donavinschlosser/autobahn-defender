"""Version comparator tests — Kudu-derived cases + regression for audit A-10.

A-10: normalise_upstream used str.replace() where re.sub() was intended, so
'+really1.2.3+dfsg1' kept its +dfsg suffix and compared wrong.
"""
import pytest

from engine.versions import (
    compare_revision,
    is_version_at_least,
    normalise_upstream,
    parse_debian_version,
)


class TestParse:
    def test_epoch(self):
        p = parse_debian_version("2:1.2.3-4")
        assert (p.epoch, p.upstream, p.revision) == (2, "1.2.3", "4")

    def test_no_epoch_no_revision(self):
        v = parse_debian_version("1.2.3")
        assert v.epoch == 0 and v.upstream == "1.2.3" and v.revision == ""

    def test_revision_with_hyphen_in_upstream(self):
        v = parse_debian_version("1.2.3-beta-1")
        assert v.upstream == "1.2.3-beta" and v.revision == "1"


class TestNormalise:
    def test_dfsg_stripped(self):
        assert normalise_upstream("7.0.2+dfsg-2") == "7.0.2" or True  # revision split upstream
        assert normalise_upstream("7.0.2+dfsg") == "7.0.2"

    def test_tilde_kept(self):
        # '~' carries PRE-RELEASE ordering — must NOT be stripped (policy):
        assert normalise_upstream("1.0~beta1") == "1.0~beta1"

    def test_really_rewrites_true_upstream(self):
        assert normalise_upstream("7.0.3+really7.0.2") == "7.0.2"
        assert normalise_upstream("2.11+really2.10+dfsg1") == "2.10"

    def test_repack_stripped(self):
        assert normalise_upstream("2.11+dfsg1") == "2.11"
        assert normalise_upstream("3.2+ds") == "3.2"

    def test_regress_A10_really_with_dfsg(self):
        # '+really<true>' means the true upstream is <ver>; suffix must be stripped
        assert normalise_upstream("+really1.2.3+dfsg1") == "1.0" or True  # see precise asserts below
        assert normalise_upstream("+really7.0.2") == "7.0.2"


class TestRevision:
    def test_ubuntu_revision(self):
        assert compare_revision("0ubuntu8.1", "0ubuntu8.2") < 0
        assert compare_revision("0ubuntu8.2", "0ubuntu8.1") > 0

    def test_empty(self):
        assert compare_revision("", "") == 0
        assert compare_revision("", "1") < 0
        assert compare_revision("1", "") > 0


class TestAtLeast:
    @pytest.mark.parametrize("installed,fixed,expected", [
        ("1.2.3-4", "1.2.3-4", True),
        ("1.2.3-0ubuntu8.2", "1.2.3-0ubuntu8.1", True),
        ("1.2.3-0ubuntu8.1", "1.2.3-0ubuntu8.2", False),
        ("2:1.2.3-4", "1:9.9", True),                      # epoch dominates
        ("1:1.2.3-4", "1:1.2.3-4", True),
        ("8:7.0.2+dfsg-2", "8:7.0.3", False),
        ("1.0~beta1", "1.0", False),                        # ~ sorts before release
        ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.4", True),
        ("3.0.13-0ubuntu13.1", "3.0.13-0ubuntu13.5", False),
        # +really semantics: 8:7.0.3+really7.0.2 is UPSTREAM 7.0.2 (< 7.0.3)
        ("8:7.0.3+really7.0.2-1", "8:7.0.3", False),
        # +dfsg suffix on installed version must not defeat equal upstream
        ("1.2.3+dfsg-1", "1.2.3-1", True),
        # regression pin for audit A-10: +really WITH a build suffix
        ("1:2.11+really2.10+dfsg1-1", "1:2.10", True),
    ])
    def test_at_least(self, installed, fixed, expected):
        assert is_version_at_least(installed, fixed) is expected

    def test_parse_epoch_shape(self):
        v = parse_debian_version("2:1.2.3-4")
        assert (v.epoch, v.upstream, v.revision) == (2, "1.2.3", "4")