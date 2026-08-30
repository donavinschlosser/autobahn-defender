"""Finding model + CVSS 3.1 parser tests.

Expected scores cross-checked against the FIRST CVSS 3.1 spec Appendix F
examples and NVD-published scores (CVE-2023-4863 → 8.8 etc.).
"""
import pytest

from engine.findings import (
    Finding,
    SEVERITY_ENUM,
    extract_score_text,
    normalize_severity,
    parse_cvss31,
)


@pytest.mark.parametrize("vector,expected_score,expected_label", [
    # FIRST CVSS 3.1 spec / NVD published examples:
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", 9.4, "CRITICAL"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "HIGH"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, "LOW"),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "LOW"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE"),
])
def test_cvss31_spec_examples(vector, expected_score, expected_label):
    score, label = parse_cvss31(vector)
    assert score == expected_score
    assert label == expected_label or (expected_score == 0.0 and label == "NONE")


def test_cvss31_bad_vectors_return_unknown():
    for bad in ("", None, "nonsense", "CVSS:3.1/AV:X", "CVSS:3.1"):
        score, label = parse_cvss31(bad)
        assert score is None and label == "UNKNOWN"


def test_normalize_severity():
    assert normalize_severity("high") == "HIGH"
    assert normalize_severity("MODERATE") == "MEDIUM"
    assert normalize_severity("info") == "INFO"
    assert normalize_severity("") == "UNKNOWN"
    assert normalize_severity("weird") == "UNKNOWN"


def test_finding_roundtrip():
    f = Finding(
        severity="critical", check_id="AD-TEST-001", title="t",
        what="w", why="why", fix="fix me", fix_command="do --it",
        source="test", cve_id="CVE-2026-0001", exploited=True,
        raw={"x": 1},
    )
    d = f.to_dict()
    assert d["severity"] == "CRITICAL"
    f2 = Finding.from_dict(d)
    assert f2.check_id == "AD-TEST-001" and f2.cve_id == "CVE-2026-0001"
    assert f2.exploited is True
    assert f2.severity == "CRITICAL"


def test_extract_score_text():
    assert extract_score_text("a critical vulnerability in X") == "CRITICAL"
    assert extract_score_text("medium severity") == "MEDIUM"
    assert extract_score_text("") == ""