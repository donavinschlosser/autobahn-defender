"""
Autobahn Defender — Unified finding model + CVSS 3.1 parsing.

P0 (audit 2026-08-31, findings A-5/B-1): every check converts its ad-hoc
output into Finding dicts; the advisor consumes findings directly. Also hosts
the CVSS 3.1 base-score calculator so CVE severities become real
CRITICAL/HIGH/MEDIUM/LOW labels instead of raw vector strings.

Field contract (CLI/JSON stable; additive changes only):
    severity, check_id, title, what, why, fix, fix_command, source, cve_id,
    exploited, raw
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    severity: str                 # CRITICAL|HIGH|MEDIUM|LOW|INFO|UNKNOWN
    check_id: str
    title: str
    what: str
    why: str
    fix: str = ""
    fix_command: str = ""         # display-only; never auto-run
    source: str = ""
    cve_id: str = ""
    exploited: bool = False
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = normalize_severity(d.get("severity"))
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return Finding(
            severity=str(d.get("severity", "UNKNOWN") or "UNKNOWN").upper(),
            check_id=str(d.get("check_id", "AD-UNKNOWN")),
            title=str(d.get("title", "") or ""),
            what=str(d.get("what", "") or ""),
            why=str(d.get("why", "") or ""),
            fix=str(d.get("fix", "") or ""),
            fix_command=str(d.get("fix_command", "") or ""),
            source=str(d.get("source", "") or ""),
            cve_id=str(d.get("cve_id", "") or ""),
            exploited=bool(d.get("exploited", False)),
            raw=dict(d.get("raw") or {}),
        )


_SEVERITY_ALIASES = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "MODERATE": "MEDIUM",
    "LOW": "LOW", "INFO": "INFO", "INFORMATIONAL": "INFO", "NONE": "INFO",
    "UNKNOWN": "UNKNOWN",
}


def normalize_severity(label: str) -> str:
    """Map any severity-ish string (OSV 'HIGH', nvd 'MODERATE', 'critical') to
    the fixed enum. Unknown -> UNKNOWN."""
    if not label:
        return "UNKNOWN"
    return _SEVERITY_ENUM.get(str(label).strip().upper(), "UNKNOWN")


SEVERITY_ENUM = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")

_SEVERITY_ENUM = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
    "NONE": "UNKNOWN",
    "UNKNOWN": "UNKNOWN",
}

# --------------------------------------------------------------------------
# CVSS 3.1 base score (FIRST spec)
# --------------------------------------------------------------------------

_CVSS_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {  # keyed by (value, scope_changed)
        ("N", 0): 0.85, ("N", 1): 0.85,
        ("L", 0): 0.62, ("L", 1): 0.68,
        ("H", 0): 0.27, ("H", 1): 0.5,
    },
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def parse_cvss31(vector: str) -> tuple[float | None, str]:
    """Compute the CVSS 3.1 base score + severity label from a vector string.

    Returns (None, 'UNKNOWN') when unparseable. Implements the FIRST CVSS 3.1
    base formula with the spec's mandated round-up to one decimal.
    """
    if not vector or "CVSS" not in vector:
        return None, "UNKNOWN"
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
        parts.pop("CVSS", None)
        av = _CVSS_W["AV"][parts["AV"]]
        ac = _CVSS_W["AC"][parts["AC"]]
        ui = _CVSS_W["UI"][parts["UI"]]
        scope_changed = 1 if parts.get("S") == "C" else 0
        pr = _CVSS_W["PR"][(parts["PR"], scope_changed)]
        c = _CVSS_W["C"][parts["C"]]
        i = _CVSS_W["I"][parts["I"]]
        a = _CVSS_W["A"][parts["A"]]

        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            raw = 0.0
        elif scope_changed:
            raw = min(1.08 * (impact + exploitability), 10.0)
        else:
            raw = min(impact + exploitability, 10.0)

        if raw <= 0:
            return 0.0, "NONE"
        # CVSS 3.1 mandates round UP to 1 decimal: smallest n/10 >= value.
        import math
        score = math.ceil(raw * 10) / 10.0
        return score, _cvss_label(score)
    except (KeyError, ValueError, TypeError):
        return None, "UNKNOWN"


def _cvss_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def extract_score_text(text: str) -> str:
    """Best-effort: pull a severity label out of free text (advisory strings
    like 'critical vulnerability'), else ''. Used by feed-based flows that
    have prose instead of vectors.
    """
    if not text:
        return ""
    s = str(text).upper()
    for word in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if word in s:
            return word
    return ""