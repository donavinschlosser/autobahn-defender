"""Engine smoke harness — the gate that catches the 'undefined name' bug class.

Audit context (2026-08-31): engine/checks.py composite checks referenced undefined
_t_* names; NameErrors were swallowed by except-pass, so dead features looked like
"no findings". This harness makes that failure mode loud: every registered check
must either run clean, return a *known* skip/error reason, or FAIL here.
"""
import pytest

from engine import checks

# Checks that intentionally require external fixtures/hardware:
# - check_yara_scan_file needs a compiled rules dir (own dedicated test)
EXTERNAL_ONLY = {"check_yara_scan_file"}

# NameError/ImportError/AttributeError leaking into results = dead code path.
FORBIDDEN_FRAGMENTS = (
    "NameError", "ImportError", "is not defined",
    "ModuleNotFoundError", "AttributeError",
)


@pytest.mark.parametrize("name", sorted(set(checks.CHECKS)))
def test_check_returns_known_shape(name, isolated_env):
    if name in EXTERNAL_ONLY:
        pytest.skip("external-fixture check")
    res = checks.run_check(name, {})
    assert isinstance(res, dict), f"{name}: non-dict result"
    assert res.get("status") in ("ok", "error"), f"{name}: malformed status {res!r}"
    if res["status"] == "error":
        msg = str(res.get("error", ""))
        for frag in FORBIDDEN_FRAGMENTS:
            assert frag not in msg, f"{name}: leaked interpreter error ({frag}): {msg}"


@pytest.mark.parametrize("name", sorted(set(checks.CHECKS)))
def test_check_ok_results_have_expected_keys(name, isolated_env):
    """Key checks must expose their advertised top-level keys — the advisor and
    the CLI read these; drift here is what silently emptied the old reports."""
    ADVERTISED = {
        "check_system_audit": lambda d: "firewall" in d and "ports" in d,
        "check_scan_persistence": lambda d: "findings" in d,
        "check_check_hosts": lambda d: "findings" in d,
        "check_ssh_audit": lambda d: "installed" in d and "findings" in d,
        "check_privacy_hardening": lambda d: "findings" in d and "total_checks" in d,
        "check_service_manager": lambda d: "running_count" in d or "error" in d,
        "check_dns_check": lambda d: "findings" in d,
        "check_network_security": lambda d: "findings" in d and "sub_checks" in d
            and not any(sc.get("status") == "error" and "not defined" in str(sc.get("error", ""))
                        for sc in d.get("sub_checks", {}).values()),
        "check_hardening_audit": lambda d: "findings" in d and "sub_checks" in d
            and not any(sc.get("status") == "error" and "not defined" in str(sc.get("error", ""))
                        for sc in d["sub_checks"].values()),
        "check_network_threat_monitor": lambda d: "findings" in d,
        "check_disk_encryption": lambda d: "findings" in d,
        "check_startup_manager": lambda d: "startup_items" in d,
        "check_password_policy": lambda d: "findings" in d,
        "check_update_status": lambda d: "findings" in d,
        "check_screen_lock": lambda d: "findings" in d,
        "check_privacy_hardening": lambda d: "findings" in d,
    }
    if name not in ADVERTISED:
        pytest.skip("no schema pin for this check")
    res = checks.run_check(name, {})
    if res.get("status") != "ok":
        pytest.skip(f"{name} not ok on this machine: {res.get('error', '')[:80]}")
    assert ADVERTISED[name](res["data"]), f"{name}: data missing advertised keys: {list(res['data'])}"