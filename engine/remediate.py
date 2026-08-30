"""Autobahn Defender — Remediation lifecycle engine (Phase 3.3).

The "disable it, patch it, verify it, restore it" loop, review-first:

    DETECTED ─▶ plan(review) ─▶ CONTAIN(opt) ─▶ UPDATE ─▶ VERIFY ─▶ RESTORE

Every step produces a *plan* the user (or agent, with a confirm token) reviews
before executing. No step auto-executes. All privileged commands flow through
engine.apply's pkexec + actions.log machinery — no new privilege surface.

CLI:   autobahn-defender remediate plan <alert-id> / apply <alert-id> --token
GUI:   future Alert Center integration (plan shown as review dialog)
"""
from __future__ import annotations

import secrets
from typing import Any

from . import alerts as alerts_mod
from . import patches as patches_mod
from .apply import service_action


def plan_for_alert(alert: dict) -> dict[str, Any]:
    """Build the containment/update/verify/restore plan for an intel alert.

    alert: dict from the alerts store (cve_id, package, fixed_in,
    exploited, public_poc, ransomware...) — or the intel store's row.
    """
    cve_id = str(alert.get("cve_id") or alert.get("cve") or "")
    package = str(alert.get("package") or alert.get("affected_package") or "")
    if not cve_id or not package:
        return {"ok": False, "error": "alert missing cve_id/package"}

    exploited = bool(alert.get("exploited"))
    ransomware = bool(alert.get("ransomware")) or \
        "ransomware" in str(alert.get("title", "")).lower()

    steps: list[dict[str, Any]] = []

    # 1. CONTAIN — optional, only for exploited/ransomware CVEs with a
    #    maskable associated service (best-effort name match).
    svc_guess = _guess_service(package)
    if exploited and svc_guess:
        steps.append({
            "step": "contain", "label": f"Mask {svc_guess} (stop + disable until patched)",
            "argv": ["systemctl", "mask", svc_guess],
            "rollback": ["systemctl", "unmask", svc_guess],
            "requires_root": True,
            "risk": "medium — disables the service until restored",
        })

    # 2. UPDATE — the actual fix
    if alert.get("fixed_in"):
        steps.append({
            "step": "update", "label": f"Upgrade {package}",
            "argv": ["apt-get", "install", "-y", package],
            "rollback": [f"apt-get install {package}=<previous_version>"],
            "requires_root": True,
    "risk": "installs a package update (review the version)",
        })
    else:
        steps.append({
            "step": "update", "label": f"No patch for {cve_id} yet",
            "argv": None, "rollback": None, "requires_root": False,
            "risk": "none available — mitigation is containment only",
            "blocked": True,
        })

    # 3. VERIFY
    steps.append({
        "step": "verify", "label": f"Verify {package} resolves {cve_id}",
        "argv": None, "engine_call": "patches.verify_patch_applied",
        "rollback": None, "requires_root": False, "risk": "read-only",
    })

    # 4. RESTORE (undo containment)
    if exploited and svc_guess:
        steps.append({
            "step": "restore", "label": f"Unmask {svc_guess} (after verified fix)",
            "argv": ["systemctl", "unmask", svc_guess],
            "rollback": None, "requires_root": True,
            "risk": "re-enables the service",
            "condition": "only after verify returns all_resolved=true",
        })

    urgency = "URGENT" if (exploited and ransomware) else \
        ("HIGH" if exploited else "NORMAL")
    return {
        "ok": True,
        "cve_id": cve_id, "package": package,
        "urgency": urgency_label(exploited, ransomware),
        "exploited": exploited, "ransomware": ransomware,
        "steps": steps,
        "review_required": True,
        "note": ("Execution requires explicit confirmation per step "
                 "(GUI dialog or CLI confirm token)."),
    }


def urgency_label(exploited: bool, ransomware: bool) -> str:
    if exploited and ransomware:
        return "URGENT"
    if exploited:
        return "HIGH"
    return "NORMAL"


def _guess_service(package: str) -> str | None:
    """Best-effort service name for a package; None when not a known daemon."""
    known = {
        "openssh-server": "ssh",
        "apache2": "apache2", "nginx": "nginx",
        "cups": "cups", "samba": "smbd", "postfix": "postfix",
        "dovecot": "dovecot", "postgresql": "postgresql",
        "mariadb-server": "mariadb", "redis-server": "redis-server",
        "docker.io": "docker", "docker-ce": "docker",
        "memcached": "memcached", "bind9": "named",
        "clamav-daemon": "clamav-daemon", "fail2ban": "fail2ban",
    }
    return known.get(package)


# ── execution (token-gated) ──────────────────────────────────────────────────

_pending_tokens: dict[str, dict[str, Any]] = {}


def request_token(alert: dict, step: str) -> dict[str, Any]:
    """Issue a one-time confirm token for a planned step (agent friction:
    read-then-write contract — the caller must read the plan before acting).

    Returns {ok, token, step, plan} so callers display the plan AND the token
    in one response."""
    plan = plan_for_alert(alert)
    if not plan.get("ok"):
        return plan
    token = secrets.token_urlsafe(8)
    _pending_tokens[token] = {"plan": plan, "step": step}
    return {"ok": True, "token": token, "step": step, "plan": plan,
            "expires_after_use": True}


def execute_step(token: str) -> dict[str, Any]:
    """Execute a planned step with a valid token. One-time use."""
    entry = _pending_tokens.pop(token, None)
    if not entry:
        return {"ok": False, "error": "invalid or expired token"}
    plan = entry["plan"]
    step_name = entry["step"]
    step = next((s for s in plan["steps"] if s["step"] == step_name), None)
    if not step:
        return {"ok": False, "error": f"unknown step '{step_name}'"}
    if step.get("blocked"):
        return {"ok": False, "error": "step blocked: " + step.get("risk", "")}

    if step_name in ("contain", "restore") and step.get("argv"):
        argv = step["argv"]
        if argv[:2] == ["systemctl", "mask"]:
            svc = argv[2]
            res = service_action(svc, "mask")
        elif argv[:2] == ["systemctl", "unmask"]:
            svc = argv[2]
            res = service_action(svc, "unmask")
        else:
            return {"ok": False, "error": f"unsupported argv {argv}"}
        return {"ok": bool(res.get("success")), "result": res}

    if step_name == "update" and step.get("argv"):
        pkg = plan["package"]
        from .apply import apt_upgrade_package
        res = apt_upgrade_package(pkg)
        return {"ok": bool(res.get("success")), "result": res}

    if step_name == "verify":
        res = patches_mod.verify_patch_applied(plan["package"], plan["cve_id"])
        return {"ok": True, "result": res,
                "resolved": bool(res.get("all_resolved")),
                "inconclusive": res.get("status") == "inconclusive"}

    return {"ok": False, "error": f"step '{step_name}' has no executor"}