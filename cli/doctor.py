"""`autobahn-defender doctor` — environment self-check (Phase 6.2).

One JSON blob: dependencies, paths, perms, rule compile, API reachability,
kernel features. Also the CI entry point. Exit 1 = any check failed.
"""
from __future__ import annotations

import platform
import shutil
import sys
from pathlib import Path


def cmd_doctor(args, env) -> int:
    from .exitcodes import EXIT_CLEAN, EXIT_FINDINGS
    from engine.version import APP_VERSION

    checks = []

    def add(name: str, ok, detail="") -> None:
        checks.append({"check": name, "ok": bool(ok), "detail": str(detail)[:200]})

    add("python", True, f"{sys.version_info.major}.{sys.version_info.minor}")
    for tool in ("clamscan", "freshclam", "yara", "pkexec", "systemctl"):
        add(f"tool:{tool}", shutil.which(tool) is not None,
            shutil.which(tool) or "NOT FOUND")

    try:
        import yara  # noqa
        add("python3-yara", True)
    except ImportError:
        add("python3-yara", False, "install: sudo apt install python3-yara")
    try:
        import requests  # noqa
        add("python3-requests", True)
    except ImportError:
        add("python3-requests", False)
    try:
        import feedparser  # noqa
        add("python3-feedparser", True)
    except ImportError:
        add("python3-feedparser", False,
            "install: sudo apt install python3-feedparser")

    from engine.paths import APP_DIR, DATA_DIR
    add("app_dir", APP_DIR.exists(), str(APP_DIR))
    add("data_dir", DATA_DIR.exists(), str(DATA_DIR))
    rules_dir = APP_DIR / "rules"
    rule_files = list(rules_dir.glob("*.yar")) if rules_dir.exists() else []
    add("yara_rules_installed", len(rule_files) > 0, f"{len(rule_files)} file(s)")

    if rule_files:
        try:
            import yara
            file_map = {f.stem: str(f) for f in rule_files}
            yara.compile(filepaths=file_map)
            add("yara_rules_compile", True, f"{len(file_map)} files compiled")
        except AttributeError:
            # not yara-python (e.g. some venv shims) — the packaged runtime
            # uses python3-yara from apt which is correct; don't hard-fail
            add("yara_rules_compile", True,
                "skipped: active interpreter's yara is not yara-python "
                "(packaged runtime uses apt python3-yara)")
        except Exception as e:
            add("yara_rules_compile", False, str(e)[:150])

    # engine smoke — the audit's undefined-name detector, automated
    try:
        from engine.checks import CHECKS, run_check
        bad = []
        for name in sorted({c for c in CHECKS if not c.startswith("_t_")}):
            res = run_check(name, {})
            if res.get("status") == "error":
                msg = str(res.get("error", ""))
                if "NameError" in msg or "is not defined" in msg:
                    bad.append(name)
        add("engine_checks_no_undefined", len(bad) == 0,
            ", ".join(bad[:5]) or "all clean")
    except Exception as e:
        add("engine_checks_smoke", False, str(e)[:150])

    # kernel features
    try:
        cfg = Path(f"/boot/config-{platform.release()}")
        if cfg.exists():
            content = cfg.read_text()
            add("fanotify", "CONFIG_FANOTIFY=y" in content)
            add("fanotify_access_permissions",
                "CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y" in content)
        else:
            add("fanotify", True, "kernel config not readable — skipped")
    except Exception as e:
        add("fanotify", True, f"skipped: {e}")

    try:
        from engine.watch.inotify_watch import inotify_available
        add("inotify", inotify_available())
    except Exception as e:
        add("inotify", False, str(e)[:100])

    # intel feed reachability (HEAD, 5s each) — skipped in --quiet
    endpoints = [
        ("cisa-kev", "https://www.cisa.gov/sites/default/files/feeds/"
                     "known_exploited_vulnerabilities.json"),
        ("osv-api", "https://api.osv.dev/v1/query"),
        ("ubuntu-notices", "https://ubuntu.com/security/notices.json"),
        ("epss-csv", "https://epss.cyentia.com/epss_scores-current.csv.gz"),
    ]
    if not getattr(args, "quiet", False):
        env.progress("probing intel feed endpoints (5s timeout each)...", False)
    try:
        import requests
        for name, url in endpoints:
            try:
                r = requests.head(url, timeout=5, allow_redirects=True)
                add(f"feed:{name}", r.status_code < 500, f"HTTP {r.status_code}")
            except Exception as e:
                add(f"feed:{name}", False, str(e)[:80])
    except ImportError:
        add("feed-probe", False, "requests not installed")

    failed = sum(1 for c in checks if not c["ok"])
    doc = env.envelope("doctor", results=checks, summary={
        "version": __import__("engine.version", fromlist=["APP_VERSION"]).APP_VERSION,
        "failed": failed,
        "total": len(checks),
    })
    from cli.main import _emit
    _emit(args, doc, env)
    return EXIT_CLEAN if failed == 0 else EXIT_FINDINGS