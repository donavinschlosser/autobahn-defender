"""Autobahn Defender — Threat-intel pipeline (Phase 3).

Collectors (all keyless, verified live 2026-08-30 — see
RESEARCH_zero_day_monitoring_digest_2026-08-31.md):
  kev        CISA Known Exploited Vulnerabilities JSON  (primary signal)
  ubuntu_osv Ubuntu OSV export tar.xz + notices.json    (Ubuntu/Mint fixed-versions)
  epss       FIRST EPSS bulk CSV                        (prioritization)
  poc        PoC-in-GitHub per-year JSON                (public-PoC flag)

store: SQLite (WAL, 0600) at ~/.local/share/autobahn-defender/intel/intel.db
match: joins intel against the installed package list → alerts
poll:  orchestrates one full collection cycle
"""