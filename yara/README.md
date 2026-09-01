# YARA Rules — Release Package (Codeberg `yara/` folder)

This folder is what installed Autobahn Defender apps download for rule
updates (`yara_updater.py` → `raw/branch/main/yara/VERSION`).

## Current release: VERSION 4 (v2.0 rule rebuild)

Contents:
- `VERSION` — integer release number; bump when shipping rule changes
- `linux-rules.yar` — Linux rules, v2.0 precision rebuild
  (16 over-generalized rules rewritten: family-specific indicators only)
- `windows-rules.yar` — Windows ransomware/backdoor rules
- `macos-rules.yar` — macOS rules
- (windows-malware-rules.yar ships only inside the app packages — it is
  loaded for PE files separately and is not part of the auto-update set)

## How to ship an update

1. Edit the rules and make sure `yara.compile()` succeeds for every file:
   `python3 -c "import yara; yara.compile(filepath='yara/linux-rules.yar')"`
2. Scan a stock system directory — there must be **zero hits** on
   `/usr/bin/*` binaries. Zero FP on system files is a release gate.
3. Confirm real samples still trigger their family rules.
4. Bump `VERSION` (integer). Apps compare integers; anything smaller than
   the local value is ignored.
5. Commit + push to Codeberg. Installed apps pick it up within 24h or via
   Settings → *Update YARA Rules Now*.

## Version history

- 4 — v2.0 rule rebuild: precision pass (16 rules rewritten), zero-FP gate
- 3 — pre-release v2.0 set
- 2 — v1.4 baseline