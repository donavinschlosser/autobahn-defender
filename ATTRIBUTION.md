# Attribution

## AdventDev/Kudu

Some security detection patterns and architectural concepts in Autobahn Defender
are adapted from [AdventDev/kudu](https://github.com/AdventDevInc/kudu) (MIT License).

Specifically, the following components draw from Kudu's codebase:

- **CVE false-positive filter** (`engine/cve_filter.py`): Debian/Ubuntu version
  parsing, misattributed-package suppression, disputed-CVE pairs, deduplication.
  Adapted from `src/main/services/cve-filter.ts`.

- **Privacy shield** (`engine/privacy.py`): GNOME gsettings privacy checks and
  sysctl kernel/network hardening settings.
  Adapted from `src/main/platform/linux/privacy.ts`.

- **Startup manager** (`engine/startup.py`): XDG autostart + systemd user
  services + @reboot cron listing and management.
  Adapted from `src/main/platform/linux/startup.ts`.

- **Threat blacklist validation** (`engine/network_watch.py`): Size caps and
  schema validation for downloaded blacklists.
  Adapted from `src/main/services/threat-blacklist-store.ts`.

- **Detection ledger** (in `scanner.py`): Content-hash binding for quarantine
  actions to prevent TOCTOU attacks.
  Adapted from Kudu's detection ledger concept.

- **SKIP_DIRS** (in `scanner.py`): Skipping node_modules, .git, __pycache__
  during file collection.
  Adapted from `src/main/platform/linux/paths.ts`.

Kudu is licensed under the MIT License. We thank the AdventDev team for their
excellent work on open-source security tooling.

## License

Autobahn Defender is licensed under the MIT License.

## Contact

XMPP: digitalautobahn@xmpp.brax.me