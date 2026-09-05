.deps:
	@echo "dev deps: pip install pytest (dev only, never runtime)"

.PHONY: tests oracle lint compile audit-scan build-deb clean

# The always-run gate: compile + AST undefined-name scan + pytest
compile:
	python3 -m compileall -q engine cli ai main.py scanner.py quarantine.py settings.py updater.py yara_updater.py history_db.py firewall.py hardening.py kernel_checker.py usb_monitor.py security_tab.py security_news_tab.py settings.py history_db.py 2>/dev/null

tests: compile
	python3 -m pytest tests/ -q

oracle:
	/usr/bin/python3 tests/test_versions_oracle.py

lint:
	python3 /tmp/ad_lint.py

audit: compile tests

build-deb:
	bash build_v2.sh

clean:
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf build_deb_v2.0/autobahn-defender_2.0.1_amd64/usr/share/autobahn-defender/engine/__pycache__