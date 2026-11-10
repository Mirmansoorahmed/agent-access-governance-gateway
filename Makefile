# Minimal Makefile -- DX shortcut for the NOTICE-file generator.
# Add other targets here as the project grows.

.PHONY: notice notice-check

# Regenerate NOTICE from pyproject.toml + scripts/notice-metadata.yaml.
# Run this whenever you add / remove / bump a runtime dependency.
notice:
	uv run python scripts/generate-notice.py

# Same check that .github/workflows/notice-drift.yml runs in CI; useful
# for verifying locally before pushing.
notice-check:
	uv run python scripts/generate-notice.py --check

# --- Access Governance Gateway (fork-only) ---------------------------------
.PHONY: gateway-test

# Run the fork-only gateway unit suite. Uses the isolated gateway/pytest.ini so
# it does not inherit upstream APM markers/addopts. Pure-stdlib tests run
# without network or extra dependencies.
gateway-test:
	PYTHONPATH=. python -m pytest -c pytest-gateway.ini

.PHONY: opa-data opa-data-check opa-test

# Regenerate the JSON mirror of policy/opa/tiers.yml (offline gateway reads it).
opa-data:
	python scripts/sync_opa_data.py

# CI check: fail if the JSON mirror is stale.
opa-data-check:
	python scripts/sync_opa_data.py --check

# Run the Rego unit tests. Requires the `opa` binary (OPA 1.22.3 on the
# maintainer machine; CI installs the static binary).
opa-test:
	opa test policy/opa -v

.PHONY: reports

# Render the five audit reports to Markdown + PDF. Evidence comes from a demo or
# eval run: run `make demo` (or the eval harness) FIRST to produce the evidence
# files under .gateway/, then `make reports`. If the evidence is missing this
# fails closed (non-zero) rather than emitting all-zero reports. Numbers are
# never hand-entered. Requires the optional PDF dependency:
#   pip install 'apm-cli[reports]'.
reports:
	python scripts/render_reports.py --out reports/out \
		--spans .gateway/spans.jsonl \
		--approvals .gateway/approvals.json \
		--pins .gateway/pins.json \
		--lockfile apm.lock.yaml \
		--pdf
