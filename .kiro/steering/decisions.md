# Approved spec decisions (governance-spec)

Recorded after Mir approved the spec. These bind implementation.

1. **Grant model** — single-use per `(agent, tool, args-hash)`; a grant is consumed on first use and expires after a short TTL.
2. **Tier source** — `policy/opa/tiers.yml` data file loaded into OPA as `data` (not hard-coded in Rego, not in the gateway).
3. **Approval interface** — CLI first; web UI is optional/out of scope now.
4. **License** — state **Apache-2.0** for software and **CC-BY-4.0** for docs. Keep upstream `LICENSE`, `LICENSE-DOCS`, `NOTICE` untouched. Fix the "MIT" wording in `docs/DESIGN.md` as part of task 16.
5. **apm in CI** — build and install `apm` from this fork's own `src/apm_cli` (do not depend on a published PyPI release).

## Guardrails (standing)
- Do not modify anything under `src/apm_cli/**` except read-only imports.
- Do not merge into `main`; do not open PRs to `microsoft/apm`.
- No `Co-authored-by` and no AI-attribution lines in commit messages.
- Never invent eval numbers: report metrics only from an actual committed eval run (timestamp + git SHA).
- One commit per task with tests passing; stop and report after each task group or on any blocker.

## Environment constraint discovered at implementation start (2026-11-10)
Sandbox network mode is **INTEGRATIONS_ONLY**: no PyPI, no Docker registry pulls, no external binary downloads.
- Base interpreter has only stdlib + `click`; `apm_cli` cannot import (missing `requests`/`pyyaml`/etc.).
- OPA binary, Keycloak, OpenTelemetry SDK, PDF libraries, and docker-compose are **not installable here**.
Implication: implement with a **dependency-light, pluggable** design so core logic is unit-testable on stdlib now, with real OPA/OIDC/OTel/PDF wired behind adapters and exercised in CI (which has network), not in this sandbox. See each task's notes.
