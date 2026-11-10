# Steering — agent-access-governance-gateway

## Purpose
Portfolio project: extend Microsoft **APM** (Agent Package Manager) with a **runtime Access Governance Gateway**. One policy (`apm-policy.yml`) enforced at install/CI **and** on every live MCP tool call. Demo firm: **Northwind Advisory**.

## Upstream fork rules
- This repo is a **fork of [microsoft/apm](https://github.com/microsoft/apm)** — **Apache-2.0** for software, **CC-BY-4.0** for docs (historical MIT releases noted in `NOTICE`). Keep the Microsoft copyright and upstream license notices (incl. the historical MIT `NOTICE`) in all substantial portions.
- **Do not rewrite or freely edit upstream APM code paths.** Prefer **minimal hooks** only where the runtime must read policy/lockfile.
- Put **all our code** in isolated dirs, e.g.:
  - `gateway/` — MCP proxy / PEP
  - `policy/opa/` — Rego for groups + approval tiers
  - `reports/` — inventory, access, blocked, approvals, audit summary
  - `demo/` — 10-minute script assets
  - `eval/` — attack + benign suites and runner
- Track `upstream/main` with periodic merges; pin the APM CLI version in CI.

## Stack (cloud-agnostic)
- **OPA** (Rego) for allow / deny / ask decisions
- **OpenTelemetry** for the evidence log
- **OIDC** via **Keycloak** in docker-compose (lab default)
- **Entra** only as an **optional adapter stub** (Terraform/docs), never required to run the lab
- MCP streamable HTTP; Python for the gateway unless a clear reason says otherwise

## Hard constraints
- **Synthetic data only.** No real client data. Fictional firm: **Northwind Advisory**.
- **No PwC, Telekom, Magenta, or other employer branding** on demos, READMEs, or reports.
- **No AI attribution** and **no `Co-authored-by`** (or similar) on commits.
- **Never invent metrics.** Every number in README / report must come from a **committed eval run** with **timestamp + git SHA**. Until then write “planned / to be measured.”
- **Tests required** for every check (policy, gateway, reports parsers, eval smoke).
- README must be **skimmable in ~3 minutes**: problem → diagram → how to run → results table (when measured) → limitations.

## Docs Mir will place for you
- `docs/DESIGN.md` (product design)
- `docs/architecture-v2.png` (Miro-style architecture)

## Out of scope (v1)
- Classifying *what code* a coding agent writes (separate compliance project)
- Fixing upstream APM preview gaps / signed SLSA attestations
- Production HA / multi-region gateway
