# Requirements — Agent Access Governance Gateway

**Status:** draft for review (spec turn 1 of 1) · **Do not implement until Mir says go.**
**Product brief:** [`docs/DESIGN.md`](../../../docs/DESIGN.md) · architecture: `docs/architecture-v2.png` (to be placed by Mir).
**Scope anchor:** fork of [microsoft/apm](https://github.com/microsoft/apm). Keep upstream install/CI behaviour; add a runtime Access Governance Gateway in isolated dirs (`gateway/`, `policy/opa/`, `reports/`, `demo/`, `eval/`).

> **Note for review (upstream license):** The brief and steering call upstream APM "MIT". The checked-in fork declares **Apache-2.0** in `apm.yml`/`LICENSE`, with `CONTRIBUTING.md` stating Apache-2.0 for software + CC-BY-4.0 for docs and the historical MIT notice retained in `NOTICE`. `DESIGN.md`/steering are kept verbatim as provided; this discrepancy is flagged for Mir to reconcile before any public README claim. See design.md §9.

---

## 1. Introduction

Upstream APM governs **what gets installed** (`apm.yml` → `apm.lock.yaml`, gated by `apm-policy.yml` at `apm install` and `apm audit --ci`). It is explicitly *not* a runtime sandbox and has no schema fields for the calling agent's identity or for live tool-call decisions (verified in `src/apm_cli/policy/schema.py`: `McpPolicy` matches names/transports and carries `trust_transitive` parsed-but-unenforced; there are no role/department/seniority/runtime fields).

This feature adds a **runtime Policy Enforcement Point (PEP)** — an MCP proxy — that loads the **same** effective `apm-policy.yml` and `apm.lock.yaml` and enforces policy on every `tools/call`. **One policy, two enforcement points.** All synthetic data; fictional firm **Northwind Advisory**; no employer branding; no AI commit attribution; no invented metrics.

### Glossary
- **PEP** — Policy Enforcement Point (the gateway intercepting calls).
- **PDP** — Policy Decision Point (OPA / Rego evaluating the decision).
- **Drift pin** — SHA-256 over an approved tool's `name + description + input schema`.
- **Tier** — approval class per tool/risk: `allow | ask | deny | four-eyes | break-glass`.
- **Effective policy** — `apm-policy.yml` after tighten-only inheritance merge (enterprise → org → repo).

---

## 2. User roles
- **Developer / Consultant** — runs an agent that issues MCP `tools/call` requests.
- **Security approver** — reviews onboarding requests and runtime `ask`/`four-eyes`/`break-glass` queue items.
- **Auditor** — reads the report pack; never operates the gateway.
- **Platform operator** — runs the gateway, OPA, Keycloak, OTel collector in the lab.

---

## 3. Requirements

Acceptance criteria use EARS-style phrasing. Each requirement names its test hook (see `tasks.md`).

### R1 — Runtime PEP intercepts every tool call
**Story:** As a platform operator, I want every MCP `tools/call` to pass through the gateway, so that no approved-at-install tool can be invoked without a runtime decision.

1. WHEN an MCP client sends `tools/call` to the gateway THEN the gateway SHALL evaluate the four checks (R3–R6) before forwarding to the upstream MCP server.
2. WHEN all four checks pass THEN the gateway SHALL forward the call unchanged and return the upstream response.
3. IF any check fails AND no approval grant applies THEN the gateway SHALL NOT forward the call and SHALL return a structured MCP error with a machine-readable `reason` code.
4. The gateway SHALL support MCP **streamable HTTP** transport between client and gateway, and to the upstream server.
5. WHEN `tools/list` is proxied THEN the gateway SHALL record the live catalogue for drift evaluation (R5) without blocking the listing itself.

### R2 — Same policy source as install/CI
**Story:** As a security approver, I want the gateway to read the same policy and lockfile as `apm audit --ci`, so that policy is written once and enforced in both planes.

1. The gateway SHALL load the **effective** `apm-policy.yml` using the fork's existing inheritance/merge logic (reuse `apm_cli.policy`, do not re-implement the merge).
2. The gateway SHALL load `apm.lock.yaml` pins (server identity, version, content hash) as read-only input.
3. WHEN policy or lockfile cannot be loaded or parsed THEN the gateway SHALL **fail closed** (deny all calls) and emit a `policy-load-failed` decision event.
4. The gateway SHALL NOT mutate `apm.yml`, `apm-policy.yml`, `apm.lock.yaml`, or any upstream APM code path at runtime.

### R3 — Check 1: Tool approved (policy allowlist, deny wins)
**Story:** As a security approver, I want calls to non-allowlisted servers/tools denied at runtime, so that a bypass of install-time gating is still stopped.

1. WHEN a call targets a server/tool matched by `mcp.deny` THEN the gateway SHALL deny (deny wins over allow).
2. IF `mcp.allow` is set AND the server/tool does not match it THEN the gateway SHALL deny.
3. WHEN `mcp.allow` is `None` ("no opinion") THEN the gateway SHALL treat the absence as **deny by default** at runtime and record `reason=no-allowlist` (fail-closed posture; documented divergence from install-time "no opinion").
4. Matching SHALL reuse upstream matcher semantics (`apm_cli.policy.matcher`) where applicable.

### R4 — Check 2: Group allowed (OIDC claims via OPA)
**Story:** As a security approver, I want tool access to follow the caller's role/department/seniority, so that approval alone does not grant everyone access.

1. The gateway SHALL authenticate the caller via **OIDC** (Keycloak in the lab) and extract `role`, `department`, `seniority` and group claims.
2. The gateway SHALL send tool + caller claims to **OPA** and SHALL allow only when Rego returns `allow` for that group→tool mapping.
3. IF required claims are missing or the token is invalid/expired THEN the gateway SHALL deny with `reason=identity-invalid`.
4. The group→tool mapping SHALL live in Rego under `policy/opa/`, not hard-coded in the gateway.
5. Entra SHALL be supported only as an **optional adapter stub**; the default lab path SHALL run with Keycloak and SHALL NOT require any cloud IdP.

### R5 — Check 3: Description unchanged (drift / tool-poisoning pin)
**Story:** As a security approver, I want a tool whose description changed after approval to be blocked, so that post-approval tool poisoning is caught.

1. At approval time the system SHALL compute and store a drift pin = SHA-256 of the approved tool's `name + description + input schema` (canonicalised).
2. WHEN a `tools/call` targets a tool whose live `tools/list` entry hashes differently from the stored pin THEN the gateway SHALL deny with `reason=description-drift`.
3. The gateway SHALL NOT auto-reset a pin; a pin reset SHALL require an explicit approval action (recorded in evidence).
4. Canonicalisation (key ordering, whitespace) SHALL be deterministic and unit-tested so benign serialisation changes do not false-block.

### R6 — Check 4: Approval tier
**Story:** As a security approver, I want sensitive calls routed through human approval, so that risky actions get a recorded decision.

1. Each tool (or risk class) SHALL carry a tier: `allow | ask | deny | four-eyes | break-glass`, resolved from policy/Rego.
2. WHEN tier is `allow` AND R3–R5 pass THEN the gateway SHALL auto-allow.
3. WHEN tier is `deny` THEN the gateway SHALL deny regardless of other checks.
4. WHEN tier is `ask` THEN the gateway SHALL pause the call and enqueue it for one approver decision.
5. WHEN tier is `four-eyes` THEN the gateway SHALL require **two distinct** approver identities before allowing.
6. WHEN tier is `break-glass` THEN the gateway MAY allow with mandatory justification and SHALL mark the decision high-severity in evidence for post-hoc review.
7. IF a queued request is not decided within a configured timeout THEN the gateway SHALL deny with `reason=approval-timeout`.

### R7 — Human approval interface
**Story:** As a security approver, I want to grant or deny queued calls, so that `ask`/`four-eyes`/`break-glass` have a clear workflow.

1. The system SHALL expose a **CLI and/or minimal web UI** to list the queue and grant/deny items.
2. A grant SHALL be scoped to one agent + one tool + one argument-set + single use by default; any broader grant model SHALL be explicitly documented.
3. Every grant/deny SHALL record approver id, timestamp, decision, and (for break-glass) justification in the evidence log.
4. `four-eyes` SHALL reject a second approval from the same identity as the first.

### R8 — Onboarding flow
**Story:** As a developer, I want to request a new MCP/skill and get it approved via a repeatable flow, so that new tools enter the allowlist safely.

1. A request SHALL trigger an automated **linter + attack-suite smoke** run against the candidate tool.
2. Approval SHALL require **four-eyes**.
3. On approval the flow SHALL open/update a **PR that amends `apm-policy.yml`** (it SHALL NOT silently edit policy on disk).
4. The happy path SHALL be documented in README and runnable in the demo.

### R9 — Evidence (OpenTelemetry)
**Story:** As an auditor, I want one evidence record per decision, so that the trail is machine-readable and complete.

1. The gateway SHALL emit one **OpenTelemetry span** per decision with: tool, server, agent id, group/claims summary, decision, `reason`, tier, pin hash, timestamp.
2. The gateway SHALL **redact full argument payloads** (store presence/shape or a hash, never raw sensitive args).
3. Evidence SHALL be exportable to a local OTel collector in the lab with **no cloud dependency**.

### R10 — Report pack (Markdown + PDF)
**Story:** As an auditor, I want five reports, so that I can review posture without operating the system.

1. The system SHALL generate: (1) Tool Inventory, (2) Access by Group, (3) Blocked Activity, (4) Approvals, (5) Audit Summary — each as **Markdown and PDF**.
2. The **Audit Summary** SHALL present only an **illustrative** mapping to ISO/IEC 42001 Annex A themes and EU AI Act Art. 12 (logging) / Art. 14 (human oversight), with an explicit disclaimer that it is not a conformity claim.
3. Reports SHALL derive solely from committed evidence (OTel spans, lockfile, policy) — no hand-entered numbers.
4. Reports SHALL complement, not replace, upstream SARIF and lockfile history.

### R11 — Eval harness
**Story:** As a maintainer, I want measured results, so that README claims are backed by a committed run.

1. The harness SHALL include attack cases: unapproved tool; wrong OIDC group; description drift / tool poisoning; risky action without approval; break-glass misuse.
2. The harness SHALL include a **benign golden path** that MUST NOT be false-blocked.
3. The harness SHALL measure **block rate**, **benign false-block rate**, and gateway overhead **p50 / p95** on the allow path.
4. Every result SHALL be persisted with **timestamp + git SHA**.
5. README/report numbers SHALL only be sourced from a committed eval run; until then they SHALL read "planned / to be measured".

### R12 — Demo + CI
**Story:** As a reviewer, I want a one-command demo and green CI, so that the end-to-end story is reproducible.

1. `make demo` SHALL run the 10-minute DESIGN.md script: unapproved PR fails CI → onboard → runtime allow → drift blocks → wrong group denies → show report.
2. CI (GitHub Actions) SHALL run upstream **`apm audit --ci`** plus the fork's unit/integration/OPA tests and the eval smoke.
3. CI SHALL pin the APM CLI version used for `apm audit --ci`.

### R13 — Fork hygiene & constraints (cross-cutting)
1. All fork code SHALL live under `gateway/`, `policy/opa/`, `reports/`, `demo/`, `eval/`; upstream `src/apm_cli/**` SHALL NOT be rewritten (minimal read-only hooks only).
2. All demo data SHALL be synthetic; the only firm name SHALL be **Northwind Advisory**; no PwC/Telekom/Magenta or other employer branding anywhere.
3. Commits SHALL carry **no AI attribution** and no `Co-authored-by` trailer.
4. The README SHALL be skimmable in ~3 minutes (problem → diagram → how to run → results table when measured → limitations).
5. Every check (policy, gateway, reports parsers, eval smoke) SHALL have tests.

---

## 4. Out of scope (v1)
- Classifying *what code* a coding agent writes.
- Fixing upstream APM preview semantics, `mcp.trust_transitive` wiring, or signed SLSA/sigstore install attestations.
- Production HA / multi-region gateway (single PEP is intentional and a known SPOF).
- Mandatory cloud IdP (Entra is an optional adapter stub only).

## 5. Open questions for review
1. **Grant model** for `ask`/`four-eyes`: single-use per (agent, tool, args) vs time-boxed session grant — confirm default.
2. **Tier source of truth**: tiers in Rego only, or a thin `policy/opa/tiers.yml` data document loaded into OPA?
3. **CLI vs web UI** for approvals in v1 — CLI first, web UI optional?
4. **Upstream license wording** (MIT vs Apache-2.0) — reconcile before any public claim (see note at top).
5. **`apm` CLI availability in CI** — is a pinned published version usable, or do we build from this fork's `src/apm_cli`?
