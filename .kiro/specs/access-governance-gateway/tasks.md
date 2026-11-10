# Tasks — Agent Access Governance Gateway

**Status:** draft for review · **do not start until Mir says go.**
Companion: [`requirements.md`](./requirements.md) · [`design.md`](./design.md).
Each task names the requirement(s) it satisfies and its test hook. Prefer small, testable slices. No invented metrics; README numbers only from a committed eval run.

---

- [ ] 1. Scaffold fork-only dirs and read-only policy bridge
  - Create `gateway/`, `policy/opa/`, `reports/`, `demo/`, `eval/` with package skeletons; no edits under `src/apm_cli/**`.
  - Implement `gateway/policy_loader.py` importing `apm_cli.policy` (parser, inheritance, matcher) read-only to return effective `ApmPolicy` + `apm.lock.yaml` pins.
  - _Test:_ loader returns merged policy for a fixture repo; raises/flags on malformed policy (drives fail-closed in task 3).
  - _Requirements: R2.1, R2.2, R13.1_

- [ ] 2. Drift pin: canonicalise + hash + pin store
  - `gateway/drift.py`: deterministic canonicalisation of `name + description + input schema` → SHA-256.
  - `gateway/pins.py`: append-only pin store; explicit, recorded reset only (no auto-reset).
  - _Test:_ identical-shape/different-serialisation inputs hash equal (no false-block); changed description hashes differently; auto-reset is impossible.
  - _Requirements: R5.1, R5.3, R5.4_

- [ ] 3. Gateway core: MCP streamable-HTTP proxy + fail-closed
  - `gateway/proxy.py`: accept `tools/list` and `tools/call` over streamable HTTP; forward to upstream MCP server; record live catalogue on `tools/list`.
  - Wire the fixed check order from design §5; `gateway/errors.py` structured MCP errors with reason codes (§6).
  - Fail closed when policy/lockfile/OPA unavailable.
  - _Test:_ allow path forwards unchanged; load failure denies all with `policy-load-failed`; `tools/list` populates drift input without blocking.
  - _Requirements: R1.1, R1.2, R1.3, R1.4, R1.5, R2.3, R2.4_

- [ ] 4. Check 1 — policy allowlist (deny wins, fail-closed)
  - Implement allow/deny matching via `apm_cli.policy.matcher`; `None` allow → deny-by-default with `reason=no-allowlist`.
  - _Test:_ deny match blocks; non-match-under-allow blocks; `None` allow blocks; allowed tool passes.
  - _Requirements: R3.1, R3.2, R3.3, R3.4_

- [ ] 5. Identity — OIDC verify + claim extraction (+ Entra stub)
  - `gateway/identity.py`: JWT validation (issuer/aud/exp/signature) against Keycloak; extract `role/department/seniority/groups`. Entra adapter stub, not required to run.
  - _Test:_ valid token → claims; invalid/expired/missing-claim → deny `identity-invalid`; lab path runs with no cloud IdP.
  - _Requirements: R4.1, R4.3, R4.5_

- [ ] 6. OPA PDP — access + tier Rego
  - `policy/opa/access.rego` (group → allowed tools) and `tiers.rego` (tool/risk → tier) with synthetic `data/`; single eval returns `{allow, tier, reason}`.
  - `gateway/opa_client.py`: PDP client used for Check 2 and tier resolution.
  - _Test:_ `opa test` covers allow/deny + each tier; client maps absent `allow` → deny `group-denied`.
  - _Requirements: R4.2, R4.4, R6.1_

- [ ] 7. Check 3 — drift enforcement in flow
  - Compare live tool hash to pin on each call; mismatch → deny `description-drift`; no implicit reset.
  - _Test:_ pinned-match passes; post-approval description change blocks.
  - _Requirements: R5.2_

- [ ] 8. Check 4 — approval tiers + approval state machine
  - `gateway/tiers.py` + `gateway/approvals.py`: route `allow|deny|ask|four-eyes|break-glass`; four-eyes requires two distinct approver ids; break-glass requires justification + high-severity mark; timeout → deny `approval-timeout`.
  - _Test:_ each tier path; four-eyes rejects same-identity second approval; timeout denies; break-glass records justification.
  - _Requirements: R6.2, R6.3, R6.4, R6.5, R6.6, R6.7_

- [ ] 9. Approval interface (CLI first; web UI optional)
  - CLI to list queue and grant/deny; grant scoped to one (agent, tool, args) single-use by default (document any broader model); record approver id/ts/decision/justification.
  - _Test:_ grant releases the matching queued call; deny blocks it; records written to evidence; four-eyes enforced end-to-end.
  - _Requirements: R7.1, R7.2, R7.3, R7.4_

- [ ] 10. Evidence — OpenTelemetry spans + redaction
  - `gateway/evidence.py`: one span per decision (design §4.1 fields); redact full args (hash/shape only); export to local OTel collector; compose service for collector.
  - _Test:_ span emitted per decision with reason/tier/pin; raw sensitive args never present; collector path has no cloud dependency.
  - _Requirements: R9.1, R9.2, R9.3_

- [ ] 11. Reports — five generators (Markdown + PDF)
  - `reports/`: Tool Inventory, Access by Group, Blocked Activity, Approvals, Audit Summary. Derive only from evidence/lockfile/policy. Audit Summary = illustrative ISO 42001 Annex A + EU AI Act Art. 12/14 mapping with explicit non-conformity disclaimer.
  - _Test:_ each report parses committed evidence into expected rows; no hand-entered numbers; disclaimer present; MD and PDF produced.
  - _Requirements: R10.1, R10.2, R10.3, R10.4_

- [ ] 12. Onboarding flow
  - Request → run linter + attack-suite smoke → four-eyes → open/update a PR that amends `apm-policy.yml` (never silent on-disk edit). Document happy path in README/demo.
  - _Test:_ request triggers smoke; approval produces a policy-amending PR diff; rejection produces none.
  - _Requirements: R8.1, R8.2, R8.3, R8.4_

- [ ] 13. Eval harness + persisted results
  - `eval/`: attack suite (unapproved tool, wrong group, drift/poisoning, risky-without-approval, break-glass misuse) + benign golden path; runner asserts expected decisions and measures block rate, benign false-block rate, overhead p50/p95; persist results with timestamp + git SHA.
  - _Test:_ smoke run asserts expected decision per case; benign path not false-blocked; results file carries timestamp + SHA.
  - _Requirements: R11.1, R11.2, R11.3, R11.4, R11.5_

- [ ] 14. Demo + synthetic environment
  - `demo/` + docker-compose (gateway, OPA, Keycloak realm, OTel collector, synthetic MCP servers, Northwind fixtures). `make demo` runs the DESIGN §8 script: unapproved PR fails CI → onboard → allow → drift blocks → wrong group denies → show report.
  - _Test:_ `make demo` reaches each stage with expected decisions; data is synthetic; no employer branding.
  - _Requirements: R12.1, R13.2_

- [ ] 15. CI (GitHub Actions)
  - Workflow runs pinned `apm audit --ci` + unit/integration/OPA tests + eval smoke.
  - _Test:_ CI green on a clean branch; unapproved-MCP fixture fails `apm audit --ci`.
  - _Requirements: R12.2, R12.3, R13.5_

- [ ] 16. README + license reconciliation (skimmable ~3 min)
  - README: problem → diagram (`docs/architecture-v2.png`) → how to run → results table ("planned / to be measured" until a committed eval run) → limitations.
  - Reconcile the MIT-vs-Apache-2.0 upstream wording (requirements §5.4 / design §9) before any public license claim; preserve upstream notices.
  - _Test:_ README has no unmeasured numbers; links resolve; license statement matches the repo's actual `LICENSE`/`NOTICE`.
  - _Requirements: R11.5, R13.2, R13.3, R13.4_

---

## Cross-cutting (apply to every task)
- No edits under `src/apm_cli/**` beyond read-only imports (R13.1).
- Synthetic data only; firm = **Northwind Advisory**; no employer branding (R13.2).
- Commits carry no AI attribution / no `Co-authored-by` (R13.3).
- Every check has tests before it is considered done (R13.5).
- Resolve requirements §5 open questions with Mir before the tasks they gate (grant model → task 9; tier source → task 6; CLI/UI → task 9; license → task 16; apm-in-CI → task 15).
