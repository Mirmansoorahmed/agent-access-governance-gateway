# Design — Agent Access Governance Gateway

**Status:** draft for review · aligns with [`docs/DESIGN.md`](../../../docs/DESIGN.md) and `docs/architecture-v2.png` (to be placed by Mir).
**Companion:** [`requirements.md`](./requirements.md) · [`tasks.md`](./tasks.md).

---

## 1. Overview

Two enforcement points, one policy:

- **Install/CI plane (upstream, unchanged):** `apm.yml` → `apm.lock.yaml`, gated by `apm-policy.yml` via `apm install` and `apm audit --ci`.
- **Runtime plane (this fork):** a PEP (MCP proxy) between the AI agent and MCP servers that loads the **same** effective `apm-policy.yml` + `apm.lock.yaml` and decides every `tools/call` via OPA.

Grounding against the fork: `src/apm_cli/policy/schema.py` confirms the policy model has `mcp.allow/deny`, transport rules, and `trust_transitive` (parsed, not enforced) but **no identity/runtime fields** — so OIDC group checks, drift pins, and approval tiers are genuinely additive and must live outside the upstream schema (in Rego + gateway state), not by editing `ApmPolicy`.

---

## 2. Architecture

```
                 ┌──────────────── Install/CI plane (UPSTREAM, unchanged) ────────────────┐
  developer ──▶  apm.yml ──apm install──▶ apm.lock.yaml ──apm audit --ci --policy──▶ CI gate
  security  ──▶  apm-policy.yml  (effective policy via tighten-only inheritance merge)
                 └──────────────────────────────┬─────────────────────────────────────────┘
                                                 │ read-only (same files)
                                                 ▼
  AI agent ──MCP tools/call──▶ ┌─────────────── GATEWAY (PEP, fork) ───────────────┐ ──▶ MCP server(s)
                               │ 1 tool approved?  (policy allowlist, deny wins)   │
   OIDC token (Keycloak) ────▶ │ 2 group allowed?  (OPA/Rego on role/dept/sen.)    │
                               │ 3 description unchanged?  (SHA-256 drift pin)     │
                               │ 4 approval tier?  allow|ask|deny|4eyes|break-glass │
                               └───────────────┬───────────────────┬──────────────┘
                                               │ decision span      │ queue (ask/4eyes/bg)
                                               ▼                     ▼
                                   OTel collector (local)   Approval CLI / web UI
                                               │
                                               ▼
                         reports/  ── Inventory · Access · Blocked · Approvals · Audit Summary (MD + PDF)
```

Fail-closed boundaries: if policy/lockfile/OPA cannot be loaded or reached, the gateway denies (R2.3). Decision order is fixed: identity → policy allowlist → group (OPA) → drift pin → tier (see §5).

---

## 3. Components & directory layout

All fork code is isolated (R13.1):

```
gateway/                 # Python MCP proxy / PEP
  __init__.py
  proxy.py               # streamable-HTTP MCP server + upstream client
  policy_loader.py       # read-only bridge to apm_cli.policy (effective merge + lockfile)
  identity.py            # OIDC verify (Keycloak), claim extraction; Entra adapter stub
  opa_client.py          # PDP client (role/dept/seniority -> allow + tier)
  drift.py               # canonicalise tool (name+description+input schema) -> SHA-256 pin
  pins.py                # pin store (approved hashes), explicit reset only
  tiers.py               # tier resolution + queue routing
  approvals.py           # ask / four-eyes / break-glass state machine
  evidence.py            # OpenTelemetry span emission + arg redaction
  errors.py              # structured MCP errors with machine-readable reason codes
  config.py
policy/opa/              # Rego PDP
  access.rego            # group -> allowed tools
  tiers.rego             # tool/risk -> tier
  data/*.json|yml        # synthetic group/tool mappings (Northwind Advisory)
reports/                 # five report generators (MD + PDF)
demo/                    # make demo assets + synthetic MCP servers + apm manifests
eval/                    # attack + benign suites, runner, results/ (timestamp + SHA)
```

Minimal upstream hooks: `gateway/policy_loader.py` imports from `apm_cli.policy` (parser, inheritance, matcher) **read-only**. No edits to `src/apm_cli/**`.

---

## 4. Data model

### 4.1 Decision record (one per call; basis for OTel span + reports)
| Field | Notes |
|---|---|
| `decision_id` | uuid |
| `ts` | RFC3339 |
| `agent_id` | caller subject from OIDC |
| `claims` | `{role, department, seniority, groups[]}` (summary, not raw token) |
| `server`, `tool` | target |
| `tier` | allow\|ask\|deny\|four-eyes\|break-glass |
| `decision` | allow\|deny\|pending\|granted\|rejected |
| `reason` | code (see §6) |
| `pin_hash` | SHA-256 of approved tool shape |
| `live_hash` | SHA-256 of live tool shape (for drift) |
| `policy_version`, `lockfile_sha` | provenance |
| `approvers` | list of `{id, ts, justification?}` |
| `args_redacted` | shape/hash only; never raw sensitive args (R9.2) |

### 4.2 Drift pin store (`gateway/pins`)
`{server, tool} -> {pin_hash, approved_by, approved_at, policy_version}`. Append-only; reset is an explicit, recorded approval action.

### 4.3 OPA input / output contract
Input: `{agent:{role,department,seniority,groups}, server, tool}`.
Output: `{allow: bool, tier: "allow|ask|deny|four-eyes|break-glass", reason: string}`.

### 4.4 Effective policy (read-only, from upstream)
Loaded via `apm_cli.policy` inheritance merge → `ApmPolicy` with `mcp.allow/deny`, transports. Lockfile pins from `apm.lock.yaml` (`name`, `content_hash`, `version`).

---

## 5. Request flow (the four checks)

```
on tools/call(server, tool, args, token):
  policy, lock = policy_loader.effective()        # R2; fail-closed on error
  claims       = identity.verify(token)           # R4.3 deny identity-invalid
  # Check 1 — tool approved (deny wins)           # R3
  if matcher.denied(policy.mcp, server, tool):            deny(policy-deny)
  if policy.mcp.allow is None or not matcher.allowed(...): deny(no-allowlist)   # fail-closed
  # Check 2 — group allowed + tier (single OPA eval)      # R4 + R6
  opa = opa_client.eval(claims, server, tool)
  if not opa.allow:                                        deny(group-denied)
  # Check 3 — description drift pin               # R5
  live = drift.hash(live_catalogue[server][tool])
  if live != pins.get(server, tool):                       deny(description-drift)
  # Check 4 — approval tier                        # R6
  match opa.tier:
    allow       -> allow()
    deny        -> deny(tier-deny)
    ask         -> enqueue(1); wait_or_timeout()           # approval-timeout on expiry
    four-eyes   -> enqueue(2 distinct);  wait_or_timeout()
    break-glass -> allow_with_justification(); mark high-severity
  # always
  evidence.emit(decision_record)                   # R9
```

OPA is queried once and returns both `allow` and `tier` (§4.3) to avoid two round-trips.

---

## 6. Reason codes (machine-readable)
`policy-load-failed`, `identity-invalid`, `policy-deny`, `no-allowlist`, `group-denied`, `description-drift`, `tier-deny`, `approval-timeout`, `approval-rejected`, `allow`, `break-glass-granted`. These are the join key between gateway decisions, OTel spans, and the Blocked Activity / Approvals reports.

---

## 7. Identity (OIDC)
- **Lab default:** Keycloak in docker-compose; realm with synthetic Northwind users carrying `role`, `department`, `seniority`, `groups`.
- Gateway validates JWT signature/issuer/audience/expiry; extracts claims.
- **Entra adapter stub:** interface-compatible module + Terraform/docs placeholder; never required to run the lab (R4.5). No cloud call on the default path.

## 8. Policy & OPA
- `policy/opa/access.rego` maps `(role, department, seniority, groups) → allowed (server, tool)`; `tiers.rego` maps `(server, tool|risk class) → tier`.
- Synthetic mappings live in `policy/opa/data/`.
- Upstream `apm-policy.yml` stays the allowlist/deny source of truth (Check 1); OPA adds the identity + tier layer it cannot express. Open question (requirements §5.2): keep tiers purely in Rego vs a thin `tiers` data doc — leaning data doc for reviewability.

## 9. Fork hygiene & license
- No edits to `src/apm_cli/**`; only read-only imports from `apm_cli.policy`.
- **License wording to reconcile:** `DESIGN.md`/steering say upstream is MIT; the checked-in fork is **Apache-2.0** (`LICENSE`, `apm.yml`) with CC-BY-4.0 docs and historical MIT in `NOTICE` (`CONTRIBUTING.md`). Keep provided docs verbatim; add a reconciliation note before any public README license claim. Preserve upstream copyright/notices in substantial portions regardless.
- Track `upstream/main`; pin APM CLI version in CI (R12.3).

## 10. Threat notes
| Threat | Mitigation | Residual |
|---|---|---|
| Install-gate bypass (tool present, not approved) | Runtime Check 1 deny-wins + no-allowlist fail-closed | Direct server access that skips the gateway — out of scope; document that the gateway must be the only path |
| Tool poisoning (description/schema changed post-approval) | Check 3 drift pin, explicit reset only | Malicious server-side behaviour with an unchanged description — needs runtime monitoring/human review (DESIGN §10) |
| Privilege misuse (wrong role/dept/seniority) | Check 2 OPA group mapping | IdP mis-provisioning — out of scope; synthetic lab realm |
| Risky action without human sign-off | Check 4 ask/four-eyes/break-glass + queue | Approver fatigue; timeout → deny |
| Break-glass abuse | Mandatory justification, high-severity evidence, Approvals report | Post-hoc only by design |
| Evidence tampering / arg leakage | Redact args (hash/shape), append-only decision log | Collector-side retention is lab-local |
| Fail-open on dependency outage | Fail-closed on policy/lockfile/OPA load/reach failure | Availability trade-off (single PEP SPOF, accepted v1) |

## 11. Testing strategy (summary; detail in tasks.md)
- **Unit:** drift canonicalisation + hashing; reason-code mapping; tier state machine; four-eyes distinct-identity rule; arg redaction.
- **OPA:** `opa test` on `access.rego`/`tiers.rego` with synthetic data for allow/deny/each tier.
- **Integration:** gateway + stub MCP server + Keycloak + OPA through the §5 flow for each attack + benign path.
- **Eval smoke:** runner executes suites, asserts expected decisions, writes results with timestamp + git SHA.
- **CI:** pinned `apm audit --ci` + the above; `make demo` exercised.

## 12. Alignment check vs `docs/DESIGN.md`
Covers DESIGN §4 additions 1–7, §5 comparison rows, §7 five reports, §8 ten-minute demo, §9 planned metrics (no numbers until a committed eval run), §10 limits. Any divergence surfaced as a requirements §5 open question.
