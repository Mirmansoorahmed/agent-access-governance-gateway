# Agent Access Governance Gateway

A fork of [microsoft/apm](https://github.com/microsoft/apm) that adds a **runtime
Access Governance Gateway** on top of APM's install-time governance. **One policy,
two enforcement points:** the same `apm-policy.yml` + `apm.lock.yaml` that gate
`apm install` / `apm audit --ci` are re-read by a runtime Policy Enforcement
Point that decides **every MCP `tools/call`**.

> Portfolio / lab project. Synthetic data only; fictional firm **Northwind
> Advisory**. Built on and crediting [microsoft/apm](https://github.com/microsoft/apm)
> (**Apache-2.0** software · **CC-BY-4.0** docs; historical MIT in [`NOTICE`](NOTICE)).
> The upstream APM README is preserved at
> [`docs/UPSTREAM-README.md`](docs/UPSTREAM-README.md). Full design:
> [`docs/DESIGN.md`](docs/DESIGN.md).

## Problem

APM governs *what gets installed*; it is explicitly **not a runtime sandbox** and
has no schema for the calling agent's identity. So after a tool is approved and
installed, nothing checks *who* calls it, whether its description changed, or
whether a sensitive call needs a human. This fork adds that runtime layer without
touching upstream APM code (`src/apm_cli/**` is imported read-only).

## APM (upstream) vs this fork

| Capability | APM (upstream) | This fork |
|---|---|---|
| Install-time dependency/MCP allowlist (`apm-policy.yml`) | ✅ | ✅ (unchanged, reused) |
| CI gate (`apm audit --ci`) | ✅ | ✅ (run in fork CI) |
| **Runtime per-call enforcement** of `tools/call` | ❌ (not a runtime sandbox) | ✅ Policy Enforcement Point |
| **OIDC group checks** (role / department / seniority) | ❌ (no identity in schema) | ✅ via OPA (Keycloak default) |
| **Live tool-description drift** detection | ❌ (install-time file hashes only) | ✅ SHA-256 pin per approved tool |
| **Approval tiers** `allow`/`ask`/`deny` | ❌ | ✅ |
| **Four-eyes** (two distinct approvers) | ❌ | ✅ sequential or one-shot |
| **Break-glass** (justified emergency) | ❌ | ✅ flagged high-severity |
| **Evidence** per decision | lockfile + SARIF | ✅ OpenTelemetry span (args redacted) |
| **Auditor reports** (MD + PDF) | ❌ | ✅ 5 reports, derived from evidence |

Check order on every call (all must pass to auto-allow; **fails closed** if
policy, lockfile, or OPA can't be loaded):

```
  apm.yml ──install──▶ apm.lock.yaml ──apm audit --ci──▶ CI gate     (UPSTREAM, unchanged)
  apm-policy.yml  ─────────────── same policy, read-only ───────────────┐
                                                                        ▼
  AI agent ──MCP tools/call──▶  GATEWAY (PEP)  ──▶ MCP server          (THIS FORK)
                                 1 tool approved? (allowlist, deny wins)
      OIDC (Keycloak) ────────▶  2 group allowed? (OPA: role/dept/seniority)
                                 3 description unchanged? (SHA-256 pin)
                                 4 approval tier? allow|ask|deny|four-eyes|break-glass
                                        │                     │
                                        ▼                     ▼
                              OTel evidence log      approval CLI (grants)
                                        │
                                        ▼
                       reports: inventory · access · blocked · approvals · audit summary (MD + PDF)
```

## How to run

```bash
# Offline demo (no Docker): run the 10-minute Northwind scenario, write evidence,
# render Markdown reports. PDF needs the optional extra: pip install '.[reports]'.
make demo

# Reports (Markdown + PDF) from a demo/eval run's evidence
make reports

# Eval harness (measured metrics). Offline reference PDP:
make eval
# Authoritative, OPA-backed run (needs OPA 1.22.3):
make eval-opa

# Full lab: OPA + Keycloak + OTel collector + gateway
docker compose -f demo/docker-compose.yml up

# Tests (offline; OPA-backed tests skip cleanly without the opa binary)
make gateway-test
```

## Results

| Metric | Value |
|---|---|
| Block rate (attack suite) | *planned — to be measured* |
| Benign false-block rate (golden path) | *planned — to be measured* |
| Gateway overhead p50 / p95 (allow path) | *planned — to be measured* |

Numbers are published **only** from a committed eval-harness run
(`eval/results/*.json`, stamped with timestamp + git SHA) — never hand-entered.
Run `make eval-opa` to produce the authoritative file, then fill this table from
it.

## Limitations

- Lab/portfolio design: synthetic MCP servers and data; not a production product.
- Does not classify *what code* an agent writes (separate compliance track).
- Does not fix upstream APM preview semantics, `mcp.trust_transitive` wiring, or
  signed install attestations.
- Heuristic description lint is narrow; a clean description with malicious
  server-side behaviour still needs runtime monitoring + human review.
- Single gateway is a deliberate PEP and a single point of failure; HA is out of
  scope for v1.
- Keycloak is the default IdP; Entra is an optional adapter stub, not required.
- The **Audit Summary** maps controls to ISO/IEC 42001 Annex A themes and EU AI
  Act Art. 12 / 14 **illustratively** — not a conformity claim.

## Credit & license

Built on [microsoft/apm](https://github.com/microsoft/apm) — all upstream APM
behaviour, docs, and the preserved [`docs/UPSTREAM-README.md`](docs/UPSTREAM-README.md)
are Microsoft's work. This fork follows upstream licensing: **Apache-2.0** for
software ([`LICENSE`](LICENSE)), **CC-BY-4.0** for general documentation
([`LICENSE-DOCS`](LICENSE-DOCS)); previously published MIT releases remain under
their original terms, retained in [`NOTICE`](NOTICE). Upstream copyright and
notices are preserved in all substantial portions.
