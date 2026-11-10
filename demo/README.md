# Demo — Northwind Advisory (10-minute scenario)

Two ways to run the DESIGN.md §8 story:

## Offline (no Docker) — `make demo`
Runs the five stages in-process against the gateway and writes evidence to
`.gateway/` (spans, approvals, pins), then renders the reports:

```
make demo      # runs demo/scenario.py, then make reports
```

Stages:
1. **Unapproved MCP** — `research` is outside `apm-policy.yml` allow (`apm audit --ci` fails the PR).
2. **Onboard** — lint + attack smoke + four-eyes → a policy-PR diff adding `research/*`.
3. **Runtime allow** — an advisor calls the approved `crm/lookup_client`; the OTel span shows `allow`.
4. **Drift** — the tool description changes after approval → blocked (`description-drift`).
5. **Wrong group** — an analyst lacking the `advisors` group is denied (`group-denied`).

## Full lab (Docker) — `docker compose`
```
docker compose -f demo/docker-compose.yml up
```
Brings up OPA 1.22.3, Keycloak (synthetic `northwind` realm), an OpenTelemetry
collector, and the gateway (built from this fork's own `src/apm_cli` + the
gateway). Keycloak is the default IdP; Entra is an optional adapter and is not
required.

> All data is synthetic. Fictional firm: **Northwind Advisory**. No employer
> branding. Report metrics come only from a committed eval-harness run, never
> hand-entered.
