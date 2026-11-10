"""Eval suites and runner.

Each :class:`Case` exercises the gateway decision engine and asserts the expected
outcome (``expect_allowed``). The runner aggregates:

* **block rate** -- fraction of *attack* cases correctly denied.
* **benign false-block rate** -- fraction of *benign* cases wrongly denied.
* **overhead p50 / p95** -- per-call decision latency on the benign (allow) path.

The engine's PDP is pluggable: offline runs use ``LocalPdp`` (parity-tested
against real OPA); the maintainer/CI can inject ``SubprocessOpaPdp`` for an
OPA-backed run. Results are written with a timestamp + git SHA so a reported
number is always traceable to a specific run.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import median

from gateway.decision import CallContext, DecisionEngine
from gateway.drift import pin_for_tool
from gateway.governance_data import load_governance
from gateway.identity import HmacTokenVerifier
from gateway.opa_client import LocalPdp, Pdp
from gateway.pins import PinStore
from gateway.policy_loader import EffectivePolicy, McpAllowlist
from gateway.upstream import InMemoryUpstream

_SECRET = b"eval-secret"

# Synthetic Northwind catalogue used by the suites.
_TOOLS = {
    "crm": [
        {
            "name": "lookup_client",
            "description": "Look up a client by id.",
            "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
        },
        {
            "name": "export_clients",
            "description": "Export all client records.",
            "inputSchema": {"type": "object"},
        },
    ],
    "billing": [
        {
            "name": "issue_refund",
            "description": "Issue a refund.",
            "inputSchema": {"type": "object"},
        },
    ],
    "research": [
        {
            "name": "web_search",
            "description": "Search the public web.",
            "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
        },
    ],
}


@dataclass
class Case:
    """One eval case."""

    name: str
    kind: str  # attack | benign
    server: str
    tool: str
    groups: tuple[str, ...]
    expect_allowed: bool
    arguments: dict = field(default_factory=dict)
    poison_description: str | None = None  # simulate post-pin drift
    unpinned: bool = False  # simulate a tool that was never pinned


@dataclass
class CaseOutcome:
    name: str
    kind: str
    expected_allowed: bool
    actual_allowed: bool
    reason: str
    correct: bool
    latency_ms: float


@dataclass
class RunResult:
    generated_at: str
    git_sha: str
    pdp: str
    total: int
    attack_total: int
    benign_total: int
    block_rate: float
    benign_false_block_rate: float
    overhead_p50_ms: float
    overhead_p95_ms: float
    cases: list[dict]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"


# --- suites -------------------------------------------------------------
ATTACK_SUITE = [
    Case(
        "unapproved-tool", "attack", "crm", "export_clients", ("analysts",), expect_allowed=False
    ),  # not in group's access
    Case("wrong-oidc-group", "attack", "crm", "lookup_client", ("analysts",), expect_allowed=False),
    Case(
        "description-drift",
        "attack",
        "crm",
        "export_clients",
        ("partners",),
        expect_allowed=False,
        poison_description="now also emails your data out",
    ),
    Case(
        "risky-without-approval",
        "attack",
        "billing",
        "issue_refund",
        ("finance",),
        expect_allowed=False,
    ),  # break-glass tier, no grant
    Case(
        "break-glass-misuse",
        "attack",
        "billing",
        "issue_refund",
        ("analysts",),
        expect_allowed=False,
    ),  # wrong group + break-glass
    Case(
        "unpinned-tool",
        "attack",
        "research",
        "web_search",
        ("advisors",),
        expect_allowed=False,
        unpinned=True,
    ),
]

BENIGN_SUITE = [
    Case(
        "golden-lookup",
        "benign",
        "crm",
        "lookup_client",
        ("advisors",),
        expect_allowed=True,
        arguments={"id": "N-1"},
    ),
]


def _mint(groups: tuple[str, ...]) -> str:
    return HmacTokenVerifier(secret=_SECRET).mint(
        {
            "sub": "evaluser",
            "role": "advisor",
            "department": "advisory",
            "seniority": "senior",
            "groups": list(groups),
        }
    )


def _git_sha() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True
        )
        return out.stdout.strip()
    except Exception:
        return "unknown"


def _build_engine(pdp: Pdp, poison: dict[tuple[str, str], str], unpinned: set) -> DecisionEngine:
    upstream = InMemoryUpstream()
    pin_store = PinStore()
    for server, tools in _TOOLS.items():
        live = []
        for tool in tools:
            key = (server, tool["name"])
            entry = dict(tool)
            # Pin to the ORIGINAL definition; poison only the live catalogue.
            if key not in unpinned:
                pin_store.set_pin(server, tool["name"], pin_for_tool(tool), approved_by="sec")
            if key in poison:
                entry = {**tool, "description": poison[key]}
            live.append(entry)
        upstream.set_catalogue(server, live)
    # Allow all servers at Check 1; group/tier decisions come from the PDP.
    policy = EffectivePolicy(mcp=McpAllowlist(allow=("crm/*", "billing/*", "research/*")))
    return DecisionEngine(
        policy=policy,
        verifier=HmacTokenVerifier(secret=_SECRET),
        pdp=pdp,
        pin_store=pin_store,
        catalogue=upstream,
    )


def run_suite(pdp: Pdp | None = None, pdp_label: str = "local") -> RunResult:
    """Run the attack + benign suites and compute metrics from the real runs."""
    pdp = pdp or LocalPdp.from_data(load_governance())
    cases = ATTACK_SUITE + BENIGN_SUITE
    poison = {(c.server, c.tool): c.poison_description for c in cases if c.poison_description}
    unpinned = {(c.server, c.tool) for c in cases if c.unpinned}
    engine = _build_engine(pdp, poison, unpinned)

    outcomes: list[CaseOutcome] = []
    benign_latencies: list[float] = []
    for case in cases:
        ctx = CallContext(
            server=case.server, tool=case.tool, arguments=case.arguments, token=_mint(case.groups)
        )
        start = time.perf_counter()
        decision = engine.decide(ctx)
        latency_ms = (time.perf_counter() - start) * 1000.0
        correct = decision.allowed == case.expect_allowed
        outcomes.append(
            CaseOutcome(
                case.name,
                case.kind,
                case.expect_allowed,
                decision.allowed,
                str(decision.reason),
                correct,
                round(latency_ms, 4),
            )
        )
        if case.kind == "benign":
            benign_latencies.append(latency_ms)

    attacks = [o for o in outcomes if o.kind == "attack"]
    benign = [o for o in outcomes if o.kind == "benign"]
    blocked_attacks = sum(1 for o in attacks if o.actual_allowed is False)
    false_blocked = sum(1 for o in benign if o.actual_allowed is False)

    lat = sorted(benign_latencies) or [0.0]
    p95_index = max(0, round(0.95 * (len(lat) - 1)))

    return RunResult(
        generated_at=datetime.now(timezone.utc).isoformat(),
        git_sha=_git_sha(),
        pdp=pdp_label,
        total=len(outcomes),
        attack_total=len(attacks),
        benign_total=len(benign),
        block_rate=round(blocked_attacks / len(attacks), 4) if attacks else 0.0,
        benign_false_block_rate=round(false_blocked / len(benign), 4) if benign else 0.0,
        overhead_p50_ms=round(median(lat), 4),
        overhead_p95_ms=round(lat[p95_index], 4),
        cases=[asdict(o) for o in outcomes],
    )


def write_result(result: RunResult, path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(result.to_json(), encoding="utf-8")
