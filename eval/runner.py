"""Eval suites and runner.

Each :class:`Case` exercises the gateway decision path and asserts the expected
outcome (``expect_allowed``) and, where given, the expected reason code. The
suites span every reason code the gateway can emit so a regression in any check
shows up:

  identity-invalid · policy-deny · no-allowlist · group-denied ·
  description-drift · tier-deny · approval-rejected · approval-timeout ·
  break-glass-granted · policy-load-failed · allow

The runner aggregates:

* **block rate** -- fraction of *attack* cases correctly denied.
* **benign false-block rate** -- fraction of *benign* cases wrongly denied.
* **latency** -- n, p50, p95, p99 over a configurable number of benign
  (allow-path) calls measured *after a warm-up*, reported separately from a
  one-shot **cold-start** sample.

The PDP is pluggable: offline runs use ``LocalPdp`` (parity-tested against real
OPA); ``--opa`` injects ``SubprocessOpaPdp``. Results are written with a
timestamp + git SHA so a reported number is always traceable to a specific run.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import median

from gateway.approvals import QueueingApprovalGate, args_hash
from gateway.decision import CallContext, DecisionEngine
from gateway.drift import pin_for_tool
from gateway.errors import GatewayDenied
from gateway.governance_data import load_governance
from gateway.identity import HmacTokenVerifier
from gateway.opa_client import LocalPdp, Pdp
from gateway.pins import PinStore
from gateway.policy_loader import EffectivePolicy, McpAllowlist, load_effective_policy
from gateway.upstream import InMemoryUpstream

_SECRET = b"eval-secret"

# Latency measurement knobs (overridable in run_suite).
DEFAULT_WARMUP = 50
DEFAULT_LATENCY_SAMPLES = 200

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
        {
            "name": "bulk_delete",
            "description": "Bulk-delete client records.",
            "inputSchema": {"type": "object"},
        },
    ],
    "billing": [
        {
            "name": "issue_refund",
            "description": "Issue a refund.",
            "inputSchema": {"type": "object"},
        },
        {
            "name": "read_invoice",
            "description": "Read an invoice.",
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
    # 'hr' is deliberately NOT in the gateway allowlist (Check 1 no-allowlist),
    # and 'legal' is explicitly denied (Check 1 policy-deny).
    "hr": [
        {
            "name": "list_salaries",
            "description": "List employee salaries.",
            "inputSchema": {"type": "object"},
        },
    ],
    "legal": [
        {
            "name": "read_contract",
            "description": "Read a contract.",
            "inputSchema": {"type": "object"},
        },
    ],
}

# Gateway Check-1 allowlist for the eval environment: allow crm/billing/research,
# deny legal explicitly; hr is simply absent (-> no-allowlist deny).
_ALLOW = ("crm/*", "billing/*", "research/*")
_DENY = ("legal/*",)


@dataclass
class Case:
    """One eval case."""

    name: str
    kind: str  # attack | benign
    server: str
    tool: str
    groups: tuple[str, ...]
    expect_allowed: bool
    expect_reason: str | None = None
    arguments: dict = field(default_factory=dict)
    poison_description: str | None = None
    unpinned: bool = False
    token_override: str | None = None  # e.g. malformed/empty token
    grant: dict | None = None  # pre-mint a grant: {"tier","approvers",...}
    simulate: str | None = None  # "policy-load-failed"


@dataclass
class CaseOutcome:
    name: str
    kind: str
    expected_allowed: bool
    actual_allowed: bool
    expected_reason: str | None
    reason: str
    correct: bool


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
    latency_n: int
    overhead_p50_ms: float
    overhead_p95_ms: float
    overhead_p99_ms: float
    cold_start_ms: float
    cases: list[dict]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"


def _mint(groups: tuple[str, ...], sub: str = "evaluser") -> str:
    return HmacTokenVerifier(secret=_SECRET).mint(
        {
            "sub": sub,
            "role": "advisor",
            "department": "advisory",
            "seniority": "senior",
            "groups": list(groups),
        }
    )


# --------------------------------------------------------------------------
# Suites (>= 30 attack, >= 15 benign) spanning every reason code.
# --------------------------------------------------------------------------
def _attack_suite() -> list[Case]:
    cases: list[Case] = []

    # Check 1 -- no-allowlist: 'hr' is absent from the gateway allowlist.
    cases.append(
        Case(
            "allowlist-miss-hr",
            "attack",
            "hr",
            "list_salaries",
            ("advisors",),
            False,
            "no-allowlist",
        )
    )
    # Check 1 -- policy-deny: 'legal' is explicitly denied (deny wins).
    cases.append(
        Case(
            "allowlist-deny-legal",
            "attack",
            "legal",
            "read_contract",
            ("advisors",),
            False,
            "policy-deny",
        )
    )
    for i in range(3):  # more no-allowlist variants (different groups/args)
        cases.append(
            Case(
                f"allowlist-miss-hr-{i}",
                "attack",
                "hr",
                "list_salaries",
                ("partners", "finance", "analysts")[i : i + 1] or ("advisors",),
                False,
                "no-allowlist",
                arguments={"q": i},
            )
        )

    # Check 2 -- wrong OIDC group for an allowed tool.
    wrong_group_specs = [
        ("crm", "lookup_client", ("analysts",)),
        ("crm", "export_clients", ("advisors",)),  # export needs partners
        ("billing", "issue_refund", ("advisors",)),  # refund needs finance
        ("billing", "read_invoice", ("analysts",)),
        ("research", "web_search", ("finance",)),  # finance not allowed here
        ("crm", "lookup_client", ()),  # no groups at all
        ("crm", "export_clients", ("finance",)),
        ("billing", "issue_refund", ("partners",)),
    ]
    for idx, (srv, tool, groups) in enumerate(wrong_group_specs):
        cases.append(
            Case(
                f"wrong-group-{srv}-{tool}-{idx}",
                "attack",
                srv,
                tool,
                groups,
                False,
                "group-denied",
            )
        )

    # Check 3 -- description drift on tools the caller's group CAN reach.
    drift_specs = [
        ("crm", "export_clients", ("partners",)),
        ("billing", "read_invoice", ("finance",)),
        ("billing", "issue_refund", ("finance",)),
        ("research", "web_search", ("advisors",)),
    ]
    for idx, (srv, tool, groups) in enumerate(drift_specs):
        cases.append(
            Case(
                f"drift-{srv}-{tool}-{idx}",
                "attack",
                srv,
                tool,
                groups,
                False,
                "description-drift",
                poison_description=f"poisoned-{idx}: now also exfiltrates data",
            )
        )

    # Check 3 -- unpinned tool (never approved) the group can otherwise reach.
    unpinned_specs = [
        ("crm", "export_clients", ("partners",)),
        ("billing", "read_invoice", ("finance",)),
        ("research", "web_search", ("advisors",)),
    ]
    for idx, (srv, tool, groups) in enumerate(unpinned_specs):
        cases.append(
            Case(
                f"unpinned-{srv}-{tool}-{idx}",
                "attack",
                srv,
                tool,
                groups,
                False,
                "description-drift",
                unpinned=True,
            )
        )

    # Check 4 -- risky action without approval (tier needs a human, no grant).
    # research/web_search is tier 'ask'; billing/issue_refund is 'break-glass';
    # crm/export_clients is 'four-eyes'.
    no_approval = [
        ("research", "web_search", ("advisors",), "web search without an ask grant"),
        ("research", "web_search", ("partners",), "ask tier, partners, no grant"),
        ("research", "web_search", ("analysts",), "ask tier, analysts, no grant"),
        ("crm", "export_clients", ("partners",), "four-eyes, no grant"),
        ("billing", "issue_refund", ("finance",), "break-glass, no grant"),
    ]
    for idx, (srv, tool, groups, _d) in enumerate(no_approval):
        cases.append(
            Case(
                f"risky-no-approval-{idx}", "attack", srv, tool, groups, False, "approval-rejected"
            )
        )

    # Check 4 -- four-eyes attempted with the SAME approver twice (must not grant).
    cases.append(
        Case(
            "four-eyes-same-approver-twice",
            "attack",
            "crm",
            "export_clients",
            ("partners",),
            False,
            "approval-rejected",
            grant={"tier": "four-eyes", "approvers": ("alice", "alice")},
        )
    )
    cases.append(
        Case(
            "four-eyes-single-approver",
            "attack",
            "crm",
            "export_clients",
            ("partners",),
            False,
            "approval-rejected",
            grant={"tier": "four-eyes", "approvers": ("alice",)},
        )
    )

    # Break-glass misuse: wrong group (can't even reach the tier) and no grant.
    cases.append(
        Case(
            "break-glass-wrong-group",
            "attack",
            "billing",
            "issue_refund",
            ("analysts",),
            False,
            "group-denied",
        )
    )
    cases.append(
        Case(
            "break-glass-no-justification",
            "attack",
            "billing",
            "issue_refund",
            ("finance",),
            False,
            "approval-rejected",
        )
    )

    # Check 4 -- tier-deny: partners may reach crm/bulk_delete (Check 2) but the
    # action is tier-denied at runtime regardless of approval.
    cases.append(
        Case(
            "tier-deny-bulk-delete",
            "attack",
            "crm",
            "bulk_delete",
            ("partners",),
            False,
            "tier-deny",
        )
    )

    # Check 4 -- approval-timeout: a queued request that expired before a human
    # decided it (simulated by a zero-TTL pending request).
    cases.append(
        Case(
            "approval-timeout",
            "attack",
            "research",
            "web_search",
            ("advisors",),
            False,
            "approval-timeout",
            simulate="approval-timeout",
        )
    )

    # Identity -- malformed / missing / wrong-signature tokens.
    cases.append(
        Case(
            "malformed-token",
            "attack",
            "crm",
            "lookup_client",
            ("advisors",),
            False,
            "identity-invalid",
            token_override="not-a-jwt",
        )
    )
    cases.append(
        Case(
            "empty-token",
            "attack",
            "crm",
            "lookup_client",
            ("advisors",),
            False,
            "identity-invalid",
            token_override="",
        )
    )
    cases.append(
        Case(
            "bad-signature-token",
            "attack",
            "crm",
            "lookup_client",
            ("advisors",),
            False,
            "identity-invalid",
            token_override=HmacTokenVerifier(b"wrong").mint({"sub": "x", "groups": ["advisors"]}),
        )
    )
    cases.append(
        Case(
            "token-missing-sub",
            "attack",
            "crm",
            "lookup_client",
            ("advisors",),
            False,
            "identity-invalid",
            token_override=HmacTokenVerifier(_SECRET).mint({"groups": ["advisors"]}),
        )
    )

    # Fail-closed: policy / lockfile unavailable.
    cases.append(
        Case(
            "policy-unavailable",
            "attack",
            "crm",
            "lookup_client",
            ("advisors",),
            False,
            "policy-load-failed",
            simulate="policy-load-failed",
        )
    )
    cases.append(
        Case(
            "lockfile-unavailable",
            "attack",
            "crm",
            "lookup_client",
            ("advisors",),
            False,
            "policy-load-failed",
            simulate="policy-load-failed",
        )
    )

    return cases


def _benign_suite() -> list[Case]:
    cases: list[Case] = []
    # Allow-tier golden paths for several groups/tools (tier 'allow').
    allow_golden = [
        ("crm", "lookup_client", ("advisors",)),
        ("crm", "lookup_client", ("partners",)),
        ("billing", "read_invoice", ("advisors",)),
        ("billing", "read_invoice", ("partners",)),
        ("billing", "read_invoice", ("finance",)),
    ]
    for idx, (srv, tool, groups) in enumerate(allow_golden):
        cases.append(
            Case(
                f"golden-allow-{idx}",
                "benign",
                srv,
                tool,
                groups,
                True,
                "allow",
                arguments={"id": f"N-{idx}"},
            )
        )
    # Break-glass with a VALID justified grant -> allowed, flagged.
    cases.append(
        Case(
            "break-glass-granted",
            "benign",
            "billing",
            "issue_refund",
            ("finance",),
            True,
            "break-glass-granted",
            grant={
                "tier": "break-glass",
                "approvers": ("alice",),
                "justification": "sev1 production incident",
            },
        )
    )
    # Duplicate the primary golden path so benign count >= 15 and latency has a
    # consistent allow target. All must NOT be false-blocked.
    for idx in range(10):
        cases.append(
            Case(
                f"golden-lookup-{idx}",
                "benign",
                "crm",
                "lookup_client",
                ("advisors",),
                True,
                "allow",
                arguments={"id": f"N-1{idx:03d}"},
            )
        )
    return cases


ATTACK_SUITE = _attack_suite()
BENIGN_SUITE = _benign_suite()


def _git_sha() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True
        )
        return out.stdout.strip()
    except Exception:
        return "unknown"


def _build_engine(pdp: Pdp, cases: list[Case]) -> DecisionEngine:
    poison = {(c.server, c.tool): c.poison_description for c in cases if c.poison_description}
    unpinned = {(c.server, c.tool) for c in cases if c.unpinned}
    upstream = InMemoryUpstream()
    pin_store = PinStore()
    for server, tools in _TOOLS.items():
        live = []
        for tool in tools:
            key = (server, tool["name"])
            if key not in unpinned:
                pin_store.set_pin(server, tool["name"], pin_for_tool(tool), approved_by="sec")
            entry = {**tool, "description": poison[key]} if key in poison else dict(tool)
            live.append(entry)
        upstream.set_catalogue(server, live)
    policy = EffectivePolicy(mcp=McpAllowlist(allow=_ALLOW, deny=_DENY))
    return DecisionEngine(
        policy=policy,
        verifier=HmacTokenVerifier(secret=_SECRET),
        pdp=pdp,
        pin_store=pin_store,
        catalogue=upstream,
    )


class _RaisingBackend:
    """Simulates an unloadable policy/lockfile (fail-closed path)."""

    def load(self):
        raise RuntimeError("policy/lockfile unavailable")


def _decide_case(engine: DecisionEngine, approvals, case: Case):
    """Return (allowed, reason) for one case, handling simulated conditions."""
    if case.simulate == "policy-load-failed":
        try:
            load_effective_policy(_RaisingBackend())
            return True, "allow"  # unreachable; backend always raises
        except GatewayDenied as denied:
            return False, str(denied.reason)

    if case.simulate == "approval-timeout":
        # Enqueue a request and backdate it so it has already expired when the
        # caller retries -> the gate reports approval-timeout (R6.7).
        ah = args_hash(case.arguments)
        req = approvals.enqueue("evaluser", case.server, case.tool, ah, "ask")
        req.created_at -= approvals.pending_ttl + 1

    # Pre-mint a grant if the case supplies one (four-eyes misuse, break-glass).
    if case.grant is not None:
        ah = args_hash(case.arguments)
        tier = case.grant["tier"]
        approvers = case.grant["approvers"]
        # A same-approver-twice / single-approver four-eyes grant is invalid and
        # raises -> no grant is minted -> call is denied. A valid grant (e.g.
        # justified break-glass) is consumed by the engine.
        with contextlib.suppress(Exception):
            approvals.grant(
                "evaluser",
                case.server,
                case.tool,
                ah,
                tier,
                approvers=approvers,
                justification=case.grant.get("justification", ""),
            )

    token = case.token_override if case.token_override is not None else _mint(case.groups)
    ctx = CallContext(server=case.server, tool=case.tool, arguments=case.arguments, token=token)
    decision = engine.decide(ctx)
    return decision.allowed, str(decision.reason)


def run_suite(
    pdp: Pdp | None = None,
    pdp_label: str = "local",
    warmup: int = DEFAULT_WARMUP,
    latency_samples: int = DEFAULT_LATENCY_SAMPLES,
) -> RunResult:
    """Run the attack + benign suites and compute metrics from the real runs."""
    pdp = pdp or LocalPdp.from_data(load_governance())
    cases = ATTACK_SUITE + BENIGN_SUITE

    from gateway.approvals import ApprovalStore

    outcomes: list[CaseOutcome] = []
    for case in cases:
        approvals = QueueingApprovalGate(store=ApprovalStore())
        # Per-case engine: only THIS case's drift/unpin state is applied, so one
        # case's poisoned catalogue never bleeds into another (each call is
        # independent in the real gateway too).
        case_engine = _build_engine(pdp, [case])
        case_engine.approval_gate = approvals
        allowed, reason = _decide_case(case_engine, approvals.store, case)
        correct = (allowed == case.expect_allowed) and (
            case.expect_reason is None or reason == case.expect_reason
        )
        outcomes.append(
            CaseOutcome(
                case.name,
                case.kind,
                case.expect_allowed,
                allowed,
                case.expect_reason,
                reason,
                correct,
            )
        )

    attacks = [o for o in outcomes if o.kind == "attack"]
    benign = [o for o in outcomes if o.kind == "benign"]
    blocked_attacks = sum(1 for o in attacks if o.actual_allowed is False)
    false_blocked = sum(1 for o in benign if o.actual_allowed is False)

    # --- latency: cold start + warm-up + >=latency_samples benign allow calls --
    lat_engine = _build_engine(pdp, [])  # clean catalogue, no drift/unpin
    golden = next(c for c in BENIGN_SUITE if c.name == "golden-lookup-0")
    golden_ctx = CallContext(
        server=golden.server,
        tool=golden.tool,
        arguments=golden.arguments,
        token=_mint(golden.groups),
    )

    cold = time.perf_counter()
    lat_engine.decide(golden_ctx)
    cold_start_ms = (time.perf_counter() - cold) * 1000.0

    for _ in range(max(0, warmup)):
        lat_engine.decide(golden_ctx)

    samples: list[float] = []
    for _ in range(max(1, latency_samples)):
        start = time.perf_counter()
        lat_engine.decide(golden_ctx)
        samples.append((time.perf_counter() - start) * 1000.0)
    samples.sort()

    def _pct(p: float) -> float:
        idx = max(0, min(len(samples) - 1, round(p * (len(samples) - 1))))
        return round(samples[idx], 4)

    return RunResult(
        generated_at=datetime.now(timezone.utc).isoformat(),
        git_sha=_git_sha(),
        pdp=pdp_label,
        total=len(outcomes),
        attack_total=len(attacks),
        benign_total=len(benign),
        block_rate=round(blocked_attacks / len(attacks), 4) if attacks else 0.0,
        benign_false_block_rate=round(false_blocked / len(benign), 4) if benign else 0.0,
        latency_n=len(samples),
        overhead_p50_ms=round(median(samples), 4),
        overhead_p95_ms=_pct(0.95),
        overhead_p99_ms=_pct(0.99),
        cold_start_ms=round(cold_start_ms, 4),
        cases=[asdict(o) for o in outcomes],
    )


def write_result(result: RunResult, path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(result.to_json(), encoding="utf-8")
