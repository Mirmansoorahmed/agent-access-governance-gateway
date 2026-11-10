"""Shared test factories for gateway unit tests."""

from __future__ import annotations

from gateway.decision import DecisionEngine
from gateway.identity import Claims, HmacTokenVerifier, StaticVerifier
from gateway.opa_client import LocalPdp
from gateway.pins import PinStore
from gateway.policy_loader import EffectivePolicy, McpAllowlist
from gateway.upstream import InMemoryUpstream

TEST_SECRET = b"test-secret-key"

# A representative Northwind Advisory synthetic tool.
TOOL = {
    "name": "lookup_client",
    "description": "Look up a client record by id.",
    "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
}


def make_upstream(server: str = "crm", tool: dict | None = None) -> InMemoryUpstream:
    up = InMemoryUpstream()
    up.set_catalogue(server, [tool or TOOL])
    return up


def make_engine(
    *,
    server: str = "crm",
    tool: dict | None = None,
    allow: tuple[str, ...] | None = ("crm/*",),
    deny: tuple[str, ...] = (),
    access_groups: tuple[str, ...] = ("advisors",),
    tier: str = "allow",
    pin: bool = True,
    verifier=None,
    upstream: InMemoryUpstream | None = None,
    approval_gate=None,
):
    """Build a DecisionEngine with injectable, deterministic collaborators."""
    tool = tool or TOOL
    upstream = upstream or make_upstream(server, tool)
    pin_store = PinStore()
    if pin:
        from gateway.drift import pin_for_tool

        pin_store.set_pin(server, tool["name"], pin_for_tool(tool), approved_by="sec")

    pdp = LocalPdp(
        access={(server, tool["name"]): access_groups},
        tiers={(server, tool["name"]): tier},
        default_tier="deny",
    )
    verifier = verifier or HmacTokenVerifier(secret=TEST_SECRET)
    kwargs = {}
    if approval_gate is not None:
        kwargs["approval_gate"] = approval_gate
    return DecisionEngine(
        policy=EffectivePolicy(mcp=McpAllowlist(allow=allow, deny=deny)),
        verifier=verifier,
        pdp=pdp,
        pin_store=pin_store,
        catalogue=upstream,
        **kwargs,
    )


def valid_token(
    *,
    subject: str = "u1",
    role: str = "advisor",
    department: str = "advisory",
    seniority: str = "senior",
    groups: tuple[str, ...] = ("advisors",),
) -> str:
    return HmacTokenVerifier(secret=TEST_SECRET).mint(
        {
            "sub": subject,
            "role": role,
            "department": department,
            "seniority": seniority,
            "groups": list(groups),
        }
    )


def static_verifier(token: str, claims: Claims) -> StaticVerifier:
    return StaticVerifier(tokens={token: claims})
