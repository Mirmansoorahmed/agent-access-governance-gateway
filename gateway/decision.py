"""The runtime decision pipeline -- the four checks in fixed order.

This is the heart of the PEP. It is transport-agnostic so it can be unit-tested
in-process (the HTTP proxy in ``proxy.py`` is a thin shell over it). The order
(design.md 5) is fixed:

    identity -> Check 1 (policy allowlist, deny wins)
             -> Check 2 (group allowed, via PDP)
             -> Check 3 (description drift pin)
             -> Check 4 (approval tier)

Fail closed: a missing policy / PDP error / unverifiable identity denies.
Approval tiers (ask / four-eyes / break-glass) are delegated to an injected
approval gate (built out in task 8); this module resolves ``allow`` and
``deny`` tiers directly and asks the gate for the rest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from .drift import pin_for_tool
from .errors import GatewayDenied, Reason
from .identity import Claims, TokenVerifier
from .opa_client import OpaDecision, OpaInput, Pdp
from .pins import PinStore
from .policy_loader import EffectivePolicy


@dataclass(frozen=True)
class CallContext:
    """One tool-call request as seen by the gateway."""

    server: str
    tool: str
    arguments: dict = field(default_factory=dict)
    token: str = ""


@dataclass
class Decision:
    """The resolved decision for a call (basis for the evidence span)."""

    allowed: bool
    reason: Reason
    tier: str = ""
    pin_hash: str = ""
    live_hash: str = ""
    claims: Claims | None = None
    detail: str = ""


# Tiers that need a human before the call may proceed.
_HUMAN_TIERS = {"ask", "four-eyes", "break-glass"}


class ApprovalGate(Protocol):
    """Resolves human-approval tiers into a terminal :class:`Decision`.

    Implemented fully in task 8. ``decide`` receives the already-computed
    context (claims, tier, pin) and returns the final decision after the
    human workflow (or a timeout/rejection denial).
    """

    def decide(self, ctx: CallContext, claims: Claims, tier: str, pin_hash: str) -> Decision: ...


class _DenyAllApprovalGate:
    """Default gate used until task 8: any human tier denies (fail-closed).

    This keeps the pipeline safe and testable before the approval state machine
    exists -- an ``ask``/``four-eyes``/``break-glass`` call is never silently
    allowed.
    """

    def decide(self, ctx: CallContext, claims: Claims, tier: str, pin_hash: str) -> Decision:
        return Decision(
            allowed=False,
            reason=Reason.APPROVAL_REJECTED,
            tier=tier,
            pin_hash=pin_hash,
            claims=claims,
            detail="approval gate not configured",
        )


@dataclass
class DecisionEngine:
    """Runs the four checks for a call and returns a :class:`Decision`.

    All collaborators are injected so the engine is fully unit-testable offline:
    ``verifier`` (identity), ``pdp`` (Check 2 + tier), ``pin_store`` (Check 3),
    ``catalogue`` (live ``tools/list`` provider), and ``approval_gate``.
    """

    policy: EffectivePolicy
    verifier: TokenVerifier
    pdp: Pdp
    pin_store: PinStore
    # callable(server) -> list[tool dict] : the live catalogue for drift checks
    catalogue: object
    approval_gate: ApprovalGate = field(default_factory=_DenyAllApprovalGate)

    def decide(self, ctx: CallContext) -> Decision:
        # 0. Identity (deny identity-invalid).
        try:
            claims = self.verifier.verify(ctx.token)
        except GatewayDenied as denied:
            return _deny(denied.reason, detail=denied.detail)

        server_tool = f"{ctx.server}/{ctx.tool}"

        # 1. Tool approved? (policy allowlist, deny wins; allow=None -> deny.)
        ok, reason = self.policy.mcp.decision(server_tool)
        if not ok:
            return _deny(reason, claims=claims)

        # 2. Group allowed? + tier (single PDP evaluation).
        try:
            opa: OpaDecision = self.pdp.evaluate(
                OpaInput(
                    role=claims.role,
                    department=claims.department,
                    seniority=claims.seniority,
                    groups=claims.groups,
                    server=ctx.server,
                    tool=ctx.tool,
                )
            )
        except Exception as exc:  # fail closed on any PDP error
            return _deny(Reason.POLICY_LOAD_FAILED, claims=claims, detail=f"pdp error: {exc}")

        tier = opa.tier
        if not opa.allow:
            return _deny(Reason.GROUP_DENIED, tier=tier, claims=claims, detail=opa.reason)

        # 3. Description unchanged? (drift pin).
        live_tool = self._find_live_tool(ctx.server, ctx.tool)
        if live_tool is None:
            return _deny(
                Reason.DESCRIPTION_DRIFT,
                tier=tier,
                claims=claims,
                detail="tool absent from live catalogue",
            )
        live_hash = pin_for_tool(live_tool)
        pinned = self.pin_store.get(ctx.server, ctx.tool)
        if pinned is None or pinned != live_hash:
            return Decision(
                allowed=False,
                reason=Reason.DESCRIPTION_DRIFT,
                tier=tier,
                pin_hash=pinned or "",
                live_hash=live_hash,
                claims=claims,
                detail="unpinned tool" if pinned is None else "pin mismatch",
            )

        # 4. Approval tier.
        if tier == "deny":
            return _deny(Reason.TIER_DENY, tier=tier, pin_hash=pinned, claims=claims)
        if tier == "allow":
            return Decision(
                allowed=True,
                reason=Reason.ALLOW,
                tier=tier,
                pin_hash=pinned,
                live_hash=live_hash,
                claims=claims,
            )
        if tier in _HUMAN_TIERS:
            return self.approval_gate.decide(ctx, claims, tier, pinned)
        # Unknown tier -> fail closed.
        return _deny(
            Reason.TIER_DENY,
            tier=tier,
            pin_hash=pinned,
            claims=claims,
            detail=f"unknown tier: {tier}",
        )

    def _find_live_tool(self, server: str, tool: str) -> dict | None:
        for entry in self.catalogue.list_tools(server):
            if entry.get("name") == tool:
                return entry
        return None


def _deny(
    reason: Reason,
    *,
    tier: str = "",
    pin_hash: str = "",
    claims: Claims | None = None,
    detail: str = "",
) -> Decision:
    return Decision(
        allowed=False,
        reason=reason,
        tier=tier,
        pin_hash=pin_hash,
        claims=claims,
        detail=detail,
    )
