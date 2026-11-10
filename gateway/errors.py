"""Structured gateway errors with machine-readable reason codes.

Reason codes are the join key between gateway decisions, evidence spans, and the
Blocked Activity / Approvals reports. See design.md section 6.
"""

from __future__ import annotations

from enum import Enum


class Reason(str, Enum):
    """Machine-readable decision reason codes."""

    ALLOW = "allow"
    POLICY_LOAD_FAILED = "policy-load-failed"
    IDENTITY_INVALID = "identity-invalid"
    POLICY_DENY = "policy-deny"
    NO_ALLOWLIST = "no-allowlist"
    GROUP_DENIED = "group-denied"
    DESCRIPTION_DRIFT = "description-drift"
    TIER_DENY = "tier-deny"
    APPROVAL_TIMEOUT = "approval-timeout"
    APPROVAL_REJECTED = "approval-rejected"
    BREAK_GLASS_GRANTED = "break-glass-granted"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


# JSON-RPC / MCP error code used for a governance denial. -32000 is the start of
# the JSON-RPC "server error" implementation-defined range.
GOVERNANCE_DENIED_CODE = -32001


class GatewayDenied(Exception):
    """Raised when the gateway denies a tool call.

    Carries a :class:`Reason` so callers (proxy, evidence, reports) share one
    vocabulary instead of free-text messages.
    """

    def __init__(self, reason: Reason, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else str(reason))

    def to_mcp_error(self) -> dict:
        """Render a structured MCP/JSON-RPC error object."""
        return {
            "code": GOVERNANCE_DENIED_CODE,
            "message": f"access denied by governance gateway: {self.reason}",
            "data": {"reason": str(self.reason), "detail": self.detail},
        }
