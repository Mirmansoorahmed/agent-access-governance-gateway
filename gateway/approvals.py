"""Human-approval tiers and the grant/queue state machine (task 8).

Tiers ``ask`` / ``four-eyes`` / ``break-glass`` require a human before the call
proceeds. The gateway call path is synchronous, so approval is decoupled:

* When a human-tier call arrives, the gateway looks for a matching **grant**.
  A grant is minted out-of-band by an approver (CLI, task 9) and is:
    - keyed by ``(agent, tool, args_hash)`` -- scoped to one agent, one tool,
      one argument set;
    - **single-use** -- consumed on first matching call;
    - **TTL-bounded** -- expires a short time after issue (decision: single-use
      per (agent, tool, args-hash), consumed on first use, short TTL).
* If no valid grant exists, the call is denied *now* and a **pending request**
  is enqueued so an approver can act. A subsequent retry (after a grant is
  minted) succeeds. If the pending request is never granted within its window,
  it expires -> the retry path reports ``approval-timeout``.

Approval-tier rules enforced here:
* ``ask``        -- one approver grant.
* ``four-eyes``  -- the grant must carry **two distinct** approver identities.
* ``break-glass``-- the grant must carry a non-empty justification; the decision
  is flagged high-severity for post-hoc review (reason ``break-glass-granted``).

All grants/denials are recorded (approver ids, timestamps, justification) for the
evidence log and the Approvals report (tasks 10/11).
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field

from .decision import ApprovalGate, CallContext, Decision
from .errors import Reason
from .identity import Claims

DEFAULT_GRANT_TTL_SECONDS = 300  # 5 minutes
DEFAULT_PENDING_TTL_SECONDS = 900  # 15 minutes


def args_hash(arguments: dict) -> str:
    """Stable hash of a call's arguments (scopes a grant to one arg set)."""
    canonical = json.dumps(arguments or {}, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _now() -> float:
    return time.time()


@dataclass
class Grant:
    """A human-approved, single-use, TTL-bounded authorization for one call."""

    agent: str
    server: str
    tool: str
    args_hash: str
    tier: str
    approvers: tuple[str, ...]
    created_at: float
    ttl_seconds: int
    justification: str = ""
    consumed: bool = False

    def is_expired(self, now: float | None = None) -> bool:
        now = now if now is not None else _now()
        return now > self.created_at + self.ttl_seconds

    def is_valid(self, now: float | None = None) -> bool:
        return not self.consumed and not self.is_expired(now)


@dataclass
class PendingRequest:
    """A queued request awaiting a human decision."""

    agent: str
    server: str
    tool: str
    args_hash: str
    tier: str
    created_at: float
    ttl_seconds: int

    def is_expired(self, now: float | None = None) -> bool:
        now = now if now is not None else _now()
        return now > self.created_at + self.ttl_seconds


class ApprovalError(Exception):
    """Raised for invalid approval operations (e.g. four-eyes misuse)."""


@dataclass
class ApprovalStore:
    """Thread-safe in-memory store of pending requests and grants.

    Keyed by ``(agent, server, tool, args_hash)``. A JSON path may be supplied
    to persist across processes so the CLI (a separate process) and the gateway
    share state in the lab.
    """

    grant_ttl: int = DEFAULT_GRANT_TTL_SECONDS
    pending_ttl: int = DEFAULT_PENDING_TTL_SECONDS
    path: str | None = None
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _grants: dict[tuple, Grant] = field(default_factory=dict)
    _pending: dict[tuple, PendingRequest] = field(default_factory=dict)
    # Partial four-eyes approvals: key -> {"approvers": [...], "justification": str}.
    _partial: dict[tuple, dict] = field(default_factory=dict)
    # Append-only decision log for the Approvals report.
    log: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._load()

    @staticmethod
    def key(agent: str, server: str, tool: str, ah: str) -> tuple:
        return (agent, server, tool, ah)

    # --- persistence --------------------------------------------------------
    def _load(self) -> None:
        if not self.path:
            return
        from pathlib import Path

        p = Path(self.path)
        if not p.exists():
            return
        data = json.loads(p.read_text(encoding="utf-8"))
        for entry in data.get("grants", []):
            g = Grant(**entry)
            self._grants[self.key(g.agent, g.server, g.tool, g.args_hash)] = g
        for entry in data.get("pending", []):
            r = PendingRequest(**entry)
            self._pending[self.key(r.agent, r.server, r.tool, r.args_hash)] = r
        for entry in data.get("partial", []):
            k = self.key(entry["agent"], entry["server"], entry["tool"], entry["args_hash"])
            self._partial[k] = {
                "approvers": list(entry.get("approvers", [])),
                "justification": entry.get("justification", ""),
                "tier": entry.get("tier", "four-eyes"),
            }
        self.log = list(data.get("log", []))

    def _flush(self) -> None:
        if not self.path:
            return
        from dataclasses import asdict
        from pathlib import Path

        p = Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "grants": [asdict(g) for g in self._grants.values()],
            "pending": [asdict(r) for r in self._pending.values()],
            "partial": [
                {
                    "agent": k[0],
                    "server": k[1],
                    "tool": k[2],
                    "args_hash": k[3],
                    "approvers": v["approvers"],
                    "justification": v.get("justification", ""),
                    "tier": v.get("tier", "four-eyes"),
                }
                for k, v in self._partial.items()
            ],
            "log": self.log,
        }
        p.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    # --- queue --------------------------------------------------------------
    def enqueue(self, agent: str, server: str, tool: str, ah: str, tier: str) -> PendingRequest:
        with self._lock:
            req = PendingRequest(agent, server, tool, ah, tier, _now(), self.pending_ttl)
            self._pending[self.key(agent, server, tool, ah)] = req
            self._flush()
            return req

    def pending(self) -> list[PendingRequest]:
        with self._lock:
            return [r for r in self._pending.values() if not r.is_expired()]

    def get_pending(self, agent: str, server: str, tool: str, ah: str) -> PendingRequest | None:
        with self._lock:
            req = self._pending.get(self.key(agent, server, tool, ah))
            if req is None or req.is_expired():
                return None
            return req

    def pending_state(self, agent: str, server: str, tool: str, ah: str) -> str:
        """Return 'none' | 'active' | 'expired' for a queued request."""
        with self._lock:
            req = self._pending.get(self.key(agent, server, tool, ah))
            if req is None:
                return "none"
            return "expired" if req.is_expired() else "active"

    # --- grants -------------------------------------------------------------
    def grant(
        self,
        agent: str,
        server: str,
        tool: str,
        ah: str,
        tier: str,
        approvers: tuple[str, ...],
        justification: str = "",
    ) -> Grant:
        """Mint a grant, enforcing per-tier approver rules."""
        self._check_tier_rules(tier, approvers, justification)
        with self._lock:
            grant = Grant(
                agent=agent,
                server=server,
                tool=tool,
                args_hash=ah,
                tier=tier,
                approvers=tuple(approvers),
                created_at=_now(),
                ttl_seconds=self.grant_ttl,
                justification=justification,
            )
            self._grants[self.key(agent, server, tool, ah)] = grant
            self._pending.pop(self.key(agent, server, tool, ah), None)
            self.log.append(
                {
                    "event": "grant",
                    "agent": agent,
                    "server": server,
                    "tool": tool,
                    "args_hash": ah,
                    "tier": tier,
                    "approvers": list(approvers),
                    "justification": justification,
                    "ts": grant.created_at,
                }
            )
            self._flush()
            return grant

    def approve(
        self,
        agent: str,
        server: str,
        tool: str,
        ah: str,
        tier: str,
        approver: str,
        justification: str = "",
    ) -> Grant | None:
        """Sequential approval: accumulate distinct approvers until the tier is met.

        - ``ask`` / ``break-glass``: a single ``approve`` mints the grant.
        - ``four-eyes``: the first approver is recorded as partial; a second,
          **distinct** approver completes and mints the grant. A repeat approval
          from the same identity does not count twice.

        Returns the :class:`Grant` once minted, else ``None`` while still partial.
        The one-command :meth:`grant` form remains available for a batch decision.
        """
        if not approver:
            raise ApprovalError("approve requires an approver id")
        with self._lock:
            if tier != "four-eyes":
                return self.grant(
                    agent,
                    server,
                    tool,
                    ah,
                    tier,
                    approvers=(approver,),
                    justification=justification,
                )
            key = self.key(agent, server, tool, ah)
            state = self._partial.setdefault(
                key, {"approvers": [], "justification": "", "tier": "four-eyes"}
            )
            if justification and not state["justification"]:
                state["justification"] = justification
            if approver not in state["approvers"]:
                state["approvers"].append(approver)
                self.log.append(
                    {
                        "event": "approve",
                        "agent": agent,
                        "server": server,
                        "tool": tool,
                        "args_hash": ah,
                        "tier": tier,
                        "approver": approver,
                        "ts": _now(),
                    }
                )
            if len(state["approvers"]) >= 2:
                approvers = tuple(state["approvers"])
                justification = state["justification"]
                del self._partial[key]
                self._flush()
                return self.grant(
                    agent,
                    server,
                    tool,
                    ah,
                    tier,
                    approvers=approvers,
                    justification=justification,
                )
            self._flush()
            return None

    def partial_approvers(self, agent: str, server: str, tool: str, ah: str) -> tuple[str, ...]:
        """Return approvers recorded so far for an in-progress four-eyes flow."""
        with self._lock:
            state = self._partial.get(self.key(agent, server, tool, ah))
            return tuple(state["approvers"]) if state else ()

    def reject(
        self, agent: str, server: str, tool: str, ah: str, approver: str, reason: str = ""
    ) -> None:
        with self._lock:
            self._pending.pop(self.key(agent, server, tool, ah), None)
            self._partial.pop(self.key(agent, server, tool, ah), None)
            self.log.append(
                {
                    "event": "reject",
                    "agent": agent,
                    "server": server,
                    "tool": tool,
                    "args_hash": ah,
                    "approver": approver,
                    "reason": reason,
                    "ts": _now(),
                }
            )
            self._flush()

    def consume_valid_grant(self, agent: str, server: str, tool: str, ah: str) -> Grant | None:
        """Return and consume a valid matching grant, or ``None``."""
        with self._lock:
            key = self.key(agent, server, tool, ah)
            grant = self._grants.get(key)
            if grant is None or not grant.is_valid():
                return None
            grant.consumed = True
            self.log.append(
                {
                    "event": "consume",
                    "agent": agent,
                    "server": server,
                    "tool": tool,
                    "args_hash": ah,
                    "tier": grant.tier,
                    "ts": _now(),
                }
            )
            self._flush()
            return grant

    @staticmethod
    def _check_tier_rules(tier: str, approvers: tuple[str, ...], justification: str) -> None:
        if tier == "four-eyes":
            distinct = set(approvers)
            if len(distinct) < 2:
                raise ApprovalError("four-eyes requires two distinct approver identities")
        elif tier == "break-glass":
            if not justification.strip():
                raise ApprovalError("break-glass requires a justification")
            if not approvers:
                raise ApprovalError("break-glass requires at least one approver")
        elif not approvers:  # ask (and any single-approver tier)
            raise ApprovalError("a grant requires at least one approver")


@dataclass
class QueueingApprovalGate(ApprovalGate):
    """ApprovalGate backed by an :class:`ApprovalStore`.

    On a human-tier call: consume a matching valid grant -> allow (break-glass is
    flagged ``break-glass-granted``). Otherwise enqueue a pending request and
    deny now; if a pending request for this call previously expired, report
    ``approval-timeout`` instead of ``approval-rejected``.
    """

    store: ApprovalStore

    def decide(self, ctx: CallContext, claims: Claims, tier: str, pin_hash: str) -> Decision:
        agent = claims.subject
        ah = args_hash(ctx.arguments)
        grant = self.store.consume_valid_grant(agent, ctx.server, ctx.tool, ah)
        if grant is not None:
            reason = Reason.BREAK_GLASS_GRANTED if tier == "break-glass" else Reason.ALLOW
            return Decision(
                allowed=True,
                reason=reason,
                tier=tier,
                pin_hash=pin_hash,
                claims=claims,
                detail="; ".join(grant.approvers),
            )

        # No valid grant -- decide based on the queued request's state.
        state = self.store.pending_state(agent, ctx.server, ctx.tool, ah)
        if state == "expired":
            # A request was queued but never decided in time (R6.7).
            return Decision(
                allowed=False,
                reason=Reason.APPROVAL_TIMEOUT,
                tier=tier,
                pin_hash=pin_hash,
                claims=claims,
                detail="approval window elapsed",
            )
        if state == "none":
            # First time we see this call: enqueue for a human and deny for now.
            self.store.enqueue(agent, ctx.server, ctx.tool, ah, tier)
        # Active (either just enqueued or still awaiting a decision).
        return Decision(
            allowed=False,
            reason=Reason.APPROVAL_REJECTED,
            tier=tier,
            pin_hash=pin_hash,
            claims=claims,
            detail="awaiting approval",
        )
