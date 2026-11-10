"""Policy Decision Point (PDP) client -- pluggable OPA adapter.

The gateway asks the PDP two things in one evaluation (design.md 4.3):
  * ``allow``  -- may this caller (role/department/seniority/groups) use this
    (server, tool)?  [Check 2]
  * ``tier``   -- the approval tier for this call: allow|ask|deny|four-eyes|
    break-glass.  [Check 4]

Two implementations behind the :class:`Pdp` protocol:

* :class:`SubprocessOpaPdp` -- shells out to a real ``opa`` binary
  (``opa eval``) against ``policy/opa/*.rego`` + ``tiers.yml`` data. Used by the
  maintainer (OPA 1.22.3) and in CI, which installs the static OPA binary. Tests
  that require it are marked and skip cleanly when ``opa`` is absent (see
  ``gateway/tests/opa_support.py``).
* :class:`LocalPdp` -- a dependency-free reference evaluator with the *same*
  decision contract, so the gateway and its offline tests run without OPA. A
  parity test asserts Local and OPA agree on shared cases when ``opa`` exists.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class OpaInput:
    """Input document sent to the PDP."""

    role: str = ""
    department: str = ""
    seniority: str = ""
    groups: tuple[str, ...] = ()
    server: str = ""
    tool: str = ""

    def to_dict(self) -> dict:
        return {
            "agent": {
                "role": self.role,
                "department": self.department,
                "seniority": self.seniority,
                "groups": list(self.groups),
            },
            "server": self.server,
            "tool": self.tool,
        }


@dataclass(frozen=True)
class OpaDecision:
    """PDP output document."""

    allow: bool = False
    tier: str = "deny"
    reason: str = ""


class Pdp(Protocol):
    """Policy Decision Point surface used for Check 2 + tier resolution."""

    def evaluate(self, opa_input: OpaInput) -> OpaDecision: ...


# --------------------------------------------------------------------------
# Local reference evaluator (dependency-free; mirrors the Rego contract)
# --------------------------------------------------------------------------
@dataclass
class LocalPdp:
    """In-process PDP driven by the same data shape as the Rego data document.

    ``access`` maps a ``(server, tool)`` to the set of groups allowed to call
    it. ``tiers`` maps a ``(server, tool)`` to an approval tier (default tier
    applies when unlisted). This mirrors ``policy/opa/tiers.yml`` +
    ``access.rego`` so Local and OPA stay in lockstep.
    """

    # (server, tool) -> allowed group names
    access: dict[tuple[str, str], tuple[str, ...]] = field(default_factory=dict)
    # (server, tool) -> tier
    tiers: dict[tuple[str, str], str] = field(default_factory=dict)
    default_tier: str = "deny"

    @classmethod
    def from_data(cls, data: dict) -> LocalPdp:
        """Build from the loaded ``tiers.yml``/access data mapping.

        Expected shape::

            access:
              - {server: s, tool: t, groups: [g1, g2]}
            tiers:
              - {server: s, tool: t, tier: ask}
            default_tier: deny
        """
        access: dict[tuple[str, str], tuple[str, ...]] = {}
        for row in data.get("access", []) or []:
            access[(row["server"], row["tool"])] = tuple(row.get("groups", []))
        tiers: dict[tuple[str, str], str] = {}
        for row in data.get("tiers", []) or []:
            tiers[(row["server"], row["tool"])] = row["tier"]
        return cls(access=access, tiers=tiers, default_tier=data.get("default_tier", "deny"))

    def evaluate(self, opa_input: OpaInput) -> OpaDecision:
        key = (opa_input.server, opa_input.tool)
        allowed_groups = self.access.get(key)
        tier = self.tiers.get(key, self.default_tier)
        if allowed_groups is None:
            return OpaDecision(allow=False, tier=tier, reason="no access rule for tool")
        caller_groups = set(opa_input.groups)
        if caller_groups & set(allowed_groups):
            return OpaDecision(allow=True, tier=tier, reason="group match")
        return OpaDecision(allow=False, tier=tier, reason="caller not in allowed groups")


# --------------------------------------------------------------------------
# Real OPA adapter (subprocess; used by maintainer + CI)
# --------------------------------------------------------------------------
def opa_available() -> bool:
    """True when an ``opa`` binary is on PATH."""
    return shutil.which("opa") is not None


@dataclass
class SubprocessOpaPdp:
    """Evaluate decisions by invoking the real ``opa`` binary.

    ``query`` must yield a document shaped like :class:`OpaDecision`
    (``{allow, tier, reason}``). Raises on binary/eval failure so the caller
    (gateway pipeline) can fail closed.
    """

    bundle_dir: str | Path
    data_files: tuple[str, ...] = ()
    query: str = "data.access_governance.decision"
    opa_bin: str = "opa"

    def evaluate(self, opa_input: OpaInput) -> OpaDecision:
        cmd = [self.opa_bin, "eval", "--format", "json", "--stdin-input"]
        cmd += ["--data", str(self.bundle_dir)]
        for data_file in self.data_files:
            cmd += ["--data", str(data_file)]
        cmd += [self.query]
        proc = subprocess.run(
            cmd,
            input=json.dumps(opa_input.to_dict()),
            capture_output=True,
            text=True,
            check=True,
        )
        payload = json.loads(proc.stdout)
        value = payload["result"][0]["expressions"][0]["value"]
        return OpaDecision(
            allow=bool(value.get("allow", False)),
            tier=str(value.get("tier", "deny")),
            reason=str(value.get("reason", "")),
        )
