"""Read-only bridge to the effective APM policy and lockfile.

This module is the *only* place the gateway reaches into upstream APM, and it
does so read-only (never mutating ``apm.yml`` / ``apm-policy.yml`` /
``apm.lock.yaml`` or any ``apm_cli`` code path).

Design constraint: the gateway must be unit-testable without network access,
but ``apm_cli.policy`` transitively imports networked dependencies (``requests``
etc.). So the loader is split:

* ``EffectivePolicy`` / ``LockfilePin`` -- small, dependency-free value objects
  the rest of the gateway consumes.
* ``ApmCliPolicyBackend`` -- the real adapter that calls
  ``apm_cli.policy`` to compute the effective (inheritance-merged) policy and
  parse the lockfile. Imported lazily so importing this module never drags in
  ``apm_cli``'s dependencies.
* ``load_effective_policy`` -- fails **closed**: any load/parse error raises
  :class:`GatewayDenied` with ``policy-load-failed`` so the proxy denies.

Check 1 (tool-approved) reuses upstream glob semantics via
``apm_cli.policy.matcher`` when available; a dependency-free fallback mirrors the
same ``*`` / ``**`` rules for offline tests. The fallback is kept byte-for-byte
consistent with upstream by a contract test (see tests).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache

from .errors import GatewayDenied, Reason


@dataclass(frozen=True)
class McpAllowlist:
    """The subset of ``apm-policy.yml`` ``mcp:`` the runtime PEP needs.

    ``allow=None`` means "no opinion" in the upstream install-time schema. At
    *runtime* the gateway treats ``None`` as deny-by-default (fail-closed); see
    :meth:`decision` and requirements R3.3.
    """

    allow: tuple[str, ...] | None = None
    deny: tuple[str, ...] = ()

    def decision(self, server_tool: str) -> tuple[bool, Reason]:
        """Return the Check-1 decision for a ``server/tool`` identifier.

        Deny wins. Then, if ``allow`` is ``None`` -> deny-by-default at runtime.
        Then allow-list membership decides.
        """
        if _first_match(server_tool, self.deny) is not None:
            return False, Reason.POLICY_DENY
        if self.allow is None:
            return False, Reason.NO_ALLOWLIST
        if _first_match(server_tool, self.allow) is not None:
            return True, Reason.ALLOW
        return False, Reason.NO_ALLOWLIST


@dataclass(frozen=True)
class LockfilePin:
    """One ``apm.lock.yaml`` entry the gateway treats as read-only input."""

    name: str
    version: str = ""
    content_hash: str = ""


@dataclass(frozen=True)
class EffectivePolicy:
    """Dependency-free snapshot the gateway consumes."""

    mcp: McpAllowlist = field(default_factory=McpAllowlist)
    lockfile_pins: tuple[LockfilePin, ...] = ()
    policy_version: str = ""
    lockfile_sha: str = ""


# --------------------------------------------------------------------------
# Glob matching -- dependency-free, mirrors apm_cli.policy.matcher semantics:
#   ``*``  matches within a single segment (no ``/``)
#   ``**`` matches any depth (including ``/``)
# --------------------------------------------------------------------------
@lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern:
    parts = re.split(r"(\*\*|\*)", pattern)
    regex = ""
    for part in parts:
        if part == "**":
            regex += ".*"
        elif part == "*":
            regex += "[^/]*"
        else:
            regex += re.escape(part)
    return re.compile(f"^{regex}$")


def matches_pattern(value: str, pattern: str) -> bool:
    """Match *value* against a single policy glob *pattern*."""
    if not pattern or not value:
        return False
    if value == pattern:
        return True
    return bool(_compile(pattern).match(value))


def _first_match(value: str, patterns: tuple[str, ...] | None) -> str | None:
    for pattern in patterns or ():
        if matches_pattern(value, pattern):
            return pattern
    return None


# --------------------------------------------------------------------------
# Real backend (lazy import so this module stays dependency-free to import)
# --------------------------------------------------------------------------
class ApmCliPolicyBackend:
    """Compute the effective policy + lockfile pins from upstream ``apm_cli``.

    All imports are lazy and local so merely importing ``gateway.policy_loader``
    never pulls in ``apm_cli``'s networked dependencies. Used in CI / real labs
    where those dependencies are installed.
    """

    def __init__(self, project_dir: str = ".") -> None:
        self.project_dir = project_dir

    def load(self) -> EffectivePolicy:  # pragma: no cover - requires apm_cli deps
        from apm_cli.policy.discovery import discover_policy_with_chain
        from apm_cli.policy.inheritance import merge_policies

        chain = discover_policy_with_chain(self.project_dir)
        merged = merge_policies(chain) if chain else None
        mcp = McpAllowlist(
            allow=tuple(merged.mcp.allow) if merged and merged.mcp.allow is not None else None,
            deny=tuple(merged.mcp.deny) if merged else (),
        )
        return EffectivePolicy(
            mcp=mcp,
            lockfile_pins=self._lockfile_pins(),
            policy_version=getattr(merged, "version", "") if merged else "",
        )

    def _lockfile_pins(self) -> tuple[LockfilePin, ...]:  # pragma: no cover
        import os

        import yaml

        path = os.path.join(self.project_dir, "apm.lock.yaml")
        if not os.path.exists(path):
            return ()
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        pins = []
        for dep in data.get("dependencies", []) or []:
            pins.append(
                LockfilePin(
                    name=dep.get("name", ""),
                    version=str(dep.get("version", "")),
                    content_hash=dep.get("content_hash", ""),
                )
            )
        return tuple(pins)


def load_effective_policy(backend) -> EffectivePolicy:
    """Load the effective policy via *backend*, failing **closed**.

    Any exception from the backend becomes a :class:`GatewayDenied` with
    ``policy-load-failed`` so the proxy denies every call (requirements R2.3).
    *backend* is any object exposing ``load() -> EffectivePolicy``.
    """
    try:
        policy = backend.load()
    except Exception as exc:  # fail closed on *any* load/parse error
        raise GatewayDenied(Reason.POLICY_LOAD_FAILED, str(exc)) from exc
    if not isinstance(policy, EffectivePolicy):
        raise GatewayDenied(Reason.POLICY_LOAD_FAILED, "backend did not return an EffectivePolicy")
    return policy
