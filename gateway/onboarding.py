"""Onboarding flow: request -> lint + attack smoke -> four-eyes -> policy PR (task 12).

A developer requests a new MCP server/tool. The flow:

1. **Lint** the candidate tool definition with heuristic checks (suspicious
   description phrasing, oversized description, missing input schema). This is a
   narrow first filter -- a clean description with malicious server-side
   behaviour still needs runtime monitoring (documented limitation).
2. **Attack-suite smoke**: run the candidate through the gateway decision engine
   under representative attack inputs (callable hook) and confirm the gateway
   would block unapproved/abusive use. Here the smoke is expressed as a callable
   so the eval harness (task 13) provides the real suite.
3. **Four-eyes**: two distinct approvers must sign off.
4. **Policy PR**: produce the *amended* ``apm-policy.yml`` text that adds the
   tool's server to ``mcp.allow`` -- returned as a proposed document + unified
   diff. The flow never silently edits policy on disk; the demo/CI turns the
   proposal into a PR (``gh api``).

This module is pure and offline-testable; the actual ``gh`` PR call lives in the
demo script.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

# Heuristic phrases that indicate a likely-poisoned or over-broad description.
_SUSPICIOUS_PATTERNS = [
    r"ignore (all |the )?(previous|prior) instructions",
    r"exfiltrat",
    r"send .* to (an? )?(external|attacker|third)",
    r"base64|curl .* \|",
    r"\bsecret(s)?\b.*\b(email|dm|post|upload)\b",
    r"disregard .* (policy|rules)",
]

_MAX_DESCRIPTION_LEN = 2000


@dataclass
class OnboardingRequest:
    """A request to onboard one MCP server/tool."""

    server: str
    tool: str
    description: str
    input_schema: dict = field(default_factory=dict)
    requested_by: str = ""


@dataclass
class LintResult:
    ok: bool
    findings: list[str] = field(default_factory=list)


def lint_tool(request: OnboardingRequest) -> LintResult:
    """Run heuristic lint checks on a candidate tool definition."""
    findings: list[str] = []
    desc = request.description or ""
    if not desc.strip():
        findings.append("empty description")
    if len(desc) > _MAX_DESCRIPTION_LEN:
        findings.append(f"description exceeds {_MAX_DESCRIPTION_LEN} chars")
    for pattern in _SUSPICIOUS_PATTERNS:
        if re.search(pattern, desc, re.IGNORECASE):
            findings.append(f"suspicious phrasing matched /{pattern}/")
    if not isinstance(request.input_schema, dict) or not request.input_schema:
        findings.append("missing or empty input schema")
    return LintResult(ok=not findings, findings=findings)


@dataclass
class OnboardingResult:
    """Outcome of an onboarding attempt."""

    approved: bool
    stage: str  # lint | attack-smoke | four-eyes | policy-pr
    reason: str = ""
    lint: LintResult | None = None
    attack_passed: bool | None = None
    approvers: tuple[str, ...] = ()
    amended_policy: str = ""
    policy_diff: str = ""


def _amend_policy_allow(policy_text: str, server: str) -> str:
    """Return policy text with *server* added to ``mcp.allow`` (idempotent).

    Minimal, line-based amendment of the small lab policy document. It appends an
    allow entry under an existing ``mcp:``/``allow:`` block, or creates one. This
    is intentionally simple and reviewable; the generated diff is what humans
    approve in the PR.
    """
    lines = policy_text.splitlines()
    pattern = f"{server}/*"
    if any(pattern in ln for ln in lines):
        return policy_text  # already allowed (idempotent)

    out: list[str] = []
    in_mcp = False
    in_allow = False
    inserted = False
    for line in lines:
        stripped = line.strip()
        if stripped == "mcp:":
            in_mcp = True
            out.append(line)
            continue
        if in_mcp and stripped.startswith("allow:"):
            in_allow = True
            out.append(line)
            out.append(f"    - {pattern}")
            inserted = True
            continue
        if in_allow and not stripped.startswith("-") and stripped != "":
            in_allow = False
            in_mcp = stripped.endswith(":") and not line.startswith(" ")
        out.append(line)

    if not inserted:
        out.append("mcp:")
        out.append("  allow:")
        out.append(f"    - {pattern}")
    return "\n".join(out) + ("\n" if policy_text.endswith("\n") else "")


def run_onboarding(
    request: OnboardingRequest,
    policy_text: str,
    *,
    attack_smoke,
    approvers: tuple[str, ...],
) -> OnboardingResult:
    """Execute the onboarding flow and return its result.

    * ``attack_smoke`` -- callable(request) -> bool; True when the gateway blocks
      the attack inputs as expected (the eval harness supplies the real suite).
    * ``approvers`` -- the approver ids signing off; four-eyes requires two
      distinct ids.
    """
    lint = lint_tool(request)
    if not lint.ok:
        return OnboardingResult(False, "lint", reason="; ".join(lint.findings), lint=lint)

    attack_passed = bool(attack_smoke(request))
    if not attack_passed:
        return OnboardingResult(
            False,
            "attack-smoke",
            reason="attack suite did not pass",
            lint=lint,
            attack_passed=False,
        )

    if len(set(approvers)) < 2:
        return OnboardingResult(
            False,
            "four-eyes",
            reason="four-eyes requires two distinct approvers",
            lint=lint,
            attack_passed=True,
            approvers=tuple(approvers),
        )

    amended = _amend_policy_allow(policy_text, request.server)
    diff = "".join(
        difflib.unified_diff(
            policy_text.splitlines(keepends=True),
            amended.splitlines(keepends=True),
            fromfile="apm-policy.yml",
            tofile="apm-policy.yml",
        )
    )
    return OnboardingResult(
        True,
        "policy-pr",
        reason="approved",
        lint=lint,
        attack_passed=True,
        approvers=tuple(approvers),
        amended_policy=amended,
        policy_diff=diff,
    )
