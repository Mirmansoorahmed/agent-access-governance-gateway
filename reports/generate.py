"""Markdown report generators derived purely from committed evidence.

Inputs (all parsed, not hand-entered):
* ``spans``      -- decision spans from ``gateway.evidence`` (JSONL).
* ``approvals``  -- the approval store ``log`` (grants/rejects/consumes).
* ``pins``       -- drift pin records (``gateway.pins.PinStore.records()``).
* ``policy_version`` / ``lockfile_pins`` -- from the effective policy/lockfile.

Each generator returns Markdown text; ``generate_all`` writes the five files.
The Audit Summary is explicitly an **illustrative** control mapping, not a
conformity claim.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

REPORTS = {
    "tool-inventory": "Tool Inventory",
    "access-by-group": "Access by Group",
    "blocked-activity": "Blocked Activity",
    "approvals": "Approvals",
    "audit-summary": "Audit Summary",
}


@dataclass
class ReportInputs:
    """Parsed, evidence-derived inputs for the report generators."""

    spans: list[dict] = field(default_factory=list)
    approvals_log: list[dict] = field(default_factory=list)
    pins: list[dict] = field(default_factory=list)
    policy_version: str = ""
    lockfile_pins: list[dict] = field(default_factory=list)
    # Provenance stamped into every report so numbers are traceable.
    generated_at: str = ""
    git_sha: str = ""


def _attr(span: dict, key: str, default=""):
    return span.get("attributes", {}).get(key, default)


def _provenance(inputs: ReportInputs) -> str:
    return (
        f"\n\n---\n*Generated at {inputs.generated_at or 'unknown'} · "
        f"git {inputs.git_sha or 'unknown'} · "
        f"derived from {len(inputs.spans)} decision span(s). "
        f"No figures are hand-entered.*\n"
    )


def tool_inventory_md(inputs: ReportInputs) -> str:
    lines = [f"# {REPORTS['tool-inventory']}", ""]
    lines.append(f"Policy version: `{inputs.policy_version or 'n/a'}`")
    lines.append("")
    lines.append("| Server | Tool | Approved by | Approved at | Pin |")
    lines.append("|---|---|---|---|---|")
    for pin in inputs.pins:
        lines.append(
            f"| {pin.get('server', '')} | {pin.get('tool', '')} | "
            f"{pin.get('approved_by', '')} | {pin.get('approved_at', '')} | "
            f"`{(pin.get('pin_hash', '') or '')[:16]}…` |"
        )
    if not inputs.pins:
        lines.append("| _no approved tools pinned_ | | | | |")
    lines.append("")
    lines.append("## Lockfile pins")
    lines.append("| Name | Version | Content hash |")
    lines.append("|---|---|---|")
    for lp in inputs.lockfile_pins:
        lines.append(
            f"| {lp.get('name', '')} | {lp.get('version', '')} | "
            f"`{(lp.get('content_hash', '') or '')[:16]}…` |"
        )
    if not inputs.lockfile_pins:
        lines.append("| _none_ | | |")
    return "\n".join(lines) + _provenance(inputs)


def access_by_group_md(inputs: ReportInputs) -> str:
    # group -> set of (server/tool) that were allowed for that group in evidence
    allowed: dict[str, set[str]] = defaultdict(set)
    for span in inputs.spans:
        if _attr(span, "decision.allowed") is True:
            tool = f"{_attr(span, 'mcp.server')}/{_attr(span, 'mcp.tool')}"
            for group in _attr(span, "agent.groups", []) or []:
                allowed[group].add(tool)
    lines = [f"# {REPORTS['access-by-group']}", ""]
    lines.append("Observed allowed tool access by OIDC group (from decision spans).")
    lines.append("")
    lines.append("| Group | Tools allowed (observed) |")
    lines.append("|---|---|")
    for group in sorted(allowed):
        lines.append(f"| {group} | {', '.join(sorted(allowed[group]))} |")
    if not allowed:
        lines.append("| _no allowed calls recorded_ | |")
    return "\n".join(lines) + _provenance(inputs)


def blocked_activity_md(inputs: ReportInputs) -> str:
    blocked = [s for s in inputs.spans if _attr(s, "decision.allowed") is False]
    reasons = Counter(_attr(s, "decision.reason") for s in blocked)
    lines = [f"# {REPORTS['blocked-activity']}", ""]
    lines.append(f"Total blocked calls: **{len(blocked)}**")
    lines.append("")
    lines.append("## By reason")
    lines.append("| Reason | Count |")
    lines.append("|---|---|")
    for reason, count in sorted(reasons.items()):
        lines.append(f"| `{reason}` | {count} |")
    if not reasons:
        lines.append("| _none_ | 0 |")
    lines.append("")
    lines.append("## Detail")
    lines.append("| Timestamp | Agent | Server/Tool | Reason | Detail |")
    lines.append("|---|---|---|---|---|")
    for span in blocked:
        lines.append(
            f"| {span.get('timestamp', '')} | {_attr(span, 'agent.id')} | "
            f"{_attr(span, 'mcp.server')}/{_attr(span, 'mcp.tool')} | "
            f"`{_attr(span, 'decision.reason')}` | {_attr(span, 'decision.detail')} |"
        )
    if not blocked:
        lines.append("| _no blocked activity_ | | | | |")
    return "\n".join(lines) + _provenance(inputs)


def approvals_md(inputs: ReportInputs) -> str:
    events = Counter(e.get("event") for e in inputs.approvals_log)
    lines = [f"# {REPORTS['approvals']}", ""]
    lines.append("| Event | Count |")
    lines.append("|---|---|")
    for event in ("grant", "consume", "reject"):
        lines.append(f"| {event} | {events.get(event, 0)} |")
    lines.append("")
    lines.append("## Grants and rejections")
    lines.append("| Event | Agent | Server/Tool | Tier | Approver(s) | Justification/Reason |")
    lines.append("|---|---|---|---|---|---|")
    for entry in inputs.approvals_log:
        if entry.get("event") not in ("grant", "reject"):
            continue
        approvers = ", ".join(entry.get("approvers", [])) or entry.get("approver", "")
        note = entry.get("justification", "") or entry.get("reason", "")
        lines.append(
            f"| {entry.get('event')} | {entry.get('agent', '')} | "
            f"{entry.get('server', '')}/{entry.get('tool', '')} | "
            f"{entry.get('tier', '')} | {approvers} | {note} |"
        )
    if not any(e.get("event") in ("grant", "reject") for e in inputs.approvals_log):
        lines.append("| _no approval decisions recorded_ | | | | | |")
    return "\n".join(lines) + _provenance(inputs)


# Illustrative control mapping -- NOT a conformity claim.
_CONTROL_MAP = [
    (
        "Runtime per-call enforcement (4 checks)",
        "ISO/IEC 42001 Annex A (operational controls)",
        "EU AI Act Art. 14 (human oversight)",
    ),
    ("OIDC group/role checks (Check 2)", "ISO/IEC 42001 Annex A (access control themes)", "—"),
    ("Description-drift pin (Check 3)", "ISO/IEC 42001 Annex A (integrity/monitoring)", "—"),
    (
        "Approval tiers + four-eyes/break-glass",
        "ISO/IEC 42001 Annex A (human review)",
        "EU AI Act Art. 14 (human oversight)",
    ),
    (
        "OpenTelemetry decision log",
        "ISO/IEC 42001 Annex A (record keeping)",
        "EU AI Act Art. 12 (logging)",
    ),
]


def audit_summary_md(inputs: ReportInputs) -> str:
    total = len(inputs.spans)
    allowed = sum(1 for s in inputs.spans if _attr(s, "decision.allowed") is True)
    blocked = total - allowed
    lines = [f"# {REPORTS['audit-summary']}", ""]
    lines.append(
        "> **Illustrative mapping only.** This summary maps implemented controls "
        "to ISO/IEC 42001 Annex A themes and EU AI Act Art. 12 (logging) / Art. 14 "
        "(human oversight) for a lab demonstration. It is **not** a conformity "
        "claim and is no substitute for Legal review or an accredited audit."
    )
    lines.append("")
    lines.append("## Activity (from decision spans)")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Total decisions | {total} |")
    lines.append(f"| Allowed | {allowed} |")
    lines.append(f"| Blocked | {blocked} |")
    lines.append("")
    lines.append("## Control mapping (illustrative)")
    lines.append("| Implemented control | ISO/IEC 42001 Annex A (theme) | EU AI Act |")
    lines.append("|---|---|---|")
    for control, iso, act in _CONTROL_MAP:
        lines.append(f"| {control} | {iso} | {act} |")
    return "\n".join(lines) + _provenance(inputs)


_GENERATORS = {
    "tool-inventory": tool_inventory_md,
    "access-by-group": access_by_group_md,
    "blocked-activity": blocked_activity_md,
    "approvals": approvals_md,
    "audit-summary": audit_summary_md,
}


def generate_all(inputs: ReportInputs, out_dir: str) -> dict[str, str]:
    """Write all five Markdown reports to *out_dir*; return slug -> path."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = {}
    for slug, generator in _GENERATORS.items():
        path = out / f"{slug}.md"
        path.write_text(generator(inputs), encoding="utf-8")
        written[slug] = str(path)
    return written
