"""Report generators derived purely from committed evidence.

Inputs (all parsed, not hand-entered):
* ``spans``          -- decision spans from ``gateway.evidence`` (JSONL).
* ``approvals_log``  -- the approval store ``log`` (grants/rejects/consumes).
* ``pins``           -- drift pin records (``gateway.pins.PinStore.records()``).
* ``policy_version`` / ``lockfile_pins`` -- from the effective policy/lockfile.

Reports are built as a structured :class:`ReportDoc` (title + typed blocks) so
Markdown and PDF render from the *same* model -- the PDF shows real tables,
headings and a header, not a Markdown dump. ``*_md`` helpers render a doc to
Markdown; ``build_doc`` returns the structured doc for the PDF renderer.

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

PROJECT_NAME = "Agent Access Governance Gateway"


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


# --------------------------------------------------------------------------
# Structured document model (shared by Markdown + PDF renderers)
# --------------------------------------------------------------------------
@dataclass
class Table:
    """A table block with a header row and body rows."""

    header: list[str]
    rows: list[list[str]]


@dataclass
class Heading:
    """A second-level section heading."""

    text: str


@dataclass
class Prose:
    """A paragraph of body text."""

    text: str


@dataclass
class Note:
    """A callout / disclaimer paragraph (rendered emphasised)."""

    text: str


@dataclass
class ReportDoc:
    """A full report: title + ordered blocks + provenance footer."""

    title: str
    blocks: list = field(default_factory=list)
    generated_at: str = ""
    git_sha: str = ""
    span_count: int = 0

    def provenance(self) -> str:
        return (
            f"Generated at {self.generated_at or 'unknown'} · "
            f"git {self.git_sha or 'unknown'} · "
            f"derived from {self.span_count} decision span(s). "
            f"No figures are hand-entered."
        )


def _attr(span: dict, key: str, default=""):
    return span.get("attributes", {}).get(key, default)


def _short(value: str, n: int = 16) -> str:
    value = value or ""
    return f"{value[:n]}…" if value else ""


# --------------------------------------------------------------------------
# Document builders (one per report)
# --------------------------------------------------------------------------
def _doc(title: str, inputs: ReportInputs) -> ReportDoc:
    return ReportDoc(
        title=title,
        generated_at=inputs.generated_at,
        git_sha=inputs.git_sha,
        span_count=len(inputs.spans),
    )


def tool_inventory_doc(inputs: ReportInputs) -> ReportDoc:
    doc = _doc(REPORTS["tool-inventory"], inputs)
    doc.blocks.append(Prose(f"Policy version: {inputs.policy_version or 'n/a'}"))
    pin_rows = [
        [
            p.get("server", ""),
            p.get("tool", ""),
            p.get("approved_by", ""),
            p.get("approved_at", ""),
            _short(p.get("pin_hash", "")),
        ]
        for p in inputs.pins
    ] or [["no approved tools pinned", "", "", "", ""]]
    doc.blocks.append(Heading("Approved tools (pins)"))
    doc.blocks.append(Table(["Server", "Tool", "Approved by", "Approved at", "Pin"], pin_rows))
    lock_rows = [
        [lp.get("name", ""), lp.get("version", ""), _short(lp.get("content_hash", ""))]
        for lp in inputs.lockfile_pins
    ] or [["none", "", ""]]
    doc.blocks.append(Heading("Lockfile pins"))
    doc.blocks.append(Table(["Name", "Version", "Content hash"], lock_rows))
    return doc


def access_by_group_doc(inputs: ReportInputs) -> ReportDoc:
    allowed: dict[str, set[str]] = defaultdict(set)
    for span in inputs.spans:
        if _attr(span, "decision.allowed") is True:
            tool = f"{_attr(span, 'mcp.server')}/{_attr(span, 'mcp.tool')}"
            for group in _attr(span, "agent.groups", []) or []:
                allowed[group].add(tool)
    doc = _doc(REPORTS["access-by-group"], inputs)
    doc.blocks.append(Prose("Observed allowed tool access by OIDC group (from decision spans)."))
    rows = [[g, ", ".join(sorted(allowed[g]))] for g in sorted(allowed)]
    rows = rows or [["no allowed calls recorded", ""]]
    doc.blocks.append(Table(["Group", "Tools allowed (observed)"], rows))
    return doc


def blocked_activity_doc(inputs: ReportInputs) -> ReportDoc:
    blocked = [s for s in inputs.spans if _attr(s, "decision.allowed") is False]
    reasons = Counter(_attr(s, "decision.reason") for s in blocked)
    doc = _doc(REPORTS["blocked-activity"], inputs)
    doc.blocks.append(Prose(f"Total blocked calls: {len(blocked)}"))
    doc.blocks.append(Heading("By reason"))
    reason_rows = [[r, str(c)] for r, c in sorted(reasons.items())] or [["none", "0"]]
    doc.blocks.append(Table(["Reason", "Count"], reason_rows))
    doc.blocks.append(Heading("Detail"))
    detail_rows = [
        [
            s.get("timestamp", ""),
            _attr(s, "agent.id"),
            f"{_attr(s, 'mcp.server')}/{_attr(s, 'mcp.tool')}",
            _attr(s, "decision.reason"),
            _attr(s, "decision.detail"),
        ]
        for s in blocked
    ] or [["no blocked activity", "", "", "", ""]]
    doc.blocks.append(Table(["Timestamp", "Agent", "Server/Tool", "Reason", "Detail"], detail_rows))
    return doc


def approvals_doc(inputs: ReportInputs) -> ReportDoc:
    events = Counter(e.get("event") for e in inputs.approvals_log)
    doc = _doc(REPORTS["approvals"], inputs)
    doc.blocks.append(
        Table(
            ["Event", "Count"], [[e, str(events.get(e, 0))] for e in ("grant", "consume", "reject")]
        )
    )
    doc.blocks.append(Heading("Grants and rejections"))
    rows = []
    for entry in inputs.approvals_log:
        if entry.get("event") not in ("grant", "reject"):
            continue
        approvers = ", ".join(entry.get("approvers", [])) or entry.get("approver", "")
        note = entry.get("justification", "") or entry.get("reason", "")
        rows.append(
            [
                entry.get("event", ""),
                entry.get("agent", ""),
                f"{entry.get('server', '')}/{entry.get('tool', '')}",
                entry.get("tier", ""),
                approvers,
                note,
            ]
        )
    rows = rows or [["no approval decisions recorded", "", "", "", "", ""]]
    doc.blocks.append(
        Table(
            ["Event", "Agent", "Server/Tool", "Tier", "Approver(s)", "Justification/Reason"], rows
        )
    )
    return doc


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


def audit_summary_doc(inputs: ReportInputs) -> ReportDoc:
    total = len(inputs.spans)
    allowed = sum(1 for s in inputs.spans if _attr(s, "decision.allowed") is True)
    blocked = total - allowed
    doc = _doc(REPORTS["audit-summary"], inputs)
    doc.blocks.append(
        Note(
            "Illustrative mapping only. This summary maps implemented controls to "
            "ISO/IEC 42001 Annex A themes and EU AI Act Art. 12 (logging) / Art. 14 "
            "(human oversight) for a lab demonstration. It is not a conformity claim "
            "and is no substitute for Legal review or an accredited audit."
        )
    )
    doc.blocks.append(Heading("Activity (from decision spans)"))
    doc.blocks.append(
        Table(
            ["Metric", "Value"],
            [["Total decisions", str(total)], ["Allowed", str(allowed)], ["Blocked", str(blocked)]],
        )
    )
    doc.blocks.append(Heading("Control mapping (illustrative)"))
    doc.blocks.append(
        Table(
            ["Implemented control", "ISO/IEC 42001 Annex A (theme)", "EU AI Act"],
            [list(row) for row in _CONTROL_MAP],
        )
    )
    return doc


_DOC_BUILDERS = {
    "tool-inventory": tool_inventory_doc,
    "access-by-group": access_by_group_doc,
    "blocked-activity": blocked_activity_doc,
    "approvals": approvals_doc,
    "audit-summary": audit_summary_doc,
}


def build_doc(slug: str, inputs: ReportInputs) -> ReportDoc:
    """Return the structured document for *slug*."""
    return _DOC_BUILDERS[slug](inputs)


# --------------------------------------------------------------------------
# Markdown rendering (from the structured doc)
# --------------------------------------------------------------------------
def _md_table(table: Table) -> list[str]:
    lines = ["| " + " | ".join(table.header) + " |"]
    lines.append("|" + "|".join(["---"] * len(table.header)) + "|")
    for row in table.rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return lines


def render_markdown(doc: ReportDoc) -> str:
    lines = [f"# {doc.title}", ""]
    for block in doc.blocks:
        if isinstance(block, Heading):
            lines += [f"## {block.text}", ""]
        elif isinstance(block, Prose):
            lines += [block.text, ""]
        elif isinstance(block, Note):
            lines += [f"> **{block.text}**", ""]
        elif isinstance(block, Table):
            lines += _md_table(block)
            lines.append("")
    lines += ["---", f"*{doc.provenance()}*", ""]
    return "\n".join(lines)


# Back-compatible ``*_md`` helpers (render the structured doc to Markdown).
def tool_inventory_md(inputs: ReportInputs) -> str:
    return render_markdown(tool_inventory_doc(inputs))


def access_by_group_md(inputs: ReportInputs) -> str:
    return render_markdown(access_by_group_doc(inputs))


def blocked_activity_md(inputs: ReportInputs) -> str:
    return render_markdown(blocked_activity_doc(inputs))


def approvals_md(inputs: ReportInputs) -> str:
    return render_markdown(approvals_doc(inputs))


def audit_summary_md(inputs: ReportInputs) -> str:
    return render_markdown(audit_summary_doc(inputs))


def generate_all(inputs: ReportInputs, out_dir: str) -> dict[str, str]:
    """Write all five Markdown reports to *out_dir*; return slug -> path."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = {}
    for slug in REPORTS:
        path = out / f"{slug}.md"
        path.write_text(render_markdown(build_doc(slug, inputs)), encoding="utf-8")
        written[slug] = str(path)
    return written
