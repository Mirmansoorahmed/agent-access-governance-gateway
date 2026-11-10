"""Auditor-facing report generators (task 11).

Five reports, each rendered to Markdown here (stdlib only) and to PDF by
``scripts/render_reports.py`` (optional PDF dependency). Every figure derives
from committed evidence -- decision spans (``gateway.evidence``), the approval
store log, drift pins, and the effective policy. Nothing is hand-entered:
report generators take parsed inputs and compute counts, so a number can always
be traced to a span or log entry.
"""

from __future__ import annotations

__all__ = [
    "ReportInputs",
    "access_by_group_md",
    "approvals_md",
    "audit_summary_md",
    "blocked_activity_md",
    "generate_all",
    "tool_inventory_md",
]

from .generate import (
    ReportInputs,
    access_by_group_md,
    approvals_md,
    audit_summary_md,
    blocked_activity_md,
    generate_all,
    tool_inventory_md,
)
