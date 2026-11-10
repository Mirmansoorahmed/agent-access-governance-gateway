"""Tests for the five report generators (task 11).

Reports must derive every figure from evidence inputs (no hand-entered numbers)
and the Audit Summary must carry its non-conformity disclaimer. PDF rendering is
exercised when reportlab is importable (CI/lab) and skipped otherwise.
"""

from __future__ import annotations

import pytest

from reports.generate import (
    ReportInputs,
    access_by_group_md,
    approvals_md,
    audit_summary_md,
    blocked_activity_md,
    generate_all,
    tool_inventory_md,
)


def _span(allowed, reason, server="crm", tool="lookup_client", groups=("advisors",), detail=""):
    return {
        "name": "governance.decision",
        "timestamp": "2026-11-10T00:00:00+00:00",
        "attributes": {
            "agent.id": "u1",
            "agent.groups": list(groups),
            "mcp.server": server,
            "mcp.tool": tool,
            "decision.allowed": allowed,
            "decision.reason": reason,
            "decision.detail": detail,
        },
    }


def _inputs() -> ReportInputs:
    return ReportInputs(
        spans=[
            _span(True, "allow"),
            _span(False, "no-allowlist", tool="export_clients"),
            _span(False, "description-drift", tool="lookup_client", detail="pin mismatch"),
            _span(True, "allow", server="billing", tool="read_invoice", groups=("finance",)),
        ],
        approvals_log=[
            {
                "event": "grant",
                "agent": "u1",
                "server": "crm",
                "tool": "export_clients",
                "tier": "four-eyes",
                "approvers": ["a", "b"],
                "justification": "",
            },
            {
                "event": "reject",
                "agent": "u2",
                "server": "crm",
                "tool": "export_clients",
                "approver": "a",
                "reason": "not justified",
            },
        ],
        pins=[
            {
                "server": "crm",
                "tool": "lookup_client",
                "approved_by": "sec",
                "approved_at": "2026-11-10T00:00:00+00:00",
                "pin_hash": "sha256:abcdef0123456789",
            }
        ],
        policy_version="1.0",
        lockfile_pins=[{"name": "crm-mcp", "version": "1.2.3", "content_hash": "sha256:deadbeef"}],
        generated_at="2026-11-10T00:00:00+00:00",
        git_sha="abc1234",
    )


def test_tool_inventory_lists_pins_and_policy_version():
    md = tool_inventory_md(_inputs())
    assert "Tool Inventory" in md
    assert "lookup_client" in md
    assert "1.0" in md
    assert "crm-mcp" in md


def test_access_by_group_derives_from_spans():
    md = access_by_group_md(_inputs())
    # advisors allowed crm/lookup_client; finance allowed billing/read_invoice.
    assert "advisors" in md and "crm/lookup_client" in md
    assert "finance" in md and "billing/read_invoice" in md
    # A blocked tool must not appear as allowed access.
    assert "crm/export_clients" not in md


def test_blocked_activity_counts_match_spans():
    md = blocked_activity_md(_inputs())
    # Two blocked spans in the fixture.
    assert "Total blocked calls: 2" in md
    assert "no-allowlist" in md
    assert "description-drift" in md


def test_approvals_report_counts_and_rows():
    md = approvals_md(_inputs())
    assert "| grant | 1 |" in md
    assert "| reject | 1 |" in md
    assert "a, b" in md  # four-eyes approvers
    assert "not justified" in md


def test_audit_summary_has_disclaimer_and_counts():
    md = audit_summary_md(_inputs())
    assert "Illustrative mapping only" in md
    assert "not" in md and "conformity claim" in md
    assert "| Total decisions | 4 |" in md
    assert "| Allowed | 2 |" in md
    assert "| Blocked | 2 |" in md
    # Control mapping references the frameworks.
    assert "ISO/IEC 42001" in md
    assert "EU AI Act Art. 12" in md


def test_reports_carry_traceable_provenance():
    for md in (tool_inventory_md(_inputs()), blocked_activity_md(_inputs())):
        assert "git abc1234" in md
        assert "No figures are hand-entered" in md


def test_generate_all_writes_five_markdown_files(tmp_path):
    written = generate_all(_inputs(), str(tmp_path))
    assert set(written) == {
        "tool-inventory",
        "access-by-group",
        "blocked-activity",
        "approvals",
        "audit-summary",
    }
    for path in written.values():
        assert path.endswith(".md")
        assert (tmp_path / path.split("/")[-1]).read_text(encoding="utf-8")


def test_empty_inputs_produce_valid_reports_without_fabrication():
    empty = ReportInputs(generated_at="t", git_sha="s")
    assert "Total blocked calls: 0" in blocked_activity_md(empty)
    assert "| Total decisions | 0 |" in audit_summary_md(empty)
    assert "no approved tools pinned" in tool_inventory_md(empty)


def test_render_reports_fails_closed_without_evidence(tmp_path):
    """make reports path: missing evidence files must exit non-zero, not emit zeros."""
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent.parent
    sys.path.insert(0, str(root / "scripts"))
    import render_reports  # type: ignore

    out = tmp_path / "out"
    with pytest.raises(SystemExit) as exc:
        render_reports.main(
            [
                "--out",
                str(out),
                "--spans",
                str(tmp_path / "missing-spans.jsonl"),
                "--approvals",
                str(tmp_path / "missing.json"),
                "--pins",
                str(tmp_path / "missing-pins.json"),
            ]
        )
    assert exc.value.code != 0
    assert not out.exists()  # nothing written on fail-closed


def test_render_reports_allow_empty_renders_templates(tmp_path):
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent.parent
    sys.path.insert(0, str(root / "scripts"))
    import render_reports  # type: ignore

    out = tmp_path / "out"
    rc = render_reports.main(
        [
            "--out",
            str(out),
            "--allow-empty",
            "--lockfile",
            str(tmp_path / "none.yaml"),
            "--policy",
            str(tmp_path / "none.yml"),
        ]
    )
    assert rc == 0
    assert (out / "audit-summary.md").exists()


def test_pdf_rendering_when_reportlab_available(tmp_path):
    pytest.importorskip("reportlab")
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent.parent
    sys.path.insert(0, str(root / "scripts"))
    from render_reports import _render_pdf  # type: ignore

    pdf = tmp_path / "blocked-activity.pdf"
    _render_pdf("blocked-activity", _inputs(), pdf)
    assert pdf.exists() and pdf.stat().st_size > 0


def test_pdf_renders_table_as_real_table(tmp_path):
    """A table block must become a reportlab Table flowable, not raw text."""
    pytest.importorskip("reportlab")
    from reportlab.platypus import Table as RLTable

    captured = {}

    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent.parent
    sys.path.insert(0, str(root / "scripts"))
    import render_reports  # type: ignore

    # SimpleDocTemplate.build receives the flowables list; capture it.
    orig_build = render_reports.__dict__  # noqa: F841 - keep module ref alive

    class _Capture:
        def __init__(self, *a, **k):
            pass

        def build(self, flow):
            captured["flow"] = flow

    # Patch SimpleDocTemplate used inside _render_pdf by monkeypatching reportlab.
    from reportlab import platypus

    orig = platypus.SimpleDocTemplate
    platypus.SimpleDocTemplate = _Capture
    try:
        render_reports._render_pdf("audit-summary", _inputs(), tmp_path / "x.pdf")
    finally:
        platypus.SimpleDocTemplate = orig

    assert any(isinstance(f, RLTable) for f in captured["flow"]), "expected a reportlab Table"
