#!/usr/bin/env python3
"""Render the five audit reports to Markdown and PDF (task 11).

Evidence comes from a demo/eval run, not from thin air: run ``make demo`` (or the
eval harness) first to produce ``.gateway/spans.jsonl`` + ``approvals.json`` +
``pins.json``, then ``make reports``. If those evidence files are missing this
script **fails closed** (non-zero exit, clear message) rather than emitting
all-zero reports that could be mistaken for a real audit.

Markdown generation is pure-stdlib (``reports.generate``). PDF rendering uses the
optional ``reports`` dependency (reportlab preferred, weasyprint supported) and
produces laid-out tables/headings with a project header -- not a Markdown dump.
PDF reports are a required deliverable.

Usage:
  python scripts/render_reports.py --out reports/out \
      --spans .gateway/spans.jsonl --approvals .gateway/approvals.json \
      --pins .gateway/pins.json --lockfile apm.lock.yaml [--pdf] [--allow-empty]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from reports.generate import (  # noqa: E402
    PROJECT_NAME,
    REPORTS,
    ReportInputs,
    build_doc,
    render_markdown,
)


def _git_sha() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip()
    except Exception:
        return "unknown"


def _read_jsonl(path: str | None) -> list[dict]:
    if not path or not Path(path).exists():
        return []
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _read_json(path: str | None, key: str) -> list[dict]:
    if not path or not Path(path).exists():
        return []
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data.get(key, [])


def _load_lockfile_pins(path: str | None) -> list[dict]:
    if not path or not Path(path).exists():
        return []
    try:
        import yaml
    except ImportError:
        return []
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    pins = []
    for dep in data.get("dependencies", []) or []:
        pins.append(
            {
                "name": dep.get("name", ""),
                "version": str(dep.get("version", "")),
                "content_hash": dep.get("content_hash", ""),
            }
        )
    return pins


def _policy_version(explicit: str, policy_path: str) -> str:
    if explicit:
        return explicit
    p = Path(policy_path)
    if not p.exists():
        return ""
    try:
        import yaml

        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return str(data.get("version", ""))
    except Exception:
        return ""


def _check_evidence(args) -> None:
    """Fail closed when evidence inputs are missing (unless --allow-empty)."""
    if args.allow_empty:
        return
    missing = [
        label
        for label, path in (
            ("spans", args.spans),
            ("approvals", args.approvals),
            ("pins", args.pins),
        )
        if not path or not Path(path).exists()
    ]
    if missing:
        raise SystemExit(
            "error: missing evidence input(s): "
            + ", ".join(missing)
            + "\nReports derive every number from a demo/eval run. Run `make demo` "
            "(or the eval harness) to produce .gateway/spans.jsonl, approvals.json "
            "and pins.json first, then `make reports`.\n"
            "(Use --allow-empty only to render empty-state templates on purpose.)"
        )


def _build_inputs(args) -> ReportInputs:
    return ReportInputs(
        spans=_read_jsonl(args.spans),
        approvals_log=_read_json(args.approvals, "log"),
        pins=_read_json(args.pins, "pins"),
        policy_version=_policy_version(args.policy_version, args.policy),
        lockfile_pins=_load_lockfile_pins(args.lockfile),
        generated_at=datetime.now(timezone.utc).isoformat(),
        git_sha=_git_sha(),
    )


# --------------------------------------------------------------------------
# PDF rendering -- real tables/headings/header (not a Markdown dump)
# --------------------------------------------------------------------------
def _render_pdf(slug: str, inputs: ReportInputs, pdf_path: Path) -> None:
    doc_model = build_doc(slug, inputs)
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        _render_pdf_weasyprint(doc_model, pdf_path)
        return

    from reports.generate import Heading, Note, Prose
    from reports.generate import Table as DocTable

    styles = getSampleStyleSheet()
    pdf = SimpleDocTemplate(str(pdf_path), pagesize=A4, title=f"{PROJECT_NAME} — {doc_model.title}")
    flow = []
    # Header: project name, report title, generated-at + git SHA.
    flow.append(Paragraph(PROJECT_NAME, styles["Title"]))
    flow.append(Paragraph(doc_model.title, styles["Heading1"]))
    flow.append(
        Paragraph(
            f"Generated {doc_model.generated_at or 'unknown'} · git {doc_model.git_sha or 'unknown'}",
            styles["Normal"],
        )
    )
    flow.append(Spacer(1, 12))

    for block in doc_model.blocks:
        if isinstance(block, Heading):
            flow.append(Paragraph(block.text, styles["Heading2"]))
        elif isinstance(block, Prose):
            flow.append(Paragraph(block.text, styles["BodyText"]))
        elif isinstance(block, Note):
            flow.append(Paragraph(f"<b>{block.text}</b>", styles["BodyText"]))
        elif isinstance(block, DocTable):
            data = [list(block.header)] + [list(map(str, r)) for r in block.rows]
            table = Table(data, hAlign="LEFT")
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#30363d")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#f6f8fa")],
                        ),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ]
                )
            )
            flow.append(table)
        flow.append(Spacer(1, 8))

    flow.append(Spacer(1, 8))
    flow.append(Paragraph(f"<i>{doc_model.provenance()}</i>", styles["Normal"]))
    pdf.build(flow)


def _render_pdf_weasyprint(doc_model, pdf_path: Path) -> None:
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise SystemExit(
            "No PDF backend available. Install the optional dependency:\n"
            "  pip install 'apm-cli[reports]'   (reportlab)\n"
            "or weasyprint. PDF reports are a required deliverable."
        ) from exc
    # Minimal HTML with real tables so weasyprint lays it out properly.
    from reports.generate import Heading, Note, Prose
    from reports.generate import Table as DocTable

    html = [f"<h1>{PROJECT_NAME}</h1>", f"<h2>{doc_model.title}</h2>"]
    html.append(f"<p>Generated {doc_model.generated_at} · git {doc_model.git_sha}</p>")
    for block in doc_model.blocks:
        if isinstance(block, Heading):
            html.append(f"<h3>{block.text}</h3>")
        elif isinstance(block, Prose):
            html.append(f"<p>{block.text}</p>")
        elif isinstance(block, Note):
            html.append(f"<p><strong>{block.text}</strong></p>")
        elif isinstance(block, DocTable):
            cells = "".join(f"<th>{h}</th>" for h in block.header)
            body = "".join(
                "<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in block.rows
            )
            html.append(f"<table border='1'><tr>{cells}</tr>{body}</table>")
    html.append(f"<p><i>{doc_model.provenance()}</i></p>")
    HTML(string="".join(html)).write_pdf(str(pdf_path))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Render audit reports (MD + PDF).")
    parser.add_argument("--out", default="reports/out")
    parser.add_argument("--spans")
    parser.add_argument("--approvals")
    parser.add_argument("--pins")
    parser.add_argument("--lockfile", default="apm.lock.yaml")
    parser.add_argument(
        "--policy",
        default="apm-policy.yml",
        help="Policy file to read the version from by default.",
    )
    parser.add_argument("--policy-version", default="")
    parser.add_argument("--pdf", action="store_true", help="Also render PDFs.")
    parser.add_argument(
        "--allow-empty",
        action="store_true",
        help="Render even when evidence inputs are missing (templates only).",
    )
    args = parser.parse_args(argv)

    _check_evidence(args)
    inputs = _build_inputs(args)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for slug in REPORTS:
        (out / f"{slug}.md").write_text(render_markdown(build_doc(slug, inputs)), encoding="utf-8")
    print(f"Wrote {len(REPORTS)} Markdown reports to {args.out}")

    if args.pdf:
        for slug in REPORTS:
            pdf_path = out / f"{slug}.pdf"
            _render_pdf(slug, inputs, pdf_path)
            print(f"  PDF: {pdf_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
