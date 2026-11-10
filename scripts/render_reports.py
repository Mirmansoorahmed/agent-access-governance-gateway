#!/usr/bin/env python3
"""Render the five audit reports to Markdown and PDF (task 11).

Markdown generation is pure-stdlib (``reports.generate``). PDF rendering uses an
optional pure-Python library (reportlab preferred, weasyprint supported),
declared as the ``reports`` optional dependency and installed in CI / locally.
PDF reports are a required deliverable; this script is run by ``make reports``
and in CI.

Inputs come from committed evidence so no number is ever hand-entered:
  --spans      decision spans JSONL (gateway.evidence.FileSpanExporter output)
  --approvals  approval store JSON (gateway.approvals.ApprovalStore path)
  --pins       pin store JSON (gateway.pins.PinStore path)

Usage:
  python scripts/render_reports.py --out reports/out \
      --spans .gateway/spans.jsonl --approvals .gateway/approvals.json \
      --pins .gateway/pins.json [--pdf]
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

from reports.generate import REPORTS, ReportInputs, generate_all  # noqa: E402


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


def _build_inputs(args) -> ReportInputs:
    return ReportInputs(
        spans=_read_jsonl(args.spans),
        approvals_log=_read_json(args.approvals, "log"),
        pins=_read_json(args.pins, "pins"),
        policy_version=args.policy_version,
        generated_at=datetime.now(timezone.utc).isoformat(),
        git_sha=_git_sha(),
    )


def _render_pdf(md_path: Path, pdf_path: Path) -> None:
    """Render one Markdown file to PDF using an available pure-Python library."""
    text = md_path.read_text(encoding="utf-8")
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    except ImportError:
        _render_pdf_weasyprint(text, pdf_path)
        return
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
    flow = []
    for line in text.splitlines():
        if not line.strip():
            flow.append(Spacer(1, 6))
            continue
        style = (
            "Heading1"
            if line.startswith("# ")
            else ("Heading2" if line.startswith("## ") else "BodyText")
        )
        safe = line.lstrip("# ").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        flow.append(Paragraph(safe, styles[style]))
    doc.build(flow)


def _render_pdf_weasyprint(text: str, pdf_path: Path) -> None:
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise SystemExit(
            "No PDF backend available. Install the optional dependency:\n"
            "  pip install 'apm-cli[reports]'   (reportlab)\n"
            "or weasyprint. PDF reports are a required deliverable."
        ) from exc
    html = "<pre>" + text.replace("&", "&amp;").replace("<", "&lt;") + "</pre>"
    HTML(string=html).write_pdf(str(pdf_path))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Render audit reports (MD + PDF).")
    parser.add_argument("--out", default="reports/out")
    parser.add_argument("--spans")
    parser.add_argument("--approvals")
    parser.add_argument("--pins")
    parser.add_argument("--policy-version", default="")
    parser.add_argument("--pdf", action="store_true", help="Also render PDFs.")
    args = parser.parse_args(argv)

    inputs = _build_inputs(args)
    written = generate_all(inputs, args.out)
    print(f"Wrote {len(written)} Markdown reports to {args.out}")

    if args.pdf:
        for slug in REPORTS:
            md_path = Path(written[slug])
            pdf_path = md_path.with_suffix(".pdf")
            _render_pdf(md_path, pdf_path)
            print(f"  PDF: {pdf_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
