#!/usr/bin/env python3
"""Render the README Results table from a committed eval results JSON.

The numbers come ONLY from the results file (produced by a real `python -m eval`
run), never hand-entered. By default this reads eval/results/latest-opa.json —
the authoritative OPA-backed run — and prints a Markdown table. With --write it
replaces the section between the <!-- RESULTS:BEGIN --> / <!-- RESULTS:END -->
markers in README.md.

    python scripts/render_results_table.py                 # print the table
    python scripts/render_results_table.py --write         # update README.md

If the results file is absent, it prints/writes the 'to be measured' placeholder
so the README never carries fabricated numbers.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RESULTS = ROOT / "eval" / "results" / "latest-opa.json"
README = ROOT / "README.md"
BEGIN = "<!-- RESULTS:BEGIN -->"
END = "<!-- RESULTS:END -->"

_PLACEHOLDER = (
    "*No committed `eval/results/latest-opa.json` yet — run `make eval-opa` then\n"
    "`make results-table`. Until then: planned / to be measured.*"
)


def render_table(results_path: Path) -> str:
    if not results_path.exists():
        return _PLACEHOLDER
    data = json.loads(results_path.read_text(encoding="utf-8"))
    rows = [
        (
            "Block rate (attack suite)",
            f"{data['block_rate'] * 100:.1f}% ({data['attack_total']} cases)",
        ),
        (
            "Benign false-block rate",
            f"{data['benign_false_block_rate'] * 100:.1f}% ({data['benign_total']} cases)",
        ),
        (
            "Gateway overhead p50 / p95 / p99",
            f"{data['overhead_p50_ms']} / {data['overhead_p95_ms']} / "
            f"{data['overhead_p99_ms']} ms (n={data['latency_n']})",
        ),
        ("OPA cold start", f"{data['cold_start_ms']} ms"),
    ]
    lines = ["| Metric | Value |", "|---|---|"]
    lines += [f"| {metric} | {value} |" for metric, value in rows]
    lines.append("")
    lines.append(
        f"*PDP: {data.get('pdp', '?')} · measured {data.get('generated_at', '?')} · "
        f"git {data.get('git_sha', '?')}. Rendered by scripts/render_results_table.py "
        f"from eval/results/latest-opa.json; not hand-entered.*"
    )
    return "\n".join(lines)


def _write_readme(table: str) -> None:
    text = README.read_text(encoding="utf-8")
    if BEGIN not in text or END not in text:
        raise SystemExit(f"error: {README} is missing the RESULTS markers")
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    README.write_text(f"{head}{BEGIN}\n{table}\n{END}{tail}", encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Render README Results table from eval JSON.")
    parser.add_argument("--results", default=str(DEFAULT_RESULTS))
    parser.add_argument("--write", action="store_true", help="Update README.md in place.")
    args = parser.parse_args(argv)

    table = render_table(Path(args.results))
    if args.write:
        _write_readme(table)
        print(f"Updated {README} Results section from {args.results}")
    else:
        print(table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
