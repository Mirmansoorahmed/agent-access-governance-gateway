"""Tests for the README Results-table renderer (polish item 4).

The renderer must take numbers ONLY from a results JSON (never fabricate), and
emit the 'to be measured' placeholder when the file is absent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import render_results_table as rrt  # type: ignore  # noqa: E402

_SAMPLE = {
    "pdp": "opa",
    "generated_at": "2026-11-10T00:00:00+00:00",
    "git_sha": "abc1234",
    "attack_total": 37,
    "benign_total": 16,
    "block_rate": 1.0,
    "benign_false_block_rate": 0.0,
    "latency_n": 200,
    "overhead_p50_ms": 0.12,
    "overhead_p95_ms": 0.25,
    "overhead_p99_ms": 0.4,
    "cold_start_ms": 5.1,
}


def test_placeholder_when_results_absent(tmp_path):
    table = rrt.render_table(tmp_path / "missing.json")
    assert "to be measured" in table
    assert "%" not in table  # no fabricated numbers


def test_table_numbers_come_from_json(tmp_path):
    path = tmp_path / "latest-opa.json"
    path.write_text(json.dumps(_SAMPLE), encoding="utf-8")
    table = rrt.render_table(path)
    assert "100.0%" in table  # block_rate
    assert "0.0%" in table  # benign false-block
    assert "0.12 / 0.25 / 0.4 ms" in table
    assert "n=200" in table
    assert "5.1 ms" in table  # cold start
    assert "git abc1234" in table
    assert "not hand-entered" in table


def test_write_only_touches_between_markers(tmp_path, monkeypatch):
    # Build a throwaway README with the markers and assert only that span changes.
    readme = tmp_path / "README.md"
    readme.write_text(
        "# Title\n\n## Results\n\nintro\n\n"
        f"{rrt.BEGIN}\nOLD\n{rrt.END}\n\n## Limitations\nkeep me\n",
        encoding="utf-8",
    )
    results = tmp_path / "latest-opa.json"
    results.write_text(json.dumps(_SAMPLE), encoding="utf-8")
    monkeypatch.setattr(rrt, "README", readme)
    rrt.main(["--results", str(results), "--write"])
    out = readme.read_text(encoding="utf-8")
    assert "OLD" not in out
    assert "## Limitations\nkeep me" in out  # content outside markers preserved
    assert "100.0%" in out
