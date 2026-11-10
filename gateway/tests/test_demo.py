"""Tests for the demo scenario driver (task 14)."""

from __future__ import annotations

import json

from demo.scenario import run_demo
from gateway.evidence import load_spans


def test_demo_runs_all_five_stages(tmp_path):
    log = run_demo(out_dir=str(tmp_path))
    joined = "\n".join(log)
    assert "Stage 1" in joined
    assert "Stage 2" in joined and "approved=True" in joined
    assert "Stage 3" in joined
    assert "Stage 4" in joined and "description-drift" in joined
    assert "Stage 5" in joined and "group-denied" in joined


def test_demo_writes_evidence_files(tmp_path):
    run_demo(out_dir=str(tmp_path))
    spans = load_spans(str(tmp_path / "spans.jsonl"))
    # allow (stage 3) + drift block (stage 4) + wrong-group block (stage 5)
    assert len(spans) == 3
    reasons = [s["attributes"]["decision.reason"] for s in spans]
    assert "allow" in reasons
    assert "description-drift" in reasons
    assert "group-denied" in reasons

    approvals = json.loads((tmp_path / "approvals.json").read_text(encoding="utf-8"))
    assert any(e["event"] == "grant" for e in approvals["log"])

    pins = json.loads((tmp_path / "pins.json").read_text(encoding="utf-8"))
    assert any(p["tool"] == "lookup_client" for p in pins["pins"])


def test_demo_emits_policy_pr_artifacts(tmp_path):
    run_demo(out_dir=str(tmp_path))
    amended = (tmp_path / "onboarding-policy.yml").read_text(encoding="utf-8")
    assert "research/*" in amended
    diff = (tmp_path / "onboarding.diff").read_text(encoding="utf-8")
    assert "research/*" in diff


def test_demo_evidence_feeds_reports(tmp_path):
    run_demo(out_dir=str(tmp_path))
    from reports.generate import ReportInputs, blocked_activity_md

    spans = load_spans(str(tmp_path / "spans.jsonl"))
    md = blocked_activity_md(ReportInputs(spans=spans, generated_at="t", git_sha="s"))
    # Two blocked calls (drift + wrong group) show up in the report.
    assert "Total blocked calls: 2" in md
