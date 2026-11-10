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


def test_sample_policy_exists_with_version():
    from pathlib import Path

    policy = Path(__file__).resolve().parent.parent.parent / "apm-policy.yml"
    assert policy.exists(), "sample apm-policy.yml for the demo is missing"
    text = policy.read_text(encoding="utf-8")
    assert "version:" in text
    assert "mcp:" in text and "allow:" in text


def test_demo_onboarding_amends_committed_sample_policy(tmp_path):
    run_demo(out_dir=str(tmp_path))
    amended = (tmp_path / "onboarding-policy.yml").read_text(encoding="utf-8")
    # The amendment is applied on top of the committed sample policy.
    assert "northwind-advisory" in amended
    assert "research/*" in amended


def test_demo_runs_with_real_opa_when_available(tmp_path):
    from gateway.opa_client import opa_available

    if not opa_available():
        import pytest

        pytest.skip("requires the 'opa' binary on PATH (maintainer/CI only)")
    log = run_demo(out_dir=str(tmp_path), use_opa=True)
    assert any("real OPA" in line for line in log)
    spans = load_spans(str(tmp_path / "spans.jsonl"))
    reasons = [s["attributes"]["decision.reason"] for s in spans]
    assert "allow" in reasons and "group-denied" in reasons
