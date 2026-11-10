"""Tests for the eval harness (task 13).

These assert the harness produces correct per-case outcomes and well-formed
metrics from a real run (LocalPdp offline; parity-tested against OPA). They do
NOT hard-code expected metric *values* into the README -- metrics come only from
a committed harness run.
"""

from __future__ import annotations

import json

from eval.runner import ATTACK_SUITE, BENIGN_SUITE, run_suite, write_result


def test_every_case_outcome_is_correct():
    result = run_suite()
    incorrect = [c for c in result.cases if not c["correct"]]
    assert incorrect == [], f"unexpected outcomes: {incorrect}"


def test_attack_suite_fully_blocked_and_benign_not_false_blocked():
    result = run_suite()
    assert result.block_rate == 1.0  # all attack cases denied
    assert result.benign_false_block_rate == 0.0  # golden path not blocked


def test_metrics_shape_and_provenance():
    result = run_suite()
    assert result.attack_total == len(ATTACK_SUITE)
    assert result.benign_total == len(BENIGN_SUITE)
    assert result.overhead_p50_ms >= 0.0
    assert result.overhead_p95_ms >= result.overhead_p50_ms
    assert result.git_sha  # provenance present
    assert result.generated_at


def test_specific_attack_reasons():
    by_name = {c["name"]: c for c in run_suite().cases}
    assert by_name["wrong-oidc-group"]["reason"] == "group-denied"
    assert by_name["description-drift"]["reason"] == "description-drift"
    assert by_name["unpinned-tool"]["reason"] == "description-drift"
    # break-glass tier without a grant is not auto-allowed.
    assert by_name["risky-without-approval"]["actual_allowed"] is False


def test_result_is_json_serialisable_and_persisted(tmp_path):
    result = run_suite()
    path = tmp_path / "results.json"
    write_result(result, str(path))
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["total"] == result.total
    assert "block_rate" in loaded
    assert loaded["pdp"] == "local"
