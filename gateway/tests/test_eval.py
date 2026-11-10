"""Tests for the eval harness (task 13 + polish).

Assert correct per-case outcomes, coverage of every reason code, and well-formed
latency metrics from a real run (LocalPdp offline; parity-tested against OPA).
No metric *values* are hard-coded into the README -- numbers come only from a
committed harness run.
"""

from __future__ import annotations

import json

from eval.runner import ATTACK_SUITE, BENIGN_SUITE, run_suite, write_result

# Small latency budget keeps the unit tests fast; a dedicated test covers >=200.
_FAST = {"warmup": 3, "latency_samples": 20}

_ALL_REASONS = {
    "allow",
    "no-allowlist",
    "policy-deny",
    "group-denied",
    "description-drift",
    "tier-deny",
    "approval-rejected",
    "approval-timeout",
    "break-glass-granted",
    "identity-invalid",
    "policy-load-failed",
}


def test_suite_sizes_meet_minimums():
    assert len(ATTACK_SUITE) >= 30
    assert len(BENIGN_SUITE) >= 15


def test_every_case_outcome_is_correct():
    result = run_suite(**_FAST)
    incorrect = [c for c in result.cases if not c["correct"]]
    assert incorrect == [], f"unexpected outcomes: {incorrect}"


def test_attack_suite_fully_blocked_and_benign_not_false_blocked():
    result = run_suite(**_FAST)
    assert result.block_rate == 1.0
    assert result.benign_false_block_rate == 0.0


def test_all_reason_codes_are_exercised():
    reasons = {c["reason"] for c in run_suite(**_FAST).cases}
    missing = _ALL_REASONS - reasons
    assert not missing, f"reason codes not exercised: {missing}"


def test_latency_metrics_well_formed_and_ordered():
    result = run_suite(warmup=5, latency_samples=200)
    assert result.latency_n == 200
    assert result.overhead_p50_ms >= 0.0
    assert result.overhead_p95_ms >= result.overhead_p50_ms
    assert result.overhead_p99_ms >= result.overhead_p95_ms
    assert result.cold_start_ms >= 0.0  # cold start reported separately


def test_specific_attack_reasons():
    by_name = {c["name"]: c for c in run_suite(**_FAST).cases}
    # Allowlist deny (legal) vs allowlist miss (hr) are distinct reason codes.
    assert by_name["allowlist-deny-legal"]["reason"] == "policy-deny"
    assert by_name["allowlist-miss-hr"]["reason"] == "no-allowlist"
    # Four-eyes with the SAME approver twice must NOT grant.
    assert by_name["four-eyes-same-approver-twice"]["actual_allowed"] is False
    # Fail closed when policy/lockfile cannot be loaded.
    assert by_name["policy-unavailable"]["reason"] == "policy-load-failed"
    assert by_name["lockfile-unavailable"]["reason"] == "policy-load-failed"
    # tier-deny and approval-timeout.
    assert by_name["tier-deny-bulk-delete"]["reason"] == "tier-deny"
    assert by_name["approval-timeout"]["reason"] == "approval-timeout"
    # A valid justified break-glass grant is allowed and flagged.
    assert by_name["break-glass-granted"]["actual_allowed"] is True
    assert by_name["break-glass-granted"]["reason"] == "break-glass-granted"


def test_result_is_json_serialisable_and_persisted(tmp_path):
    result = run_suite(**_FAST)
    path = tmp_path / "results.json"
    write_result(result, str(path))
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["total"] == result.total
    assert "block_rate" in loaded
    assert loaded["pdp"] == "local"
    assert "overhead_p99_ms" in loaded
    assert "cold_start_ms" in loaded
