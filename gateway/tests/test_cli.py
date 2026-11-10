"""Tests for the approval CLI (task 9)."""

from __future__ import annotations

from click.testing import CliRunner

from gateway.approvals import ApprovalStore, args_hash
from gateway.cli import cli


def _store_path(tmp_path):
    return str(tmp_path / "approvals.json")


def test_list_empty(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["--store", _store_path(tmp_path), "list"])
    assert result.exit_code == 0
    assert "No pending" in result.output


def test_list_shows_enqueued(tmp_path):
    path = _store_path(tmp_path)
    store = ApprovalStore(path=path)
    store.enqueue("u1", "crm", "export_clients", args_hash({"id": "A"}), "four-eyes")
    result = CliRunner().invoke(cli, ["--store", path, "list"])
    assert "export_clients" in result.output
    assert "four-eyes" in result.output


def test_grant_releases_a_call(tmp_path):
    path = _store_path(tmp_path)
    ah = args_hash({})
    result = CliRunner().invoke(
        cli,
        [
            "--store",
            path,
            "grant",
            "--agent",
            "u1",
            "--server",
            "crm",
            "--tool",
            "lookup_client",
            "--args-hash",
            ah,
            "--tier",
            "ask",
            "--approver",
            "alice",
        ],
    )
    assert result.exit_code == 0, result.output
    # The grant is now consumable from a fresh store instance (the gateway).
    store = ApprovalStore(path=path)
    assert store.consume_valid_grant("u1", "crm", "lookup_client", ah) is not None


def test_four_eyes_requires_two_distinct_approvers(tmp_path):
    path = _store_path(tmp_path)
    ah = args_hash({})
    # One approver -> error.
    result = CliRunner().invoke(
        cli,
        [
            "--store",
            path,
            "grant",
            "--agent",
            "u1",
            "--server",
            "crm",
            "--tool",
            "export_clients",
            "--args-hash",
            ah,
            "--tier",
            "four-eyes",
            "--approver",
            "alice",
        ],
    )
    assert result.exit_code != 0
    assert "two distinct" in result.output
    # Two distinct approvers -> success.
    ok = CliRunner().invoke(
        cli,
        [
            "--store",
            path,
            "grant",
            "--agent",
            "u1",
            "--server",
            "crm",
            "--tool",
            "export_clients",
            "--args-hash",
            ah,
            "--tier",
            "four-eyes",
            "--approver",
            "alice",
            "--approver",
            "bob",
        ],
    )
    assert ok.exit_code == 0, ok.output


def test_break_glass_requires_justification(tmp_path):
    path = _store_path(tmp_path)
    ah = args_hash({})
    result = CliRunner().invoke(
        cli,
        [
            "--store",
            path,
            "grant",
            "--agent",
            "u1",
            "--server",
            "billing",
            "--tool",
            "issue_refund",
            "--args-hash",
            ah,
            "--tier",
            "break-glass",
            "--approver",
            "alice",
        ],
    )
    assert result.exit_code != 0
    assert "justification" in result.output


def test_deny_removes_pending_and_logs(tmp_path):
    path = _store_path(tmp_path)
    ah = args_hash({})
    store = ApprovalStore(path=path)
    store.enqueue("u1", "crm", "lookup_client", ah, "ask")
    result = CliRunner().invoke(
        cli,
        [
            "--store",
            path,
            "deny",
            "--agent",
            "u1",
            "--server",
            "crm",
            "--tool",
            "lookup_client",
            "--args-hash",
            ah,
            "--approver",
            "alice",
            "--reason",
            "risky",
        ],
    )
    assert result.exit_code == 0, result.output
    reloaded = ApprovalStore(path=path)
    assert reloaded.pending() == []
    assert any(e["event"] == "reject" for e in reloaded.log)
