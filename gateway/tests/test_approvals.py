"""Tests for approval tiers and the grant/queue state machine (task 8)."""

from __future__ import annotations

import pytest

from gateway.approvals import (
    ApprovalError,
    ApprovalStore,
    QueueingApprovalGate,
    args_hash,
)
from gateway.decision import CallContext
from gateway.errors import Reason
from gateway.tests.factories import make_engine, valid_token


# --- store-level tier rules ---------------------------------------------
def test_ask_grant_requires_an_approver():
    store = ApprovalStore()
    with pytest.raises(ApprovalError):
        store.grant("u1", "crm", "export_clients", "h", "ask", approvers=())


def test_four_eyes_requires_two_distinct_approvers():
    store = ApprovalStore()
    with pytest.raises(ApprovalError):
        store.grant("u1", "crm", "export_clients", "h", "four-eyes", approvers=("a",))
    with pytest.raises(ApprovalError):
        store.grant("u1", "crm", "export_clients", "h", "four-eyes", approvers=("a", "a"))
    # Two distinct is fine.
    grant = store.grant("u1", "crm", "export_clients", "h", "four-eyes", approvers=("a", "b"))
    assert grant.approvers == ("a", "b")


def test_break_glass_requires_justification_and_approver():
    store = ApprovalStore()
    with pytest.raises(ApprovalError):
        store.grant(
            "u1", "billing", "issue_refund", "h", "break-glass", approvers=("a",), justification=""
        )
    grant = store.grant(
        "u1",
        "billing",
        "issue_refund",
        "h",
        "break-glass",
        approvers=("a",),
        justification="prod incident 42",
    )
    assert grant.justification == "prod incident 42"


def test_grant_is_single_use():
    store = ApprovalStore()
    store.grant("u1", "crm", "export_clients", "h", "ask", approvers=("a",))
    assert store.consume_valid_grant("u1", "crm", "export_clients", "h") is not None
    # Second consume fails (single-use).
    assert store.consume_valid_grant("u1", "crm", "export_clients", "h") is None


def test_grant_expires_with_ttl():
    store = ApprovalStore(grant_ttl=0)  # expires immediately
    store.grant("u1", "crm", "export_clients", "h", "ask", approvers=("a",))
    # With ttl=0, now > created_at+0 only after time passes; force expiry check.
    grant = store._grants[store.key("u1", "crm", "export_clients", "h")]
    assert grant.is_expired(now=grant.created_at + 1) is True


def test_args_hash_scopes_grant_to_arg_set():
    assert args_hash({"id": "A"}) != args_hash({"id": "B"})
    assert args_hash({"a": 1, "b": 2}) == args_hash({"b": 2, "a": 1})


# --- gate through the engine --------------------------------------------
def _engine(tier: str, store: ApprovalStore):
    gate = QueueingApprovalGate(store=store)
    return make_engine(tier=tier, approval_gate=gate)


def _call(args=None):
    return CallContext(
        server="crm", tool="lookup_client", arguments=args or {}, token=valid_token(subject="u1")
    )


def test_ask_without_grant_denies_and_enqueues():
    store = ApprovalStore()
    engine = _engine("ask", store)
    decision = engine.decide(_call())
    assert decision.allowed is False
    assert decision.reason is Reason.APPROVAL_REJECTED
    assert len(store.pending()) == 1


def test_ask_with_grant_allows_once():
    store = ApprovalStore()
    engine = _engine("ask", store)
    ah = args_hash({})
    store.grant("u1", "crm", "lookup_client", ah, "ask", approvers=("sec",))
    first = engine.decide(_call())
    assert first.allowed is True
    assert first.reason is Reason.ALLOW
    # Grant consumed: a second identical call is denied again.
    assert engine.decide(_call()).allowed is False


def test_four_eyes_grant_allows():
    store = ApprovalStore()
    engine = _engine("four-eyes", store)
    ah = args_hash({})
    store.grant("u1", "crm", "lookup_client", ah, "four-eyes", approvers=("a", "b"))
    decision = engine.decide(_call())
    assert decision.allowed is True
    assert decision.detail == "a; b"


def test_break_glass_grant_is_flagged():
    store = ApprovalStore()
    engine = _engine("break-glass", store)
    ah = args_hash({})
    store.grant(
        "u1", "crm", "lookup_client", ah, "break-glass", approvers=("a",), justification="sev1"
    )
    decision = engine.decide(_call())
    assert decision.allowed is True
    assert decision.reason is Reason.BREAK_GLASS_GRANTED


def test_grant_does_not_apply_to_different_args():
    store = ApprovalStore()
    engine = _engine("ask", store)
    store.grant("u1", "crm", "lookup_client", args_hash({"id": "A"}), "ask", approvers=("sec",))
    # Call with different args must not be covered by the grant.
    assert engine.decide(_call(args={"id": "B"})).allowed is False


def test_expired_pending_reports_timeout():
    store = ApprovalStore(pending_ttl=0)
    engine = _engine("ask", store)
    engine.decide(_call())  # enqueues
    req = store._pending[store.key("u1", "crm", "lookup_client", args_hash({}))]
    # Force the request to look expired by backdating it.
    req.created_at -= 10
    decision = engine.decide(_call())
    assert decision.reason is Reason.APPROVAL_TIMEOUT


def test_sequential_four_eyes_completes_on_second_distinct_approver():
    store = ApprovalStore()
    ah = args_hash({})
    # First approver -> still partial, no grant yet.
    assert store.approve("u1", "crm", "export_clients", ah, "four-eyes", approver="alice") is None
    assert store.partial_approvers("u1", "crm", "export_clients", ah) == ("alice",)
    # Same approver again -> still partial (no double count).
    assert store.approve("u1", "crm", "export_clients", ah, "four-eyes", approver="alice") is None
    assert store.partial_approvers("u1", "crm", "export_clients", ah) == ("alice",)
    # Second distinct approver -> grant minted.
    grant = store.approve("u1", "crm", "export_clients", ah, "four-eyes", approver="bob")
    assert grant is not None
    assert set(grant.approvers) == {"alice", "bob"}
    assert store.consume_valid_grant("u1", "crm", "export_clients", ah) is not None


def test_sequential_ask_grants_on_first_approve():
    store = ApprovalStore()
    ah = args_hash({})
    grant = store.approve("u1", "crm", "lookup_client", ah, "ask", approver="alice")
    assert grant is not None
    assert grant.approvers == ("alice",)


def test_sequential_break_glass_requires_justification():
    store = ApprovalStore()
    ah = args_hash({})
    with pytest.raises(ApprovalError):
        store.approve("u1", "billing", "issue_refund", ah, "break-glass", approver="a")
    grant = store.approve(
        "u1", "billing", "issue_refund", ah, "break-glass", approver="a", justification="sev1"
    )
    assert grant is not None


def test_reject_clears_partial_four_eyes():
    store = ApprovalStore()
    ah = args_hash({})
    store.approve("u1", "crm", "export_clients", ah, "four-eyes", approver="alice")
    store.reject("u1", "crm", "export_clients", ah, approver="carol", reason="no")
    assert store.partial_approvers("u1", "crm", "export_clients", ah) == ()


def test_partial_four_eyes_persists(tmp_path):
    path = str(tmp_path / "approvals.json")
    store = ApprovalStore(path=path)
    ah = args_hash({})
    store.approve("u1", "crm", "export_clients", ah, "four-eyes", approver="alice")
    # Second approver in a fresh process completes it.
    reloaded = ApprovalStore(path=path)
    grant = reloaded.approve("u1", "crm", "export_clients", ah, "four-eyes", approver="bob")
    assert grant is not None
    assert set(grant.approvers) == {"alice", "bob"}


def test_store_persists_across_instances(tmp_path):
    path = str(tmp_path / "approvals.json")
    store = ApprovalStore(path=path)
    store.grant("u1", "crm", "export_clients", "h", "four-eyes", approvers=("a", "b"))
    store.enqueue("u2", "crm", "lookup_client", "h2", "ask")
    # A new instance (e.g. the CLI process) sees the same state.
    reloaded = ApprovalStore(path=path)
    assert reloaded.consume_valid_grant("u1", "crm", "export_clients", "h") is not None
    assert len(reloaded.pending()) == 1
    assert any(e["event"] == "grant" for e in reloaded.log)


def test_reject_removes_pending_and_logs():
    store = ApprovalStore()
    engine = _engine("ask", store)
    engine.decide(_call())
    store.reject("u1", "crm", "lookup_client", args_hash({}), approver="sec", reason="risky")
    assert store.pending() == []
    assert any(e["event"] == "reject" for e in store.log)
