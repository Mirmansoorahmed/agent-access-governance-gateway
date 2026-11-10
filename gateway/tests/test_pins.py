"""Tests for the drift pin store (task 2)."""

from __future__ import annotations

import pytest

from gateway.pins import PinStore


def test_unpinned_tool_returns_none():
    store = PinStore()
    assert store.get("srv", "tool") is None


def test_set_and_get_pin():
    store = PinStore()
    store.set_pin("srv", "tool", "sha256:abc", approved_by="alice", policy_version="1")
    assert store.get("srv", "tool") == "sha256:abc"


def test_reset_requires_approver():
    store = PinStore()
    store.set_pin("srv", "tool", "sha256:abc", approved_by="alice")
    with pytest.raises(ValueError):
        store.reset_pin("srv", "tool", approved_by="")


def test_reset_removes_pin_and_returns_record():
    store = PinStore()
    store.set_pin("srv", "tool", "sha256:abc", approved_by="alice")
    removed = store.reset_pin("srv", "tool", approved_by="bob")
    assert removed is not None
    assert removed.pin_hash == "sha256:abc"
    assert store.get("srv", "tool") is None


def test_reset_unknown_tool_returns_none():
    store = PinStore()
    assert store.reset_pin("srv", "missing", approved_by="bob") is None


def test_no_implicit_reset_on_get():
    # Reading a pin never mutates the store (no auto-reset path exists).
    store = PinStore()
    store.set_pin("srv", "tool", "sha256:abc", approved_by="alice")
    for _ in range(3):
        assert store.get("srv", "tool") == "sha256:abc"
    assert len(store.records()) == 1


def test_persistence_round_trip(tmp_path):
    path = tmp_path / "pins.json"
    store = PinStore(path)
    store.set_pin("srv", "tool", "sha256:abc", approved_by="alice", policy_version="2")
    # New instance reads from disk.
    reloaded = PinStore(path)
    assert reloaded.get("srv", "tool") == "sha256:abc"
    record = reloaded.records()[0]
    assert record.approved_by == "alice"
    assert record.policy_version == "2"
    assert record.approved_at  # timestamp recorded
