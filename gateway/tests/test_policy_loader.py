"""Tests for the read-only policy loader and Check-1 allowlist (task 1).

Also includes a contract test asserting the dependency-free glob matcher agrees
with upstream ``apm_cli.policy.matcher`` when that module is importable (it is
skipped offline, where ``apm_cli`` dependencies are absent).
"""

from __future__ import annotations

import pytest

from gateway.errors import GatewayDenied, Reason
from gateway.policy_loader import (
    EffectivePolicy,
    LockfilePin,
    McpAllowlist,
    MissingLockfileError,
    load_effective_policy,
    lockfile_pins_from_data,
    matches_pattern,
)


# --- Check 1: McpAllowlist.decision -------------------------------------
def test_deny_wins_over_allow():
    acl = McpAllowlist(allow=("srv/*",), deny=("srv/danger",))
    ok, reason = acl.decision("srv/danger")
    assert ok is False
    assert reason is Reason.POLICY_DENY


def test_allow_none_is_deny_by_default_at_runtime():
    acl = McpAllowlist(allow=None)
    ok, reason = acl.decision("srv/tool")
    assert ok is False
    assert reason is Reason.NO_ALLOWLIST


def test_not_in_allowlist_is_denied():
    acl = McpAllowlist(allow=("srv/read",))
    ok, reason = acl.decision("srv/write")
    assert ok is False
    assert reason is Reason.NO_ALLOWLIST


def test_allowed_tool_passes():
    acl = McpAllowlist(allow=("srv/read",))
    ok, reason = acl.decision("srv/read")
    assert ok is True
    assert reason is Reason.ALLOW


def test_wildcard_single_segment():
    acl = McpAllowlist(allow=("srv/*",))
    assert acl.decision("srv/read")[0] is True
    # ``*`` does not cross a '/': a deeper path should not match "srv/*".
    assert acl.decision("srv/sub/read")[0] is False


def test_double_wildcard_crosses_segments():
    acl = McpAllowlist(allow=("srv/**",))
    assert acl.decision("srv/sub/read")[0] is True


# --- glob semantics -----------------------------------------------------
@pytest.mark.parametrize(
    ("value", "pattern", "expected"),
    [
        ("a/b", "a/b", True),
        ("a/b", "a/*", True),
        ("a/b/c", "a/*", False),
        ("a/b/c", "a/**", True),
        ("a/b", "x/*", False),
        ("", "a", False),
        ("a", "", False),
    ],
)
def test_matches_pattern(value, pattern, expected):
    assert matches_pattern(value, pattern) is expected


# --- load_effective_policy fails closed ---------------------------------
class _BoomBackend:
    def load(self):
        raise RuntimeError("cannot read policy")


class _WrongTypeBackend:
    def load(self):
        return {"not": "an EffectivePolicy"}


class _OkBackend:
    def load(self):
        return EffectivePolicy(mcp=McpAllowlist(allow=("srv/*",)))


def test_load_failure_is_policy_load_failed():
    with pytest.raises(GatewayDenied) as excinfo:
        load_effective_policy(_BoomBackend())
    assert excinfo.value.reason is Reason.POLICY_LOAD_FAILED


def test_wrong_return_type_is_policy_load_failed():
    with pytest.raises(GatewayDenied) as excinfo:
        load_effective_policy(_WrongTypeBackend())
    assert excinfo.value.reason is Reason.POLICY_LOAD_FAILED


def test_ok_backend_returns_policy():
    policy = load_effective_policy(_OkBackend())
    assert isinstance(policy, EffectivePolicy)
    assert policy.mcp.allow == ("srv/*",)


# --- missing lockfile fails closed (R2.3) -------------------------------
class _MissingLockfileBackend:
    def load(self):
        raise MissingLockfileError("apm.lock.yaml not found at ./apm.lock.yaml")


def test_missing_lockfile_is_policy_load_failed():
    with pytest.raises(GatewayDenied) as excinfo:
        load_effective_policy(_MissingLockfileBackend())
    assert excinfo.value.reason is Reason.POLICY_LOAD_FAILED
    assert "apm.lock.yaml" in excinfo.value.detail


def test_lockfile_pins_from_data_parses_entries():
    data = {
        "dependencies": [
            {"name": "a", "version": "1.0.0", "content_hash": "sha256:aa"},
            {"name": "b"},
        ]
    }
    pins = lockfile_pins_from_data(data)
    assert pins[0] == LockfilePin(name="a", version="1.0.0", content_hash="sha256:aa")
    assert pins[1] == LockfilePin(name="b", version="", content_hash="")


def test_lockfile_pins_from_empty_is_empty():
    assert lockfile_pins_from_data(None) == ()
    assert lockfile_pins_from_data({}) == ()


# --- Check 1 matcher prefers upstream, falls back offline ----------------
def test_matcher_resolver_falls_back_offline():
    """Offline (no apm_cli), the resolver returns a working fallback matcher."""
    from gateway import policy_loader

    matcher = policy_loader._resolve_first_matcher()
    assert matcher("srv/read", ("srv/*",)) == "srv/*"
    assert matcher("srv/read", ("other/*",)) is None


def test_matcher_resolver_prefers_upstream_when_importable(monkeypatch):
    """When apm_cli.policy.matcher imports, the resolver returns its function."""
    import sys
    import types

    sentinel = types.ModuleType("apm_cli.policy.matcher")
    calls = {}

    def _fake_first_matching_pattern(value, patterns):
        calls["used"] = True
        return patterns[0] if patterns else None

    sentinel.first_matching_pattern = _fake_first_matching_pattern
    monkeypatch.setitem(sys.modules, "apm_cli", types.ModuleType("apm_cli"))
    monkeypatch.setitem(sys.modules, "apm_cli.policy", types.ModuleType("apm_cli.policy"))
    monkeypatch.setitem(sys.modules, "apm_cli.policy.matcher", sentinel)

    from gateway import policy_loader

    resolved = policy_loader._resolve_first_matcher()
    assert resolved("x", ("p",)) == "p"
    assert calls.get("used") is True


# --- contract: fallback glob agrees with upstream matcher ----------------
def test_glob_matches_upstream_matcher_when_available():
    """When ``apm_cli.policy.matcher`` imports, our fallback must agree.

    Skipped offline where ``apm_cli`` dependencies (requests/pyyaml) are absent.
    """
    pytest.importorskip("apm_cli.policy.matcher")
    from apm_cli.policy.matcher import matches_pattern as upstream_match

    cases = [
        ("a/b", "a/b"),
        ("a/b", "a/*"),
        ("a/b/c", "a/*"),
        ("a/b/c", "a/**"),
        ("srv/read", "srv/*"),
        ("srv/sub/read", "srv/*"),
    ]
    for value, pattern in cases:
        assert matches_pattern(value, pattern) == upstream_match(value, pattern)
