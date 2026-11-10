"""Tests for the MCP proxy shell and end-to-end allow/deny wiring (task 3)."""

from __future__ import annotations

from gateway.decision import DecisionEngine
from gateway.errors import GOVERNANCE_DENIED_CODE, Reason
from gateway.identity import HmacTokenVerifier
from gateway.opa_client import LocalPdp
from gateway.pins import PinStore
from gateway.policy_loader import EffectivePolicy, McpAllowlist
from gateway.proxy import Gateway
from gateway.tests.factories import TEST_SECRET, TOOL, make_engine, make_upstream, valid_token


def _gateway(engine: DecisionEngine, upstream) -> Gateway:
    return Gateway(engine=engine, upstream=upstream)


def test_tools_list_is_forwarded_and_not_blocked():
    upstream = make_upstream()
    engine = make_engine(upstream=upstream)
    gw = _gateway(engine, upstream)
    resp = gw.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"server": "crm"}}
    )
    assert resp["result"]["tools"][0]["name"] == TOOL["name"]


def test_allow_path_forwards_to_upstream():
    upstream = make_upstream()
    engine = make_engine(upstream=upstream)
    gw = _gateway(engine, upstream)
    resp = gw.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "server": "crm",
                "name": "lookup_client",
                "arguments": {"id": "N-1"},
                "token": valid_token(),
            },
        }
    )
    assert "error" not in resp
    assert resp["result"]["tier"] == "allow"
    # upstream actually invoked
    assert upstream.calls == [("crm", "lookup_client", {"id": "N-1"})]


def test_denied_call_is_not_forwarded_and_carries_reason():
    upstream = make_upstream()
    # policy allow=None -> deny-by-default (Check 1)
    engine = make_engine(upstream=upstream, allow=None)
    gw = _gateway(engine, upstream)
    resp = gw.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"server": "crm", "name": "lookup_client", "token": valid_token()},
        }
    )
    assert resp["error"]["code"] == GOVERNANCE_DENIED_CODE
    assert resp["error"]["data"]["reason"] == str(Reason.NO_ALLOWLIST)
    assert upstream.calls == []  # never forwarded


def test_unknown_method_returns_method_not_found():
    upstream = make_upstream()
    gw = _gateway(make_engine(upstream=upstream), upstream)
    resp = gw.handle_message({"jsonrpc": "2.0", "id": 4, "method": "tools/bogus"})
    assert resp["error"]["code"] == -32601


def test_handle_raw_rejects_invalid_json():
    upstream = make_upstream()
    gw = _gateway(make_engine(upstream=upstream), upstream)
    import json

    resp = json.loads(gw.handle_raw("{not json"))
    assert resp["error"]["code"] == -32602


def test_fail_closed_when_policy_load_failed():
    # Simulate a load failure by building an engine whose policy denies all and
    # whose PDP raises -- but the earliest fail-closed point is identity/policy.
    # Here we assert a raising PDP yields policy-load-failed (fail closed).
    upstream = make_upstream()

    class _BoomPdp:
        def evaluate(self, _opa_input):
            raise RuntimeError("opa unreachable")

    engine = DecisionEngine(
        policy=EffectivePolicy(mcp=McpAllowlist(allow=("crm/*",))),
        verifier=HmacTokenVerifier(secret=TEST_SECRET),
        pdp=_BoomPdp(),
        pin_store=PinStore(),
        catalogue=upstream,
    )
    gw = _gateway(engine, upstream)
    resp = gw.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"server": "crm", "name": "lookup_client", "token": valid_token()},
        }
    )
    assert resp["error"]["data"]["reason"] == str(Reason.POLICY_LOAD_FAILED)
    assert upstream.calls == []


def test_on_decision_hook_is_invoked():
    upstream = make_upstream()
    seen = []
    gw = Gateway(
        engine=make_engine(upstream=upstream),
        upstream=upstream,
        on_decision=lambda d, c: seen.append((d.reason, c.tool)),
    )
    gw.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"server": "crm", "name": "lookup_client", "token": valid_token()},
        }
    )
    assert seen and seen[0][1] == "lookup_client"


def test_local_pdp_default_tier_deny_for_unlisted_tool():
    pdp = LocalPdp(access={}, tiers={}, default_tier="deny")
    from gateway.opa_client import OpaInput

    decision = pdp.evaluate(OpaInput(server="crm", tool="x", groups=("advisors",)))
    assert decision.allow is False
    assert decision.tier == "deny"
