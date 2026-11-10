"""Tests for the evidence recorder, span shape, and arg redaction (task 10)."""

from __future__ import annotations

import pytest

from gateway.decision import CallContext
from gateway.evidence import (
    EvidenceRecorder,
    FileSpanExporter,
    InMemorySpanExporter,
    build_otlp_exporter,
    build_span,
    load_spans,
    redact_arguments,
)
from gateway.proxy import Gateway
from gateway.tests.factories import make_engine, make_upstream, valid_token


def test_redaction_keeps_keys_and_hash_not_values():
    red = redact_arguments({"id": "SECRET-123", "amount": 9999})
    assert red["keys"] == ["amount", "id"]
    assert red["count"] == 2
    assert red["hash"].startswith("sha256:")
    # No raw value leaks into the summary.
    assert "SECRET-123" not in str(red)
    assert "9999" not in str(red)


def test_redaction_hash_is_order_independent():
    assert redact_arguments({"a": 1, "b": 2})["hash"] == redact_arguments({"b": 2, "a": 1})["hash"]


def test_span_has_decision_and_identity_attributes():
    engine = make_engine(tier="allow")
    ctx = CallContext(
        server="crm",
        tool="lookup_client",
        arguments={"id": "N-1"},
        token=valid_token(role="advisor"),
    )
    decision = engine.decide(ctx)
    span = build_span(decision, ctx)
    attrs = span["attributes"]
    assert attrs["mcp.server"] == "crm"
    assert attrs["mcp.tool"] == "lookup_client"
    assert attrs["decision.allowed"] is True
    assert attrs["decision.reason"] == "allow"
    assert attrs["agent.role"] == "advisor"
    assert attrs["arguments"]["keys"] == ["id"]
    assert "N-1" not in str(span)  # value redacted


def test_recorder_exports_one_span_per_decision():
    exporter = InMemorySpanExporter()
    recorder = EvidenceRecorder(exporter=exporter)
    upstream = make_upstream()
    gw = Gateway(engine=make_engine(upstream=upstream), upstream=upstream, on_decision=recorder)
    gw.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "server": "crm",
                "name": "lookup_client",
                "arguments": {"id": "N-1"},
                "token": valid_token(),
            },
        }
    )
    assert len(exporter.spans) == 1
    assert exporter.spans[0]["attributes"]["decision.reason"] == "allow"


def test_denied_call_also_emits_a_span():
    exporter = InMemorySpanExporter()
    recorder = EvidenceRecorder(exporter=exporter)
    upstream = make_upstream()
    gw = Gateway(
        engine=make_engine(upstream=upstream, allow=None), upstream=upstream, on_decision=recorder
    )
    gw.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"server": "crm", "name": "lookup_client", "token": valid_token()},
        }
    )
    assert exporter.spans[0]["attributes"]["decision.allowed"] is False
    assert exporter.spans[0]["attributes"]["decision.reason"] == "no-allowlist"


def test_file_exporter_round_trip(tmp_path):
    path = str(tmp_path / "spans.jsonl")
    exporter = FileSpanExporter(path=path)
    engine = make_engine(tier="allow")
    ctx = CallContext(server="crm", tool="lookup_client", token=valid_token())
    exporter.export(build_span(engine.decide(ctx), ctx))
    exporter.export(build_span(engine.decide(ctx), ctx))
    spans = load_spans(path)
    assert len(spans) == 2
    assert all(s["name"] == "governance.decision" for s in spans)


def test_otlp_exporter_is_stub():
    with pytest.raises(NotImplementedError):
        build_otlp_exporter()
