"""Evidence log -- one OpenTelemetry-shaped span per decision (task 10).

Each decision produces a span whose attributes feed the audit reports (task 11).
Exporting is pluggable so the core is testable offline without the OpenTelemetry
SDK:

* :class:`SpanExporter` protocol -- ``export(span: dict)``.
* :class:`InMemorySpanExporter` -- collects spans (tests / eval harness).
* :class:`FileSpanExporter` -- appends spans as JSON lines (lab-local, no cloud).
* :func:`build_otlp_exporter` -- wires the real OTel SDK -> OTLP collector in
  CI / the lab (not on the offline path).

Argument redaction (R9.2): raw argument *values* are never stored. The span
records only the argument key names and a stable hash of the full argument set,
so an auditor can correlate calls without leaking sensitive payloads.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

from .decision import CallContext, Decision

SPAN_NAME = "governance.decision"


def redact_arguments(arguments: dict | None) -> dict:
    """Return an evidence-safe summary of call arguments (no raw values)."""
    arguments = arguments or {}
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    return {
        "keys": sorted(arguments.keys()),
        "count": len(arguments),
        "hash": "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def build_span(decision: Decision, ctx: CallContext) -> dict:
    """Build the OTel-shaped span document for one decision."""
    claims = decision.claims
    return {
        "name": SPAN_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attributes": {
            "agent.id": claims.subject if claims else "",
            "agent.role": claims.role if claims else "",
            "agent.department": claims.department if claims else "",
            "agent.seniority": claims.seniority if claims else "",
            "agent.groups": list(claims.groups) if claims else [],
            "mcp.server": ctx.server,
            "mcp.tool": ctx.tool,
            "decision.allowed": decision.allowed,
            "decision.reason": str(decision.reason),
            "decision.tier": decision.tier,
            "decision.detail": decision.detail,
            "drift.pin_hash": decision.pin_hash,
            "drift.live_hash": decision.live_hash,
            "arguments": redact_arguments(ctx.arguments),
        },
    }


@runtime_checkable
class SpanExporter(Protocol):
    def export(self, span: dict) -> None: ...


@dataclass
class InMemorySpanExporter:
    """Collects spans in memory (tests, eval harness)."""

    spans: list[dict] = field(default_factory=list)

    def export(self, span: dict) -> None:
        self.spans.append(span)


@dataclass
class FileSpanExporter:
    """Appends spans as JSON lines to a local file (no cloud dependency)."""

    path: str
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def export(self, span: dict) -> None:
        with self._lock:
            p = Path(self.path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(span, sort_keys=True) + "\n")


@dataclass
class EvidenceRecorder:
    """Builds and exports a span per decision. Use as the proxy ``on_decision``."""

    exporter: SpanExporter

    def record(self, decision: Decision, ctx: CallContext) -> dict:
        span = build_span(decision, ctx)
        self.exporter.export(span)
        return span

    # Convenience so an EvidenceRecorder can be passed directly as on_decision.
    def __call__(self, decision: Decision, ctx: CallContext) -> None:
        self.record(decision, ctx)


def load_spans(path: str) -> list[dict]:
    """Read JSONL spans back (used by report generators)."""
    p = Path(path)
    if not p.exists():
        return []
    spans = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            spans.append(json.loads(line))
    return spans


def build_otlp_exporter(*_args, **_kwargs):  # pragma: no cover - needs otel sdk
    """Wire the real OpenTelemetry SDK -> OTLP collector (CI / lab only).

    Requires opentelemetry-sdk + an exporter package, unavailable offline. The
    returned object must satisfy :class:`SpanExporter` by mapping ``export`` onto
    an OTel span with the same attributes as :func:`build_span`.
    """
    raise NotImplementedError("OTLP export is wired in CI/lab; use FileSpanExporter offline")
