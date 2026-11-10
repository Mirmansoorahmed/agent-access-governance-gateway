"""Check 3 support: description-drift pin computation.

A drift pin is the SHA-256 over an approved tool's ``name + description +
input schema``, canonicalised so that benign serialisation differences (key
order, insignificant whitespace) do not produce a different hash. A *semantic*
change (description text, schema shape) must change the hash so the gateway can
block post-approval tool poisoning.

Pure standard library: no third-party dependency, unit-testable offline.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

# Prefix recorded alongside the digest, mirroring lockfile hash notation
# (``sha256:<hex>``) so evidence and reports read consistently.
PIN_ALGORITHM = "sha256"


def _canonicalize(value: Any) -> Any:
    """Return a canonical form of *value* for stable hashing.

    - ``dict`` keys are sorted recursively.
    - ``list`` / ``tuple`` order is preserved (order is semantically meaningful
      for things like JSON-schema ``required`` and enum lists).
    - Scalars pass through unchanged.
    """
    if isinstance(value, dict):
        return {key: _canonicalize(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    return value


def canonical_tool_repr(
    name: str,
    description: str | None,
    input_schema: dict | None,
) -> str:
    """Build the deterministic string hashed into a pin.

    ``description`` of ``None`` and ``""`` are treated identically (empty), and
    a missing ``input_schema`` is treated as ``{}`` so absent-vs-empty does not
    flip the hash.
    """
    payload = {
        "name": name,
        "description": description or "",
        "input_schema": _canonicalize(input_schema or {}),
    }
    # ``sort_keys`` at the top level plus the recursive canonicalisation above
    # guarantees a single representation. ``separators`` strips insignificant
    # whitespace. ``ensure_ascii=False`` keeps unicode stable across platforms.
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_pin(
    name: str,
    description: str | None,
    input_schema: dict | None,
) -> str:
    """Compute the drift pin ``sha256:<hex>`` for one tool definition."""
    canonical = canonical_tool_repr(name, description, input_schema)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"{PIN_ALGORITHM}:{digest}"


def pin_for_tool(tool: dict) -> str:
    """Compute a pin from an MCP ``tools/list`` entry.

    Accepts both ``inputSchema`` (MCP wire form) and ``input_schema``.
    """
    return compute_pin(
        name=tool.get("name", ""),
        description=tool.get("description"),
        input_schema=tool.get("inputSchema", tool.get("input_schema")),
    )
