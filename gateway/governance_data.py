"""Load the shared governance data document for LocalPdp (offline-safe).

OPA reads ``policy/opa/tiers.yml`` natively. The offline gateway/tests need the
same data without a YAML dependency, so we keep a committed JSON mirror at
``gateway/data/tiers.json`` -- deliberately OUTSIDE ``policy/opa/`` so that
``opa test policy/opa`` and ``opa eval --data policy/opa`` do not load both the
YAML and the JSON (which would raise a data merge conflict at
``data.governance``). The mirror is generated from the YAML by
``scripts/sync_opa_data.py`` (``make opa-data``) and checked in CI. This loader
prefers YAML when ``pyyaml`` is importable (CI / lab) and falls back to the JSON
mirror offline -- a sync test asserts the two agree.
"""

from __future__ import annotations

import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
YAML_PATH = _ROOT / "policy" / "opa" / "tiers.yml"
JSON_PATH = _ROOT / "gateway" / "data" / "tiers.json"


def load_governance_document() -> dict:
    """Return the full data document (top-level ``governance`` key preserved)."""
    try:
        import yaml  # type: ignore
    except ImportError:
        yaml = None  # offline fallback to the JSON mirror

    if yaml is not None and YAML_PATH.exists():
        with open(YAML_PATH, encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    if JSON_PATH.exists():
        return json.loads(JSON_PATH.read_text(encoding="utf-8"))
    raise FileNotFoundError(f"no governance data at {YAML_PATH} or {JSON_PATH}")


def load_governance() -> dict:
    """Return just the ``governance`` mapping consumed by LocalPdp.from_data."""
    return load_governance_document().get("governance", {})
