"""Helpers to mark/skip OPA-dependent tests when the binary is absent.

The offline sandbox has no ``opa`` binary; the maintainer (OPA 1.22.3) and CI do.
Tests needing a real OPA use ``@requires_opa`` so they skip cleanly elsewhere.
"""

from __future__ import annotations

import pytest

from gateway.opa_client import opa_available

requires_opa = pytest.mark.skipif(
    not opa_available(),
    reason="requires the 'opa' binary on PATH (maintainer/CI only)",
)

# Paths for the real OPA adapter in parity tests.
from pathlib import Path  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent.parent
OPA_BUNDLE_DIR = str(_ROOT / "policy" / "opa")
OPA_DATA_FILE = str(_ROOT / "policy" / "opa" / "tiers.yml")
