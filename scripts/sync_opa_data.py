#!/usr/bin/env python3
"""Generate/check the JSON mirror of policy/opa/tiers.yml.

OPA reads the YAML natively; the offline gateway reads the JSON mirror so it
needs no YAML dependency. Keep them in lockstep:

    python scripts/sync_opa_data.py          # regenerate tiers.json from YAML
    python scripts/sync_opa_data.py --check  # fail if the mirror is stale

Requires pyyaml (available in CI / lab). This is a dev/CI tool, not part of the
offline runtime path.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
YAML_PATH = ROOT / "policy" / "opa" / "tiers.yml"
JSON_PATH = ROOT / "policy" / "opa" / "tiers.json"


def _render() -> str:
    import yaml

    with open(YAML_PATH, encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def main(argv: list[str]) -> int:
    rendered = _render()
    check = "--check" in argv
    if check:
        current = JSON_PATH.read_text(encoding="utf-8") if JSON_PATH.exists() else ""
        if current != rendered:
            print("tiers.json is stale; run: python scripts/sync_opa_data.py", file=sys.stderr)
            return 1
        print("tiers.json is in sync with tiers.yml")
        return 0
    JSON_PATH.write_text(rendered, encoding="utf-8")
    print(f"wrote {JSON_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
