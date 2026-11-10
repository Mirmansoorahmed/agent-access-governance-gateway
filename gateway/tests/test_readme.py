"""Guard tests for the fork README and license reconciliation (task 16)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
README = ROOT / "README-governance.md"
DESIGN = ROOT / "docs" / "DESIGN.md"


def test_readme_exists_and_is_skimmable():
    text = README.read_text(encoding="utf-8")
    # Problem -> diagram -> how to run -> results -> limitations structure.
    for section in (
        "## Problem",
        "## Architecture",
        "## How to run",
        "## Results",
        "## Limitations",
        "## License",
    ):
        assert section in text, f"missing section: {section}"


def test_readme_has_no_fabricated_metrics():
    text = README.read_text(encoding="utf-8")
    # The results table must say 'to be measured', not carry numbers.
    results_block = text.split("## Results", 1)[1].split("## Limitations", 1)[0]
    assert "to be measured" in results_block
    # No percentage or ms figures smuggled into the results table.
    assert not re.search(r"\|\s*\d+(\.\d+)?\s*(%|ms)\s*\|", results_block)


def test_readme_license_matches_repo():
    text = README.read_text(encoding="utf-8")
    assert "Apache-2.0" in text
    assert "CC-BY-4.0" in text
    # Actual repo files back the claim.
    assert "Apache License" in (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Attribution 4.0" in (ROOT / "LICENSE-DOCS").read_text(encoding="utf-8")
    assert "Historical MIT" in (ROOT / "NOTICE").read_text(encoding="utf-8")


def test_design_doc_no_longer_calls_upstream_mit_current():
    text = DESIGN.read_text(encoding="utf-8")
    # MIT may only appear as 'historical'; current license is Apache-2.0/CC-BY-4.0.
    assert "Apache-2.0" in text
    assert "CC-BY-4.0" in text
    for line in text.splitlines():
        if "MIT" in line:
            assert "historical" in line.lower() or "previously published" in line.lower(), (
                f"MIT referenced without historical framing: {line}"
            )


def test_readme_links_resolve_to_repo_files():
    text = README.read_text(encoding="utf-8")
    for target in ("docs/DESIGN.md", "LICENSE", "LICENSE-DOCS", "NOTICE"):
        assert (ROOT / target).exists(), f"linked file missing: {target}"
        assert target in text
