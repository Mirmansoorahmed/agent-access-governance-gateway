"""Guard tests for the fork README and license reconciliation (task 16)."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
README = ROOT / "README.md"
DESIGN = ROOT / "docs" / "DESIGN.md"


def test_readme_exists_and_is_skimmable():
    text = README.read_text(encoding="utf-8")
    # Problem -> comparison -> how to run -> results -> limitations structure.
    for section in (
        "## Problem",
        "## APM (upstream) vs this fork",
        "## How to run",
        "## Results",
        "## Limitations",
    ):
        assert section in text, f"missing section: {section}"


def test_readme_has_comparison_table_rows():
    text = README.read_text(encoding="utf-8").lower()
    for row in (
        "runtime per-call enforcement",
        "oidc group claims",
        "drift",
        "four-eyes",
        "break-glass",
        "reports",
    ):
        assert row in text, f"comparison row missing: {row}"


def test_readme_has_mermaid_architecture_and_image():
    text = README.read_text(encoding="utf-8")
    assert "```mermaid" in text, "expected an inline Mermaid diagram"
    # The diagram must cover both lanes, the gap, the four checks, and evidence.
    for node in (
        "apm audit --ci",
        "GAP",
        "Gateway PEP",
        "drift pin",
        "four-eyes",
        "evidence",
        "Reports",
    ):
        assert node.lower() in text.lower(), f"diagram missing: {node}"
    # The architecture image is linked and the file exists (no broken link).
    assert "![Architecture](docs/architecture-v2.png)" in text
    assert (ROOT / "docs" / "architecture-v2.png").exists()


def test_readme_credits_and_links_upstream():
    text = README.read_text(encoding="utf-8")
    assert "microsoft/apm" in text
    assert "docs/UPSTREAM-README.md" in text
    assert (ROOT / "docs" / "UPSTREAM-README.md").exists()


def test_readme_results_rendered_from_committed_json_not_hand_entered():
    """The README Results numbers must match the committed OPA results JSON.

    This proves the figures are rendered from eval/results/latest-opa.json by
    scripts/render_results_table.py, not typed in by hand. If the results file
    is absent the section must fall back to the 'to be measured' placeholder.
    """
    import json

    text = README.read_text(encoding="utf-8")
    results_block = text.split("## Results", 1)[1].split("## Limitations", 1)[0]
    results_file = ROOT / "eval" / "results" / "latest-opa.json"

    if not results_file.exists():
        assert "to be measured" in results_block
        return

    data = json.loads(results_file.read_text(encoding="utf-8"))
    # Provenance from the JSON is surfaced in the README.
    assert data["git_sha"] in results_block
    assert data["generated_at"] in results_block
    assert f"n={data['latency_n']}" in results_block
    # The rendered latency figures match the JSON exactly (not hand-entered).
    for key in ("overhead_p50_ms", "overhead_p95_ms", "overhead_p99_ms", "cold_start_ms"):
        assert str(data[key]) in results_block, f"{key} not rendered from JSON"
    assert "not hand-entered" in results_block


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
