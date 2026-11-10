"""Guard tests for the fork CI workflow (task 15).

Text-level assertions (no YAML dependency offline) that the workflow wires the
required steps: build apm from this fork's src/apm_cli, install OPA 1.22.3, run
apm audit --ci, the gateway tests, opa test, and the eval smoke.
"""

from __future__ import annotations

from pathlib import Path

WORKFLOW = (
    Path(__file__).resolve().parent.parent.parent / ".github" / "workflows" / "gateway-ci.yml"
)


def _text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_workflow_exists():
    assert WORKFLOW.exists()


def test_builds_apm_from_fork_source():
    text = _text()
    assert 'pip install -e ".[dev,reports]"' in text  # forked src/apm_cli, not a release
    assert "apm audit --ci" in text


def test_installs_pinned_opa():
    text = _text()
    assert "OPA_VERSION: '1.22.3'" in text
    assert "openpolicyagent.org/downloads" in text


def test_runs_opa_and_gateway_tests():
    text = _text()
    assert "make opa-test" in text
    assert "make opa-data-check" in text
    assert "pytest-gateway.ini" in text


def test_runs_eval_smoke_opa_backed():
    text = _text()
    assert "python -m eval --out eval/results/latest-opa.json --opa" in text


def test_renders_reports_with_pdf():
    text = _text()
    assert "render_reports.py" in text
    assert "--pdf" in text
