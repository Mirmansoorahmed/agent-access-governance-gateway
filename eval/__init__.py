"""Eval harness for the Access Governance Gateway (task 13).

Attack + benign suites run through the real decision engine. The runner measures
block rate, benign false-block rate, and allow-path overhead (p50/p95), and
persists results with a timestamp + git SHA. Metrics in the README/reports must
come from a committed run of this harness -- never hand-entered.
"""

from __future__ import annotations

__all__ = ["ATTACK_SUITE", "BENIGN_SUITE", "Case", "RunResult", "run_suite"]

from .runner import ATTACK_SUITE, BENIGN_SUITE, Case, RunResult, run_suite
