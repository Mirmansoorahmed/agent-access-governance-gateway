"""Run the eval harness and persist results.

    python -m eval --out eval/results/latest.json           # LocalPdp
    python -m eval --out eval/results/latest.json --opa      # real OPA PDP

With ``--opa`` the runner uses the real ``opa`` binary against policy/opa, so the
maintainer / CI produce the authoritative, OPA-backed results file whose numbers
may be cited. Exits non-zero if any case outcome is incorrect (so CI smoke fails
loudly on a regression).
"""

from __future__ import annotations

import argparse
import sys

from gateway.opa_client import SubprocessOpaPdp, opa_available

from .runner import run_suite, write_result


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Access Governance Gateway eval harness.")
    parser.add_argument("--out", default="eval/results/latest.json")
    parser.add_argument("--opa", action="store_true", help="Use the real OPA binary as the PDP.")
    args = parser.parse_args(argv)

    if args.opa:
        if not opa_available():
            print("error: --opa requested but no 'opa' binary on PATH", file=sys.stderr)
            return 2
        pdp = SubprocessOpaPdp(bundle_dir="policy/opa")
        label = "opa"
    else:
        pdp = None
        label = "local"

    result = run_suite(pdp=pdp, pdp_label=label)
    write_result(result, args.out)
    print(
        f"Eval ({label}): block_rate={result.block_rate} "
        f"benign_false_block_rate={result.benign_false_block_rate} "
        f"p50={result.overhead_p50_ms}ms p95={result.overhead_p95_ms}ms -> {args.out}"
    )

    incorrect = [c for c in result.cases if not c["correct"]]
    if incorrect:
        print(f"FAIL: {len(incorrect)} case(s) had unexpected outcomes:", file=sys.stderr)
        for c in incorrect:
            print(
                f"  {c['name']}: expected_allowed={c['expected_allowed']} "
                f"actual={c['actual_allowed']} reason={c['reason']}",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
