"""OPA PDP tests (task 6).

Two kinds:
* Offline: LocalPdp driven by the committed data mirror -- always runs.
* OPA-backed: SubprocessOpaPdp against policy/opa -- marked @requires_opa so it
  skips cleanly where the binary is absent (the offline sandbox). On the
  maintainer machine / CI it asserts LocalPdp and real OPA agree (parity).
"""

from __future__ import annotations

import pytest

from gateway.governance_data import load_governance
from gateway.opa_client import LocalPdp, OpaInput, SubprocessOpaPdp
from gateway.tests.opa_support import OPA_BUNDLE_DIR, requires_opa

# Cases spanning allow/deny and every tier present in the data document.
CASES = [
    OpaInput(groups=("advisors",), server="crm", tool="lookup_client"),  # allow / allow
    OpaInput(groups=("analysts",), server="crm", tool="lookup_client"),  # deny group
    OpaInput(groups=("partners",), server="crm", tool="export_clients"),  # allow / four-eyes
    OpaInput(groups=("finance",), server="billing", tool="issue_refund"),  # allow / break-glass
    OpaInput(groups=("advisors",), server="research", tool="web_search"),  # allow / ask
    OpaInput(groups=("advisors",), server="crm", tool="unknown"),  # no rule / deny tier
]


def _local() -> LocalPdp:
    return LocalPdp.from_data(load_governance())


def test_local_pdp_decisions_from_data_mirror():
    local = _local()
    d = local.evaluate(OpaInput(groups=("advisors",), server="crm", tool="lookup_client"))
    assert (d.allow, d.tier) == (True, "allow")
    d = local.evaluate(OpaInput(groups=("partners",), server="crm", tool="export_clients"))
    assert (d.allow, d.tier) == (True, "four-eyes")
    d = local.evaluate(OpaInput(groups=("analysts",), server="crm", tool="lookup_client"))
    assert (d.allow, d.reason) == (False, "caller not in allowed groups")
    d = local.evaluate(OpaInput(groups=("advisors",), server="crm", tool="unknown"))
    assert (d.allow, d.tier, d.reason) == (False, "deny", "no access rule for tool")


@requires_opa
@pytest.mark.parametrize("case", CASES)
def test_opa_matches_local_pdp(case):
    # Bundle dir already contains both access.rego and tiers.yml, so we do NOT
    # pass the YAML again as a second --data (that would re-merge the same keys
    # and raise a data merge conflict at data.governance).
    opa = SubprocessOpaPdp(bundle_dir=OPA_BUNDLE_DIR)
    local = _local()
    opa_decision = opa.evaluate(case)
    local_decision = local.evaluate(case)
    assert opa_decision.allow == local_decision.allow
    assert opa_decision.tier == local_decision.tier
    assert opa_decision.reason == local_decision.reason


def test_json_mirror_in_sync_when_yaml_available():
    """The committed tiers.json must match what sync_opa_data.py would render."""
    yaml = pytest.importorskip("yaml")
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent.parent
    with open(root / "policy" / "opa" / "tiers.yml", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    expected = json.dumps(data, indent=2, sort_keys=True) + "\n"
    actual = (root / "gateway" / "data" / "tiers.json").read_text(encoding="utf-8")
    assert actual == expected
