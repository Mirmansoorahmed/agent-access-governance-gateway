# OPA unit tests for the runtime PDP. Run with: opa test policy/opa
#
# These run on the maintainer machine (OPA 1.22.3) and in CI (which installs the
# static opa binary). They do not run in the offline sandbox; the Python parity
# test (gateway/tests/test_opa_parity.py) skips cleanly when opa is absent.
package access_governance_test

import data.access_governance
import rego.v1

# Minimal inline data so the tests are self-contained and independent of
# policy/opa/tiers.yml edits.
_data := {"governance": {
	"default_tier": "deny",
	"access": [
		{"server": "crm", "tool": "lookup_client", "groups": ["advisors", "partners"]},
		{"server": "crm", "tool": "export_clients", "groups": ["partners"]},
	],
	"tiers": [
		{"server": "crm", "tool": "lookup_client", "tier": "allow"},
		{"server": "crm", "tool": "export_clients", "tier": "four-eyes"},
	],
}}

test_allow_when_group_matches if {
	access_governance.decision.allow with input as {
		"agent": {"groups": ["advisors"]},
		"server": "crm", "tool": "lookup_client",
	}
		with data.governance as _data.governance
}

test_deny_when_group_missing if {
	not access_governance.decision.allow with input as {
		"agent": {"groups": ["analysts"]},
		"server": "crm", "tool": "lookup_client",
	}
		with data.governance as _data.governance
}

test_tier_resolves_from_data if {
	access_governance.decision.tier == "four-eyes" with input as {
		"agent": {"groups": ["partners"]},
		"server": "crm", "tool": "export_clients",
	}
		with data.governance as _data.governance
}

test_unlisted_tool_defaults_to_deny_tier if {
	access_governance.decision.tier == "deny" with input as {
		"agent": {"groups": ["advisors"]},
		"server": "crm", "tool": "unknown",
	}
		with data.governance as _data.governance
}

test_reason_no_access_rule if {
	access_governance.decision.reason == "no access rule for tool" with input as {
		"agent": {"groups": ["advisors"]},
		"server": "crm", "tool": "unknown",
	}
		with data.governance as _data.governance
}

test_reason_caller_not_in_groups if {
	access_governance.decision.reason == "caller not in allowed groups" with input as {
		"agent": {"groups": ["analysts"]},
		"server": "crm", "tool": "lookup_client",
	}
		with data.governance as _data.governance
}
