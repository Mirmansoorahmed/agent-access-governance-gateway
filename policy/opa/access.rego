# Access Governance Gateway -- runtime PDP (Check 2 + tier resolution).
#
# Decision contract (design.md 4.3), queried as data.access_governance.decision:
#   { "allow": bool, "tier": string, "reason": string }
#
# Input:
#   { "agent": {"role","department","seniority","groups":[...]},
#     "server": string, "tool": string }
#
# Data (policy/opa/tiers.yml, loaded as data.governance):
#   access: [ {server, tool, groups:[...]} ]
#   tiers:  [ {server, tool, tier} ]
#   default_tier: string
#
# The same data shape drives gateway.opa_client.LocalPdp so the offline
# reference evaluator and real OPA stay in lockstep (parity-tested).
package access_governance

import rego.v1

default allow := false

# Allowed when the caller shares at least one group with the tool's access rule.
allow if {
	some rule in data.governance.access
	rule.server == input.server
	rule.tool == input.tool
	some group in rule.groups
	group in input.agent.groups
}

# Tier for the requested tool, or the configured default.
tier := t if {
	some rule in data.governance.tiers
	rule.server == input.server
	rule.tool == input.tool
	t := rule.tier
} else := data.governance.default_tier

# Human-readable reason, mirroring LocalPdp.
reason := "group match" if {
	allow
} else := "no access rule for tool" if {
	not _has_access_rule
} else := "caller not in allowed groups"

_has_access_rule if {
	some rule in data.governance.access
	rule.server == input.server
	rule.tool == input.tool
}

decision := {
	"allow": allow,
	"tier": tier,
	"reason": reason,
}
