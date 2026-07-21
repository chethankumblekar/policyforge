# Rego policy for core AWS security group checks.

package policyforge.aws.core

# PF-AWS-010: security group rule must not allow unrestricted ingress
deny[msg] {
	input.type == "security_group_rule"
	input.attributes.type == "ingress"
	contains(input.attributes.cidr_blocks, "0.0.0.0/0")
	msg := sprintf("PF-AWS-010: security group rule %q allows unrestricted ingress from 0.0.0.0/0", [input.name])
}

severity["PF-AWS-010"] = "CRITICAL"
