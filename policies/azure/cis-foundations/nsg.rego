# Rego policy for Azure Network Security Group rule checks, mapped to
# CIS Azure Foundations Benchmark controls 6.1/6.2.

package policyforge.azure.cis_foundations

# PF-AZ-010: NSG rule must not allow unrestricted inbound access
deny[msg] {
	input.type == "nsg_rule"
	input.attributes.direction == "Inbound"
	input.attributes.access == "Allow"
	source := input.attributes.source_address_prefix
	source == "*"
	msg := sprintf("PF-AZ-010: NSG rule %q allows unrestricted inbound access (CIS 6.1/6.2)", [input.name])
}

deny[msg] {
	input.type == "nsg_rule"
	input.attributes.direction == "Inbound"
	input.attributes.access == "Allow"
	source := input.attributes.source_address_prefix
	source == "0.0.0.0/0"
	msg := sprintf("PF-AZ-010: NSG rule %q allows unrestricted inbound access (CIS 6.1/6.2)", [input.name])
}

severity["PF-AZ-010"] = "CRITICAL"
