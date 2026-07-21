# Rego policy for Azure Storage Account checks, mapped to CIS Azure
# Foundations Benchmark controls 3.1 and 3.6. Loaded directly by
# internal/engine.EvaluateOPA — this file is a live rule pack, not just a
# reference.

package policyforge.azure.cis_foundations

# PF-AZ-001: storage account must not allow public blob access
deny[msg] {
	input.type == "storage_account"
	input.attributes.allow_nested_items_to_be_public == "true"
	msg := sprintf("PF-AZ-001: storage account %q allows public blob access (CIS 3.6)", [input.name])
}

severity["PF-AZ-001"] = "HIGH"

# PF-AZ-002: storage account must enforce TLS 1.2 minimum
deny[msg] {
	input.type == "storage_account"
	input.attributes.min_tls_version != "TLS1_2"
	msg := sprintf("PF-AZ-002: storage account %q does not enforce TLS 1.2 (CIS 3.1)", [input.name])
}

severity["PF-AZ-002"] = "MEDIUM"
