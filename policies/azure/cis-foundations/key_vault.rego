# Rego policy for Azure Key Vault checks — data-loss prevention best
# practice (not yet a numbered CIS Azure Foundations control).

package policyforge.azure.cis_foundations

# PF-AZ-020: Key Vault must have purge protection enabled
deny[msg] {
	input.type == "key_vault"
	input.attributes.purge_protection_enabled != "true"
	msg := sprintf("PF-AZ-020: key vault %q does not have purge protection enabled", [input.name])
}

severity["PF-AZ-020"] = "MEDIUM"
