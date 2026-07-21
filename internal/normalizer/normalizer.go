// Package normalizer converts source-specific parser output (Terraform,
// Bicep, Kubernetes) into a single unified Resource model so the policy
// engine only ever has to reason about one shape of data, regardless of
// which IaC language produced it.
package normalizer

import "github.com/chethankumblekar/policyforge/internal/parser/terraform"

// Resource is the unified internal representation of any infrastructure
// resource, independent of source IaC language.
type Resource struct {
	Provider   string // "azure" | "aws" | "k8s"
	Type       string // normalized type, e.g. "storage_account", "nsg"
	Name       string
	Attributes map[string]string
	Source     Location
}

// Location points back to where in the original source this resource
// came from, for SARIF findings and human-readable output.
type Location struct {
	File string
	Line int
}

// providerPrefixes maps common Terraform resource-type prefixes to a
// normalized provider + type name. This list grows as more resource
// types get policy coverage.
var terraformTypeMap = map[string]struct {
	Provider string
	Type     string
}{
	"azurerm_storage_account":      {"azure", "storage_account"},
	"azurerm_network_security_group_rule": {"azure", "nsg_rule"},
	"azurerm_key_vault":            {"azure", "key_vault"},
	"aws_s3_bucket":                {"aws", "s3_bucket"},
	"aws_security_group_rule":      {"aws", "security_group_rule"},
}

// Normalize converts parsed Terraform resources into the unified model.
// Unknown resource types are still passed through (provider "unknown")
// so future rule packs can be added without touching the normalizer.
func Normalize(resources []terraform.Resource) []Resource {
	out := make([]Resource, 0, len(resources))

	for _, r := range resources {
		provider, typ := "unknown", r.Type
		if mapped, ok := terraformTypeMap[r.Type]; ok {
			provider, typ = mapped.Provider, mapped.Type
		}

		out = append(out, Resource{
			Provider:   provider,
			Type:       typ,
			Name:       r.Name,
			Attributes: r.Attributes,
			Source: Location{
				File: r.File,
				Line: r.Line,
			},
		})
	}

	return out
}
