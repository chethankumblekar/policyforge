// Package normalizer converts source-specific parser output (Terraform,
// Bicep, Kubernetes) into a single unified Resource model so the policy
// engine only ever has to reason about one shape of data, regardless of
// which IaC language produced it.
package normalizer

import "github.com/chethankumblekar/policyforge/internal/parser"

// Resource is the unified internal representation of any infrastructure
// resource, independent of source IaC language.
type Resource struct {
	Provider   string // "azure" | "aws" | "k8s"
	Type       string // normalized type, e.g. "storage_account", "nsg_rule"
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

// typeMap maps a source-language type string to a normalized provider +
// type name. Terraform and Bicep types that describe the same underlying
// Azure resource map to the same normalized type (e.g.
// "azurerm_storage_account" and "Microsoft.Storage/storageAccounts" both
// become "storage_account"), so one Rego rule pack covers both source
// languages — each parser is responsible for translating its own
// language's attribute names into the canonical keys the rule packs
// expect (see internal/parser/bicep for the ARM property name mapping).
//
// Kubernetes controller kinds that all wrap a pod template (Deployment,
// DaemonSet, ...) map to the same "pod_workload" type as a bare Pod, since
// internal/parser/k8s flattens them all to the same pod-security shape.
var typeMap = map[string]struct {
	Provider string
	Type     string
}{
	// Terraform (azurerm)
	"azurerm_storage_account":             {"azure", "storage_account"},
	"azurerm_network_security_group_rule": {"azure", "nsg_rule"},
	"azurerm_key_vault":                   {"azure", "key_vault"},

	// Terraform (aws)
	"aws_s3_bucket":           {"aws", "s3_bucket"},
	"aws_security_group_rule": {"aws", "security_group_rule"},

	// Bicep (ARM resource types)
	"Microsoft.Storage/storageAccounts":                     {"azure", "storage_account"},
	"Microsoft.Network/networkSecurityGroups/securityRules": {"azure", "nsg_rule"},
	"Microsoft.KeyVault/vaults":                             {"azure", "key_vault"},

	// Kubernetes
	"Pod":         {"k8s", "pod_workload"},
	"Deployment":  {"k8s", "pod_workload"},
	"DaemonSet":   {"k8s", "pod_workload"},
	"StatefulSet": {"k8s", "pod_workload"},
	"ReplicaSet":  {"k8s", "pod_workload"},
	"Job":         {"k8s", "pod_workload"},
	"CronJob":     {"k8s", "pod_workload"},
}

// Normalize converts parsed resources from any source-language parser into
// the unified model. Unknown resource types are still passed through
// (provider "unknown") so future rule packs can be added without touching
// the normalizer.
func Normalize(resources []parser.Resource) []Resource {
	out := make([]Resource, 0, len(resources))

	for _, r := range resources {
		provider, typ := "unknown", r.Type
		if mapped, ok := typeMap[r.Type]; ok {
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
