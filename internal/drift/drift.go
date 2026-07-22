// Package drift compares IaC-declared Azure resource configuration
// against the live configuration of those same resources in Azure, via
// Azure Resource Graph — catching manual/out-of-band changes that have
// drifted away from what's checked into source control.
//
// This only covers the same Azure resource types PolicyForge's Rego rule
// packs already understand (see normalizedTypeToARMType below), and only
// compares attributes that are both declared in the IaC source and
// present in the live resource's ARM properties — there's no attempt to
// guess intent for attributes the IaC source leaves unset.
package drift

import (
	"strings"

	"github.com/chethankumblekar/policyforge/internal/normalizer"
	"github.com/chethankumblekar/policyforge/internal/parser/bicep"
)

// normalizedTypeToARMType maps PolicyForge's normalized Azure resource
// types back to the ARM type Azure Resource Graph reports, so a query can
// be scoped to exactly the resource types this package can compare.
var normalizedTypeToARMType = map[string]string{
	"storage_account": "Microsoft.Storage/storageAccounts",
	"nsg_rule":        "Microsoft.Network/networkSecurityGroups/securityRules",
	"key_vault":       "Microsoft.KeyVault/vaults",
}

// ARMTypes returns the ARM resource type strings drift detection can
// compare, for building a Resource Graph query.
func ARMTypes() []string {
	types := make([]string, 0, len(normalizedTypeToARMType))
	for _, armType := range normalizedTypeToARMType {
		types = append(types, armType)
	}
	return types
}

// LiveResource is one resource record as returned by Azure Resource
// Graph: its ARM resource ID, ARM type, name, and properties blob.
type LiveResource struct {
	ID         string
	Type       string
	Name       string
	Properties map[string]interface{}
}

// Finding is a single attribute that differs between a resource's
// declared (IaC) configuration and its live Azure configuration.
type Finding struct {
	Resource  string
	Attribute string
	Declared  string
	Live      string
}

// NotFound is a declared Azure resource with no matching live resource —
// e.g. it was deleted out-of-band, or never actually deployed.
type NotFound struct {
	Resource string
	Type     string
}

// Result bundles drift findings and not-found resources from one
// Compare call.
type Result struct {
	Findings []Finding
	NotFound []NotFound
}

// Compare matches each declared Azure resource to a live resource by
// name (case-insensitive) and diffs their canonical attributes.
// Non-Azure resources (AWS, Kubernetes) and Azure resource types drift
// detection doesn't have an ARM property mapping for are skipped, since
// there is nothing live to compare them against.
func Compare(declared []normalizer.Resource, live []LiveResource) Result {
	var result Result

	for _, d := range declared {
		if d.Provider != "azure" {
			continue
		}
		armType, ok := normalizedTypeToARMType[d.Type]
		if !ok {
			continue
		}

		match := findByName(live, d.Name)
		if match == nil {
			result.NotFound = append(result.NotFound, NotFound{Resource: d.Name, Type: d.Type})
			continue
		}

		liveAttrs := bicep.CanonicalAttributes(armType, match.Properties)
		for key, declaredVal := range d.Attributes {
			liveVal, ok := liveAttrs[key]
			if !ok || liveVal == declaredVal {
				continue
			}
			result.Findings = append(result.Findings, Finding{
				Resource:  d.Name,
				Attribute: key,
				Declared:  declaredVal,
				Live:      liveVal,
			})
		}
	}

	return result
}

func findByName(live []LiveResource, name string) *LiveResource {
	for i := range live {
		if strings.EqualFold(live[i].Name, name) {
			return &live[i]
		}
	}
	return nil
}
