package drift

import (
	"testing"

	"github.com/chethankumblekar/policyforge/internal/normalizer"
)

func TestCompare_FindsAttributeDrift(t *testing.T) {
	declared := []normalizer.Resource{
		{
			Provider:   "azure",
			Type:       "storage_account",
			Name:       "examplestorage",
			Attributes: map[string]string{"allow_nested_items_to_be_public": "false", "min_tls_version": "TLS1_2"},
		},
	}
	live := []LiveResource{
		{
			ID:   "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/examplestorage",
			Type: "microsoft.storage/storageaccounts",
			Name: "examplestorage",
			Properties: map[string]interface{}{
				"allowBlobPublicAccess": true, // drifted: IaC says false
				"minimumTlsVersion":     "TLS1_2",
			},
		},
	}

	result := Compare(declared, live)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(result.Findings), result.Findings)
	}
	f := result.Findings[0]
	if f.Resource != "examplestorage" || f.Attribute != "allow_nested_items_to_be_public" {
		t.Errorf("unexpected finding: %+v", f)
	}
	if f.Declared != "false" || f.Live != "true" {
		t.Errorf("expected declared=false live=true, got declared=%s live=%s", f.Declared, f.Live)
	}
	if len(result.NotFound) != 0 {
		t.Errorf("expected no not-found resources, got %+v", result.NotFound)
	}
}

func TestCompare_NoDriftWhenAttributesMatch(t *testing.T) {
	declared := []normalizer.Resource{
		{
			Provider:   "azure",
			Type:       "key_vault",
			Name:       "examplekv",
			Attributes: map[string]string{"purge_protection_enabled": "true"},
		},
	}
	live := []LiveResource{
		{
			Type:       "microsoft.keyvault/vaults",
			Name:       "examplekv",
			Properties: map[string]interface{}{"enablePurgeProtection": true},
		},
	}

	result := Compare(declared, live)
	if len(result.Findings) != 0 {
		t.Errorf("expected no drift findings, got %+v", result.Findings)
	}
}

func TestCompare_NameMatchIsCaseInsensitive(t *testing.T) {
	declared := []normalizer.Resource{
		{Provider: "azure", Type: "key_vault", Name: "ExampleKV", Attributes: map[string]string{"purge_protection_enabled": "true"}},
	}
	live := []LiveResource{
		{Type: "microsoft.keyvault/vaults", Name: "examplekv", Properties: map[string]interface{}{"enablePurgeProtection": false}},
	}

	result := Compare(declared, live)
	if len(result.Findings) != 1 {
		t.Fatalf("expected the case-insensitive name match to still find 1 drift, got %d", len(result.Findings))
	}
}

func TestCompare_ReportsNotFoundWhenNoLiveMatch(t *testing.T) {
	declared := []normalizer.Resource{
		{Provider: "azure", Type: "storage_account", Name: "ghoststorage"},
	}

	result := Compare(declared, nil)
	if len(result.NotFound) != 1 || result.NotFound[0].Resource != "ghoststorage" {
		t.Errorf("expected ghoststorage reported as not found, got %+v", result.NotFound)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings for a resource with no live match, got %+v", result.Findings)
	}
}

func TestCompare_SkipsNonAzureResources(t *testing.T) {
	declared := []normalizer.Resource{
		{Provider: "aws", Type: "s3_bucket", Name: "logs", Attributes: map[string]string{"acl": "private"}},
		{Provider: "k8s", Type: "pod_workload", Name: "Pod/app"},
	}

	result := Compare(declared, nil)
	if len(result.Findings) != 0 || len(result.NotFound) != 0 {
		t.Errorf("expected AWS/Kubernetes resources to be skipped entirely, got %+v", result)
	}
}

func TestCompare_SkipsUnmappedAzureResourceTypes(t *testing.T) {
	declared := []normalizer.Resource{
		{Provider: "azure", Type: "some_future_azure_type", Name: "example"},
	}

	result := Compare(declared, nil)
	if len(result.Findings) != 0 || len(result.NotFound) != 0 {
		t.Errorf("expected an azure resource type with no ARM mapping to be skipped, got %+v", result)
	}
}

func TestCompare_OnlyComparesDeclaredAttributes(t *testing.T) {
	// The IaC source only sets allow_nested_items_to_be_public; whatever
	// the live TLS version is shouldn't produce a finding since there's
	// no declared value to compare it against.
	declared := []normalizer.Resource{
		{
			Provider:   "azure",
			Type:       "storage_account",
			Name:       "examplestorage",
			Attributes: map[string]string{"allow_nested_items_to_be_public": "false"},
		},
	}
	live := []LiveResource{
		{
			Type: "microsoft.storage/storageaccounts",
			Name: "examplestorage",
			Properties: map[string]interface{}{
				"allowBlobPublicAccess": false,
				"minimumTlsVersion":     "TLS1_0",
			},
		},
	}

	result := Compare(declared, live)
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings for an attribute the IaC source never declared, got %+v", result.Findings)
	}
}

func TestARMTypes_ReturnsAllMappedTypes(t *testing.T) {
	types := ARMTypes()
	if len(types) != len(normalizedTypeToARMType) {
		t.Fatalf("expected %d ARM types, got %d", len(normalizedTypeToARMType), len(types))
	}
}
