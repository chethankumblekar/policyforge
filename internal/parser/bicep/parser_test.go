package bicep

import "testing"

func TestParseFile_ExtractsResourceAndAttributes(t *testing.T) {
	resources, err := ParseFile("../../../examples/insecure.bicep")
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(resources) != 3 {
		t.Fatalf("expected 3 resources, got %d", len(resources))
	}

	sa := resources[0]
	if sa.Type != "Microsoft.Storage/storageAccounts" {
		t.Errorf("expected type Microsoft.Storage/storageAccounts, got %s", sa.Type)
	}
	if sa.Name != "examplestorage" {
		t.Errorf("expected name examplestorage, got %s", sa.Name)
	}
	if sa.Attributes["allow_nested_items_to_be_public"] != "true" {
		t.Errorf("expected allow_nested_items_to_be_public=true, got %q", sa.Attributes["allow_nested_items_to_be_public"])
	}
	if sa.Attributes["min_tls_version"] != "TLS1_0" {
		t.Errorf("expected min_tls_version=TLS1_0, got %q", sa.Attributes["min_tls_version"])
	}

	kv := resources[2]
	if kv.Type != "Microsoft.KeyVault/vaults" {
		t.Errorf("expected type Microsoft.KeyVault/vaults, got %s", kv.Type)
	}
	if kv.Attributes["purge_protection_enabled"] != "false" {
		t.Errorf("expected purge_protection_enabled=false, got %q", kv.Attributes["purge_protection_enabled"])
	}
}
