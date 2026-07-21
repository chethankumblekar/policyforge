package terraform

import "testing"

func TestParseFile_ExtractsResourceAndAttributes(t *testing.T) {
	resources, err := ParseFile("../../../examples/insecure.tf")
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(resources) != 3 {
		t.Fatalf("expected 3 resources, got %d", len(resources))
	}

	sa := resources[0]
	if sa.Type != "azurerm_storage_account" {
		t.Errorf("expected type azurerm_storage_account, got %s", sa.Type)
	}
	if sa.Attributes["allow_nested_items_to_be_public"] != "true" {
		t.Errorf("expected allow_nested_items_to_be_public=true, got %q", sa.Attributes["allow_nested_items_to_be_public"])
	}
	if sa.Attributes["min_tls_version"] != "TLS1_0" {
		t.Errorf("expected min_tls_version=TLS1_0, got %q", sa.Attributes["min_tls_version"])
	}
}

func TestParseFile_NoResources(t *testing.T) {
	resources, err := ParseFile("../../../go.mod")
	if err != nil {
		t.Fatalf("ParseFile returned error on non-.tf-like content: %v", err)
	}
	if len(resources) != 0 {
		t.Errorf("expected 0 resources, got %d", len(resources))
	}
}
