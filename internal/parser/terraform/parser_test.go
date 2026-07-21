package terraform

import (
	"os"
	"path/filepath"
	"testing"
)

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
	path := filepath.Join(t.TempDir(), "empty.tf")
	if err := os.WriteFile(path, []byte(`variable "region" {
  default = "centralindia"
}
`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	resources, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile returned error on valid HCL with no resource blocks: %v", err)
	}
	if len(resources) != 0 {
		t.Errorf("expected 0 resources, got %d", len(resources))
	}
}

func TestParseFile_InvalidHCLReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.tf")
	if err := os.WriteFile(path, []byte(`this is not valid HCL {{{`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	if _, err := ParseFile(path); err == nil {
		t.Fatal("expected an error parsing invalid HCL, got nil")
	}
}

func TestParseFile_SkipsNonLiteralAttributes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "refs.tf")
	if err := os.WriteFile(path, []byte(`resource "azurerm_storage_account" "example" {
  name     = "examplestorage"
  location = azurerm_resource_group.example.location
}
`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	resources, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}

	r := resources[0]
	if r.Attributes["name"] != "examplestorage" {
		t.Errorf("expected literal attribute name=examplestorage, got %q", r.Attributes["name"])
	}
	if _, ok := r.Attributes["location"]; ok {
		t.Errorf("expected non-literal attribute location to be skipped, got %q", r.Attributes["location"])
	}
}
