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

func TestParseFile_NumericBoolAndListAttributes(t *testing.T) {
	resources, err := ParseFile("../../../examples/insecure-aws.tf")
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}

	rule := resources[1]
	if rule.Type != "aws_security_group_rule" {
		t.Fatalf("expected aws_security_group_rule, got %s", rule.Type)
	}
	if rule.Attributes["from_port"] != "0" {
		t.Errorf("expected from_port=0, got %q", rule.Attributes["from_port"])
	}
	if rule.Attributes["to_port"] != "65535" {
		t.Errorf("expected to_port=65535, got %q", rule.Attributes["to_port"])
	}
	if rule.Attributes["cidr_blocks"] != `["0.0.0.0/0"]` {
		t.Errorf(`expected cidr_blocks=["0.0.0.0/0"], got %q`, rule.Attributes["cidr_blocks"])
	}
}

func TestParseFile_ListWithNullElementSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.tf")
	if err := os.WriteFile(path, []byte(`resource "aws_security_group_rule" "example" {
  type        = "ingress"
  cidr_blocks = [null, "10.0.0.0/8"]
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

	// The list as a whole is "wholly known" (null is a known value), so
	// literalString hands it to ctyToString — which must reject the whole
	// list rather than render a null element, since a null in the middle
	// of a rendered ["a",null,"b"] string would silently corrupt the
	// bracket syntax the Rego rules pattern-match against.
	if _, ok := resources[0].Attributes["cidr_blocks"]; ok {
		t.Errorf("expected cidr_blocks to be skipped when any element is null, got %q", resources[0].Attributes["cidr_blocks"])
	}
	if resources[0].Attributes["type"] != "ingress" {
		t.Errorf("expected type=ingress, got %q", resources[0].Attributes["type"])
	}
}

func TestParseFile_NullAttributeSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "null.tf")
	if err := os.WriteFile(path, []byte(`resource "azurerm_key_vault" "example" {
  name                     = "examplekv"
  purge_protection_enabled = null
}
`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	resources, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if _, ok := resources[0].Attributes["purge_protection_enabled"]; ok {
		t.Errorf("expected a null attribute to be skipped, got %q", resources[0].Attributes["purge_protection_enabled"])
	}
}

func TestParseFile_BoolFalseAndUnsupportedObjectAttributes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed.tf")
	if err := os.WriteFile(path, []byte(`resource "azurerm_storage_account" "example" {
  name                            = "examplestorage"
  allow_nested_items_to_be_public = false
  tags = {
    env = "prod"
  }
}
`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	resources, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if resources[0].Attributes["allow_nested_items_to_be_public"] != "false" {
		t.Errorf("expected allow_nested_items_to_be_public=false, got %q", resources[0].Attributes["allow_nested_items_to_be_public"])
	}
	if _, ok := resources[0].Attributes["tags"]; ok {
		t.Errorf("expected an object-typed attribute (tags) to be skipped, not flattened, got %q", resources[0].Attributes["tags"])
	}
}

func TestParseDir_WalksDirectoryAndAggregatesResources(t *testing.T) {
	resources, err := ParseDir("../../../examples")
	if err != nil {
		t.Fatalf("ParseDir returned error: %v", err)
	}
	// insecure.tf (3 resources) + insecure-aws.tf (2 resources); ParseDir
	// only visits *.tf files, so the Bicep/Kubernetes fixtures in the same
	// directory must not contribute any.
	if len(resources) != 5 {
		t.Fatalf("expected 5 resources across all .tf fixtures, got %d", len(resources))
	}
}

func TestParseDir_NonexistentDirErrors(t *testing.T) {
	if _, err := ParseDir(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected an error for a nonexistent directory, got nil")
	}
}
