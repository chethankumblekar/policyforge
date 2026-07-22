package bicep

import (
	"os"
	"path/filepath"
	"testing"
)

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

func TestParseFile_UnmappedResourceTypeHasNoAttributes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unmapped.bicep")
	if err := os.WriteFile(path, []byte(`resource plan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: 'exampleplan'
  location: 'centralindia'
  properties: {
    reserved: true
  }
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
	if resources[0].Name != "exampleplan" {
		t.Errorf("expected name exampleplan, got %s", resources[0].Name)
	}
	if len(resources[0].Attributes) != 0 {
		t.Errorf("expected no attributes for an ARM type with no key mapping, got %+v", resources[0].Attributes)
	}
}

func TestParseFile_MissingNameDefaultsToUnnamed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noname.bicep")
	if err := os.WriteFile(path, []byte(`resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  location: 'centralindia'
  properties: {
    allowBlobPublicAccess: true
  }
}
`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	resources, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if resources[0].Name != "unnamed" {
		t.Errorf("expected default name \"unnamed\", got %q", resources[0].Name)
	}
}

func TestParseDir_WalksDirectoryAndAggregatesResources(t *testing.T) {
	resources, err := ParseDir("../../../examples")
	if err != nil {
		t.Fatalf("ParseDir returned error: %v", err)
	}
	// insecure.bicep has 3 resources; ParseDir only visits *.bicep files,
	// so the Terraform/Kubernetes fixtures in the same directory must not
	// contribute any.
	if len(resources) != 3 {
		t.Fatalf("expected 3 resources from the .bicep fixture, got %d", len(resources))
	}
}

func TestParseDir_NonexistentDirErrors(t *testing.T) {
	if _, err := ParseDir(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected an error for a nonexistent directory, got nil")
	}
}

func TestCanonicalAttributes_TranslatesARMPropertyNames(t *testing.T) {
	attrs := CanonicalAttributes("Microsoft.Storage/storageAccounts", map[string]interface{}{
		"allowBlobPublicAccess": true,
		"minimumTlsVersion":     "TLS1_0",
	})

	if attrs["allow_nested_items_to_be_public"] != "true" {
		t.Errorf("expected allow_nested_items_to_be_public=true, got %q", attrs["allow_nested_items_to_be_public"])
	}
	if attrs["min_tls_version"] != "TLS1_0" {
		t.Errorf("expected min_tls_version=TLS1_0, got %q", attrs["min_tls_version"])
	}
}

func TestCanonicalAttributes_TypeMatchingIsCaseInsensitive(t *testing.T) {
	attrs := CanonicalAttributes("microsoft.storage/storageaccounts", map[string]interface{}{
		"allowBlobPublicAccess": false,
	})
	if attrs["allow_nested_items_to_be_public"] != "false" {
		t.Errorf("expected a case-insensitive ARM type match, got %+v", attrs)
	}
}

func TestCanonicalAttributes_UnmappedTypeReturnsEmpty(t *testing.T) {
	attrs := CanonicalAttributes("Microsoft.Compute/virtualMachines", map[string]interface{}{"osType": "Linux"})
	if len(attrs) != 0 {
		t.Errorf("expected no attributes for an ARM type with no key mapping, got %+v", attrs)
	}
}

func TestCanonicalAttributes_MissingPropertySkipped(t *testing.T) {
	attrs := CanonicalAttributes("Microsoft.Storage/storageAccounts", map[string]interface{}{})
	if len(attrs) != 0 {
		t.Errorf("expected no attributes when properties are absent, got %+v", attrs)
	}
}

func TestCanonicalAttributes_UnsupportedValueTypeSkipped(t *testing.T) {
	attrs := CanonicalAttributes("Microsoft.Storage/storageAccounts", map[string]interface{}{
		"allowBlobPublicAccess": []interface{}{"not", "a", "scalar"},
		"minimumTlsVersion":     "TLS1_2",
	})
	if _, ok := attrs["allow_nested_items_to_be_public"]; ok {
		t.Errorf("expected a non-scalar property value to be skipped, got %+v", attrs)
	}
	if attrs["min_tls_version"] != "TLS1_2" {
		t.Errorf("expected min_tls_version=TLS1_2, got %q", attrs["min_tls_version"])
	}
}

func TestScalarToString(t *testing.T) {
	cases := []struct {
		name   string
		input  interface{}
		want   string
		wantOK bool
	}{
		{"string", "TLS1_2", "TLS1_2", true},
		{"bool true", true, "true", true},
		{"bool false", false, "false", true},
		{"number", float64(100), "100", true},
		{"fractional number", float64(1.5), "1.5", true},
		{"unsupported slice", []interface{}{"a"}, "", false},
		{"unsupported map", map[string]interface{}{"a": "b"}, "", false},
		{"nil", nil, "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := scalarToString(tc.input)
			if ok != tc.wantOK {
				t.Fatalf("expected ok=%v, got ok=%v", tc.wantOK, ok)
			}
			if ok && got != tc.want {
				t.Errorf("expected %q, got %q", tc.want, got)
			}
		})
	}
}
