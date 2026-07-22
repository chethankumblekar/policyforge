package drift

import (
	"context"
	"strings"
	"testing"
)

func TestDefaultQuery_ScopedToMappedARMTypes(t *testing.T) {
	q := DefaultQuery()

	if !strings.Contains(q, "Resources") || !strings.Contains(q, "where type in~") {
		t.Fatalf("expected a KQL query filtering by type, got:\n%s", q)
	}
	for _, armType := range normalizedTypeToARMType {
		if !strings.Contains(q, strings.ToLower(armType)) {
			t.Errorf("expected query to include lowercased ARM type %q, got:\n%s", strings.ToLower(armType), q)
		}
	}
}

func TestParseRows_ObjectArrayFormat(t *testing.T) {
	data := []interface{}{
		map[string]interface{}{
			"id":   "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/examplestorage",
			"type": "microsoft.storage/storageaccounts",
			"name": "examplestorage",
			"properties": map[string]interface{}{
				"allowBlobPublicAccess": true,
			},
		},
	}

	resources, err := parseRows(data)
	if err != nil {
		t.Fatalf("parseRows returned error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	r := resources[0]
	if r.Name != "examplestorage" || r.Type != "microsoft.storage/storageaccounts" {
		t.Errorf("unexpected resource: %+v", r)
	}
	if r.Properties["allowBlobPublicAccess"] != true {
		t.Errorf("expected properties to be preserved, got %+v", r.Properties)
	}
}

func TestParseRows_EmptyArray(t *testing.T) {
	resources, err := parseRows([]interface{}{})
	if err != nil {
		t.Fatalf("parseRows returned error: %v", err)
	}
	if len(resources) != 0 {
		t.Errorf("expected 0 resources, got %d", len(resources))
	}
}

func TestParseRows_MalformedRowsSkipped(t *testing.T) {
	data := []interface{}{
		"not a row object",
		map[string]interface{}{"id": "ok", "type": "microsoft.keyvault/vaults", "name": "kv"},
	}

	resources, err := parseRows(data)
	if err != nil {
		t.Fatalf("parseRows returned error: %v", err)
	}
	if len(resources) != 1 || resources[0].Name != "kv" {
		t.Errorf("expected the malformed row to be skipped and the valid one kept, got %+v", resources)
	}
}

func TestParseRows_UnexpectedShapeErrors(t *testing.T) {
	// Table result format (ResultFormatTable) would produce a *Table, not
	// a []interface{} — parseRows should reject that clearly rather than
	// panic, since Query always requests ResultFormatObjectArray.
	if _, err := parseRows(map[string]interface{}{"columns": nil, "rows": nil}); err == nil {
		t.Fatal("expected an error for a non-objectArray response shape, got nil")
	}
}

// TestQuery_FailsWithoutAzureCredentials documents the honest limitation
// of this package's own test suite: Query needs real Azure credentials
// and network access to be exercised end to end, neither of which this
// sandbox has. It should fail fast with a clear, wrapped error rather
// than hang or panic.
func TestQuery_FailsWithoutAzureCredentials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // don't actually wait on any network call

	_, err := Query(ctx, "00000000-0000-0000-0000-000000000000", DefaultQuery())
	if err == nil {
		t.Fatal("expected an error querying with a canceled context and no credentials, got nil")
	}
}
