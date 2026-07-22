package normalizer

import (
	"testing"

	"github.com/chethankumblekar/policyforge/internal/parser"
)

func TestNormalize_KnownTypesMapToProviderAndType(t *testing.T) {
	cases := []struct {
		name         string
		sourceType   string
		wantProvider string
		wantType     string
	}{
		{"terraform azurerm storage account", "azurerm_storage_account", "azure", "storage_account"},
		{"terraform azurerm nsg rule", "azurerm_network_security_group_rule", "azure", "nsg_rule"},
		{"terraform azurerm key vault", "azurerm_key_vault", "azure", "key_vault"},
		{"terraform aws s3 bucket", "aws_s3_bucket", "aws", "s3_bucket"},
		{"terraform aws security group rule", "aws_security_group_rule", "aws", "security_group_rule"},
		{"bicep storage account", "Microsoft.Storage/storageAccounts", "azure", "storage_account"},
		{"bicep nsg security rule", "Microsoft.Network/networkSecurityGroups/securityRules", "azure", "nsg_rule"},
		{"bicep key vault", "Microsoft.KeyVault/vaults", "azure", "key_vault"},
		{"k8s Pod", "Pod", "k8s", "pod_workload"},
		{"k8s Deployment", "Deployment", "k8s", "pod_workload"},
		{"k8s DaemonSet", "DaemonSet", "k8s", "pod_workload"},
		{"k8s StatefulSet", "StatefulSet", "k8s", "pod_workload"},
		{"k8s ReplicaSet", "ReplicaSet", "k8s", "pod_workload"},
		{"k8s Job", "Job", "k8s", "pod_workload"},
		{"k8s CronJob", "CronJob", "k8s", "pod_workload"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := Normalize([]parser.Resource{{Type: tc.sourceType, Name: "example"}})
			if len(out) != 1 {
				t.Fatalf("expected 1 normalized resource, got %d", len(out))
			}
			if out[0].Provider != tc.wantProvider {
				t.Errorf("provider: expected %q, got %q", tc.wantProvider, out[0].Provider)
			}
			if out[0].Type != tc.wantType {
				t.Errorf("type: expected %q, got %q", tc.wantType, out[0].Type)
			}
		})
	}
}

func TestNormalize_UnknownTypePassesThroughAsUnknown(t *testing.T) {
	out := Normalize([]parser.Resource{{Type: "some_future_resource_type", Name: "example"}})
	if len(out) != 1 {
		t.Fatalf("expected 1 normalized resource, got %d", len(out))
	}
	if out[0].Provider != "unknown" {
		t.Errorf("expected provider \"unknown\", got %q", out[0].Provider)
	}
	if out[0].Type != "some_future_resource_type" {
		t.Errorf("expected type to pass through unchanged, got %q", out[0].Type)
	}
}

func TestNormalize_PreservesNameAttributesAndLocation(t *testing.T) {
	in := parser.Resource{
		Type:       "azurerm_storage_account",
		Name:       "example",
		Attributes: map[string]string{"min_tls_version": "TLS1_2"},
		File:       "main.tf",
		Line:       7,
	}

	out := Normalize([]parser.Resource{in})
	if len(out) != 1 {
		t.Fatalf("expected 1 normalized resource, got %d", len(out))
	}

	got := out[0]
	if got.Name != in.Name {
		t.Errorf("expected name %q, got %q", in.Name, got.Name)
	}
	if got.Attributes["min_tls_version"] != "TLS1_2" {
		t.Errorf("expected attributes to be preserved, got %+v", got.Attributes)
	}
	if got.Source.File != in.File || got.Source.Line != in.Line {
		t.Errorf("expected source location %s:%d, got %s:%d", in.File, in.Line, got.Source.File, got.Source.Line)
	}
}

func TestNormalize_EmptyInputReturnsEmptySlice(t *testing.T) {
	out := Normalize(nil)
	if len(out) != 0 {
		t.Errorf("expected 0 resources, got %d", len(out))
	}
}

func TestNormalize_MultipleResourcesPreserveOrder(t *testing.T) {
	in := []parser.Resource{
		{Type: "azurerm_storage_account", Name: "first"},
		{Type: "aws_s3_bucket", Name: "second"},
		{Type: "Pod", Name: "third"},
	}

	out := Normalize(in)
	if len(out) != 3 {
		t.Fatalf("expected 3 resources, got %d", len(out))
	}
	for i, want := range []string{"first", "second", "third"} {
		if out[i].Name != want {
			t.Errorf("index %d: expected name %q, got %q", i, want, out[i].Name)
		}
	}
}
