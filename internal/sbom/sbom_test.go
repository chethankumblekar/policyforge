package sbom

import (
	"encoding/json"
	"testing"

	"github.com/chethankumblekar/policyforge/internal/normalizer"
)

func TestGenerate_MapsResourcesToArtifacts(t *testing.T) {
	resources := []normalizer.Resource{
		{
			Provider: "azure",
			Type:     "storage_account",
			Name:     "example",
			Source:   normalizer.Location{File: "main.tf", Line: 1},
		},
		{
			Provider: "k8s",
			Type:     "pod_workload",
			Name:     "Deployment/app",
			Source:   normalizer.Location{File: "deploy.yaml", Line: 3},
		},
	}

	doc := Generate(resources)

	if doc.SchemaVersion == "" {
		t.Error("expected a non-empty SchemaVersion")
	}
	if doc.Source != "policyforge scan" {
		t.Errorf("expected Source \"policyforge scan\", got %q", doc.Source)
	}
	if len(doc.Artifacts) != len(resources) {
		t.Fatalf("expected %d artifacts, got %d", len(resources), len(doc.Artifacts))
	}

	for i, r := range resources {
		a := doc.Artifacts[i]
		if a.Name != r.Name {
			t.Errorf("artifact %d: expected name %q, got %q", i, r.Name, a.Name)
		}
		if a.Type != r.Type {
			t.Errorf("artifact %d: expected type %q, got %q", i, r.Type, a.Type)
		}
		if a.Provider != r.Provider {
			t.Errorf("artifact %d: expected provider %q, got %q", i, r.Provider, a.Provider)
		}
		if a.Location != r.Source.File {
			t.Errorf("artifact %d: expected location %q, got %q", i, r.Source.File, a.Location)
		}
	}
}

func TestGenerate_EmptyResourcesProducesEmptyArtifactList(t *testing.T) {
	doc := Generate(nil)
	if len(doc.Artifacts) != 0 {
		t.Errorf("expected 0 artifacts, got %d", len(doc.Artifacts))
	}
}

func TestToJSON_ProducesValidJSON(t *testing.T) {
	doc := Generate([]normalizer.Resource{
		{Provider: "aws", Type: "s3_bucket", Name: "logs", Source: normalizer.Location{File: "main.tf", Line: 1}},
	})

	out := ToJSON(doc)

	var decoded Document
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("ToJSON output did not parse as valid JSON: %v\noutput: %s", err, out)
	}
	if len(decoded.Artifacts) != 1 || decoded.Artifacts[0].Name != "logs" {
		t.Errorf("expected round-tripped artifact \"logs\", got %+v", decoded.Artifacts)
	}
}
