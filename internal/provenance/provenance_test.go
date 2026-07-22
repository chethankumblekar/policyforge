package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerate_ComputesMaterialDigests(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.tf")
	content := []byte(`resource "azurerm_storage_account" "example" {}`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	started := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	finished := started.Add(2 * time.Second)

	pred, err := Generate(map[string]string{"path": dir}, []string{path}, started, finished)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if len(pred.Materials) != 1 {
		t.Fatalf("expected 1 material, got %d", len(pred.Materials))
	}
	m := pred.Materials[0]
	if m.URI != "file://"+path {
		t.Errorf("expected uri file://%s, got %s", path, m.URI)
	}

	wantDigest := sha256Hex(t, content)
	if m.Digest["sha256"] != wantDigest {
		t.Errorf("expected sha256 digest %s, got %s", wantDigest, m.Digest["sha256"])
	}
}

func TestGenerate_DedupsAndSortsMaterials(t *testing.T) {
	dir := t.TempDir()
	pathB := filepath.Join(dir, "b.tf")
	pathA := filepath.Join(dir, "a.tf")
	for _, p := range []string{pathA, pathB} {
		if err := os.WriteFile(p, []byte("content"), 0o644); err != nil {
			t.Fatalf("failed to write fixture: %v", err)
		}
	}

	// pathB listed twice, pathA once — expect exactly 2 materials, sorted.
	pred, err := Generate(nil, []string{pathB, pathA, pathB}, time.Now(), time.Now())
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if len(pred.Materials) != 2 {
		t.Fatalf("expected 2 deduplicated materials, got %d: %+v", len(pred.Materials), pred.Materials)
	}
	if pred.Materials[0].URI != "file://"+pathA || pred.Materials[1].URI != "file://"+pathB {
		t.Errorf("expected materials sorted a.tf before b.tf, got %+v", pred.Materials)
	}
}

func TestGenerate_SetsBuilderAndBuildType(t *testing.T) {
	pred, err := Generate(nil, nil, time.Now(), time.Now())
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if pred.Builder.ID != BuilderID {
		t.Errorf("expected builder id %q, got %q", BuilderID, pred.Builder.ID)
	}
	if pred.BuildType != BuildType {
		t.Errorf("expected build type %q, got %q", BuildType, pred.BuildType)
	}
}

func TestGenerate_PropagatesParametersAndTimestamps(t *testing.T) {
	started := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	finished := time.Date(2026, 3, 1, 10, 0, 5, 0, time.UTC)

	pred, err := Generate(map[string]string{"format": "sarif"}, nil, started, finished)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if pred.Invocation.Parameters["format"] != "sarif" {
		t.Errorf("expected parameter format=sarif, got %+v", pred.Invocation.Parameters)
	}
	if pred.Metadata.BuildStartedOn != "2026-03-01T10:00:00Z" {
		t.Errorf("expected buildStartedOn 2026-03-01T10:00:00Z, got %s", pred.Metadata.BuildStartedOn)
	}
	if pred.Metadata.BuildFinishedOn != "2026-03-01T10:00:05Z" {
		t.Errorf("expected buildFinishedOn 2026-03-01T10:00:05Z, got %s", pred.Metadata.BuildFinishedOn)
	}
}

func TestGenerate_MissingFileErrors(t *testing.T) {
	if _, err := Generate(nil, []string{"/does/not/exist.tf"}, time.Now(), time.Now()); err == nil {
		t.Fatal("expected an error for a nonexistent material file, got nil")
	}
}

func TestToJSON_ProducesValidJSON(t *testing.T) {
	pred, err := Generate(map[string]string{"path": "."}, nil, time.Now(), time.Now())
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	out, err := ToJSON(pred)
	if err != nil {
		t.Fatalf("ToJSON returned error: %v", err)
	}

	var decoded Predicate
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("ToJSON output did not parse as valid JSON: %v", err)
	}
	if decoded.Builder.ID != BuilderID {
		t.Errorf("expected round-tripped builder id %q, got %q", BuilderID, decoded.Builder.ID)
	}
}

func sha256Hex(t *testing.T, content []byte) string {
	t.Helper()
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
