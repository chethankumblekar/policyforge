package helm

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func skipIfHelmMissing(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed on PATH; skipping")
	}
}

func TestParseChart_RendersAndExtractsPodSecurityAttributes(t *testing.T) {
	skipIfHelmMissing(t)

	resources, err := ParseChart("../../../examples/insecure-helm-chart")
	if err != nil {
		t.Fatalf("ParseChart returned error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d: %+v", len(resources), resources)
	}

	r := resources[0]
	if r.Type != "Deployment" {
		t.Errorf("expected type Deployment, got %s", r.Type)
	}
	if r.Name != "Deployment/insecure-helm-app" {
		t.Errorf("expected name Deployment/insecure-helm-app, got %s", r.Name)
	}
	// The source file must resolve to the real path on disk under the
	// chart's actual directory — not the chart's Chart.yaml `name` (which
	// deliberately differs from the directory name in this fixture, to
	// prove resolveSourcePath doesn't assume they match).
	wantFile := "../../../examples/insecure-helm-chart/templates/deployment.yaml"
	if r.File != wantFile {
		t.Errorf("expected file %s, got %s", wantFile, r.File)
	}

	for attr, want := range map[string]string{
		"host_network":               "true",
		"privileged":                 "true",
		"allow_privilege_escalation": "true",
		"run_as_non_root_false":      "true",
		"missing_resource_limits":    "true",
	} {
		if got := r.Attributes[attr]; got != want {
			t.Errorf("attribute %s: expected %q, got %q", attr, want, got)
		}
	}
}

func TestParseDir_FindsChartAndSkipsNonChartDirs(t *testing.T) {
	skipIfHelmMissing(t)

	resources, err := ParseDir("../../../examples")
	if err != nil {
		t.Fatalf("ParseDir returned error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource from the one chart under examples/, got %d: %+v", len(resources), resources)
	}
}

func TestParseDir_NoChartsReturnsEmptyWithoutRequiringHelm(t *testing.T) {
	// This must succeed even without helm installed: ParseDir should
	// never invoke `helm` unless it actually finds a Chart.yaml.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "azurerm_storage_account" "example" {}`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("ParseDir returned error: %v", err)
	}
	if len(resources) != 0 {
		t.Errorf("expected 0 resources, got %d", len(resources))
	}
}

func TestParseChart_MissingHelmBinaryErrors(t *testing.T) {
	if _, err := exec.LookPath("helm"); err == nil {
		t.Skip("helm is installed; this test only covers the missing-binary path")
	}

	if _, err := ParseChart("../../../examples/insecure-helm-chart"); err == nil {
		t.Fatal("expected an error when helm isn't on PATH, got nil")
	}
}

func TestParseChart_InvalidChartErrors(t *testing.T) {
	skipIfHelmMissing(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("not: [valid, chart"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	if _, err := ParseChart(dir); err == nil {
		t.Fatal("expected an error for an invalid chart, got nil")
	}
}

func TestResolveSourcePath_StripsOnlyFirstSegment(t *testing.T) {
	cases := []struct {
		chartDir string
		source   string
		want     string
	}{
		{"examples/insecure-helm-chart", "insecure-helm-app/templates/deployment.yaml", "examples/insecure-helm-chart/templates/deployment.yaml"},
		{"charts/foo", "foo/charts/bar/templates/x.yaml", "charts/foo/charts/bar/templates/x.yaml"},
		{"charts/foo", "singlesegment", "charts/foo/singlesegment"},
	}

	for _, tc := range cases {
		if got := resolveSourcePath(tc.chartDir, tc.source); got != filepath.FromSlash(tc.want) {
			t.Errorf("resolveSourcePath(%q, %q): expected %q, got %q", tc.chartDir, tc.source, tc.want, got)
		}
	}
}

func TestSplitBySource_GroupsBySourceComment(t *testing.T) {
	rendered := `---
# Source: mychart/templates/a.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: a
---
# Source: mychart/templates/b.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: b
`
	docs := splitBySource(rendered, "charts/mychart")
	if len(docs) != 2 {
		t.Fatalf("expected 2 grouped docs, got %d: %+v", len(docs), docs)
	}
	if docs[0].file != filepath.FromSlash("charts/mychart/templates/a.yaml") {
		t.Errorf("expected first doc file templates/a.yaml, got %s", docs[0].file)
	}
	if docs[1].file != filepath.FromSlash("charts/mychart/templates/b.yaml") {
		t.Errorf("expected second doc file templates/b.yaml, got %s", docs[1].file)
	}
}

func TestSplitBySource_NoSourceCommentsUsesChartDir(t *testing.T) {
	docs := splitBySource("apiVersion: v1\nkind: ConfigMap\n", "charts/mychart")
	if len(docs) != 1 || docs[0].file != "charts/mychart" {
		t.Errorf("expected a single doc attributed to the chart dir, got %+v", docs)
	}
}
