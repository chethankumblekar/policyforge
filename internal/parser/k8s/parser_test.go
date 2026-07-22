package k8s

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFile_ExtractsPodSecurityAttributes(t *testing.T) {
	resources, err := ParseFile("../../../examples/insecure-k8s.yaml")
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}

	deploy := resources[0]
	if deploy.Type != "Deployment" {
		t.Errorf("expected type Deployment, got %s", deploy.Type)
	}
	if deploy.Name != "Deployment/insecure-app" {
		t.Errorf("expected name Deployment/insecure-app, got %s", deploy.Name)
	}
	for attr, want := range map[string]string{
		"host_network":               "true",
		"privileged":                 "true",
		"allow_privilege_escalation": "true",
		"run_as_non_root_false":      "true",
		"missing_resource_limits":    "true",
	} {
		if got := deploy.Attributes[attr]; got != want {
			t.Errorf("attribute %s: expected %q, got %q", attr, want, got)
		}
	}

	pod := resources[1]
	if pod.Type != "Pod" {
		t.Errorf("expected type Pod, got %s", pod.Type)
	}
	if pod.Attributes["missing_resource_limits"] != "true" {
		t.Errorf("expected missing_resource_limits=true, got %q", pod.Attributes["missing_resource_limits"])
	}
	if pod.Attributes["privileged"] != "false" {
		t.Errorf("expected privileged=false, got %q", pod.Attributes["privileged"])
	}
}

func TestParseFile_SkipsNonKubernetesYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-k8s.yaml")
	if err := os.WriteFile(path, []byte(`name: ci-pipeline
steps:
  - run: go test ./...
`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	resources, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile returned error on valid non-Kubernetes YAML: %v", err)
	}
	if len(resources) != 0 {
		t.Errorf("expected 0 resources for YAML without kind/apiVersion, got %d", len(resources))
	}
}

func TestParseFile_CronJobNestedPodSpec(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cronjob.yaml")
	if err := os.WriteFile(path, []byte(`apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly-cleanup
spec:
  schedule: "0 0 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          hostNetwork: true
          containers:
            - name: cleanup
              image: example/cleanup:latest
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
	if resources[0].Attributes["host_network"] != "true" {
		t.Errorf("expected host_network=true reached through CronJob's nested jobTemplate.spec.template.spec, got %q", resources[0].Attributes["host_network"])
	}
	if resources[0].Attributes["missing_resource_limits"] != "true" {
		t.Errorf("expected missing_resource_limits=true, got %q", resources[0].Attributes["missing_resource_limits"])
	}
}

func TestParseFile_UnsupportedKindHasNoSecurityAttributes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "configmap.yaml")
	if err := os.WriteFile(path, []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  key: value
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
	if resources[0].Type != "ConfigMap" {
		t.Errorf("expected type ConfigMap, got %s", resources[0].Type)
	}
	if len(resources[0].Attributes) != 0 {
		t.Errorf("expected no pod-security attributes for a kind with no pod spec, got %+v", resources[0].Attributes)
	}
}

func TestParseFile_MissingMetadataNameDefaultsToUnnamed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noname.yaml")
	if err := os.WriteFile(path, []byte(`apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      image: example/app:latest
`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	resources, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if resources[0].Name != "Pod/unnamed" {
		t.Errorf("expected name \"Pod/unnamed\", got %q", resources[0].Name)
	}
}

func TestParseDir_WalksDirectoryAndAggregatesResources(t *testing.T) {
	resources, err := ParseDir("../../../examples")
	if err != nil {
		t.Fatalf("ParseDir returned error: %v", err)
	}
	// insecure-k8s.yaml has 2 documents (Deployment + Pod); ParseDir only
	// visits *.yaml/*.yml files, so the Terraform/Bicep fixtures in the
	// same directory must not contribute any.
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources from the .yaml fixture, got %d", len(resources))
	}
}

func TestParseDir_NonexistentDirErrors(t *testing.T) {
	if _, err := ParseDir(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected an error for a nonexistent directory, got nil")
	}
}

// TestParseDir_SkipsHelmChartDirectories is a regression test: a Helm
// chart's templates/*.yaml files contain unrendered Go template syntax
// (e.g. `hostNetwork: {{ .Values.hostNetwork }}`), not valid Kubernetes
// manifests. ParseDir must skip any directory containing a Chart.yaml
// entirely — internal/parser/helm handles those exclusively, by
// rendering the chart first — rather than attempt to parse the raw
// templates directly, which can silently misparse a value that happens
// to still be valid YAML once quoted.
func TestParseDir_SkipsHelmChartDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: test\nversion: 0.1.0\n"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	templatesDir := filepath.Join(dir, "templates")
	if err := os.MkdirAll(templatesDir, 0o755); err != nil {
		t.Fatalf("failed to create templates dir: %v", err)
	}
	// This would fail to decode as valid YAML if parsed raw (an "invalid
	// map key" error) — the important thing is ParseDir must not even
	// try, since it should skip the whole chart directory.
	if err := os.WriteFile(filepath.Join(templatesDir, "deployment.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Chart.Name }}
spec:
  template:
    spec:
      hostNetwork: {{ .Values.hostNetwork }}
`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("ParseDir returned error (it should have skipped the chart directory, not attempted to parse it): %v", err)
	}
	if len(resources) != 0 {
		t.Errorf("expected 0 resources — Helm chart directories should be skipped entirely, got %+v", resources)
	}
}
