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
