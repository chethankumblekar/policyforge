package engine

import (
	"context"
	"testing"

	"github.com/chethankumblekar/policyforge/internal/normalizer"
	"github.com/chethankumblekar/policyforge/internal/parser"
	"github.com/chethankumblekar/policyforge/internal/parser/bicep"
	"github.com/chethankumblekar/policyforge/internal/parser/k8s"
	"github.com/chethankumblekar/policyforge/internal/parser/terraform"
)

func evaluateResources(t *testing.T, resources []parser.Resource) []Finding {
	t.Helper()

	findings, err := Evaluate(context.Background(), normalizer.Normalize(resources))
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	return findings
}

func scanFixture(t *testing.T, path string) []Finding {
	t.Helper()

	resources, err := terraform.ParseDir(path)
	if err != nil {
		t.Fatalf("terraform.ParseDir(%q) returned error: %v", path, err)
	}

	return evaluateResources(t, resources)
}

func scanBicepFixture(t *testing.T, path string) []Finding {
	t.Helper()

	resources, err := bicep.ParseDir(path)
	if err != nil {
		t.Fatalf("bicep.ParseDir(%q) returned error: %v", path, err)
	}

	return evaluateResources(t, resources)
}

func scanK8sFixture(t *testing.T, path string) []Finding {
	t.Helper()

	resources, err := k8s.ParseDir(path)
	if err != nil {
		t.Fatalf("k8s.ParseDir(%q) returned error: %v", path, err)
	}

	return evaluateResources(t, resources)
}

func findByRuleID(findings []Finding, ruleID string) *Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

func TestEvaluate_AzureFixture(t *testing.T) {
	findings := scanFixture(t, "../../examples/insecure.tf")

	want := map[string]Severity{
		"PF-AZ-001": SeverityHigh,
		"PF-AZ-002": SeverityMedium,
		"PF-AZ-010": SeverityCritical,
		"PF-AZ-020": SeverityMedium,
	}

	if len(findings) != len(want) {
		t.Fatalf("expected %d findings, got %d: %+v", len(want), len(findings), findings)
	}

	for ruleID, severity := range want {
		f := findByRuleID(findings, ruleID)
		if f == nil {
			t.Errorf("expected a finding for %s, got none", ruleID)
			continue
		}
		if f.Severity != severity {
			t.Errorf("%s: expected severity %s, got %s", ruleID, severity, f.Severity)
		}
	}
}

func TestEvaluate_BicepFixture(t *testing.T) {
	findings := scanBicepFixture(t, "../../examples/insecure.bicep")

	// Same Azure Rego rule pack as Terraform (PF-AZ-*) — proves Bicep and
	// Terraform resources evaluate identically once normalized.
	want := map[string]Severity{
		"PF-AZ-001": SeverityHigh,
		"PF-AZ-002": SeverityMedium,
		"PF-AZ-010": SeverityCritical,
		"PF-AZ-020": SeverityMedium,
	}

	if len(findings) != len(want) {
		t.Fatalf("expected %d findings, got %d: %+v", len(want), len(findings), findings)
	}

	for ruleID, severity := range want {
		f := findByRuleID(findings, ruleID)
		if f == nil {
			t.Errorf("expected a finding for %s, got none", ruleID)
			continue
		}
		if f.Severity != severity {
			t.Errorf("%s: expected severity %s, got %s", ruleID, severity, f.Severity)
		}
	}
}

func TestEvaluate_KubernetesFixture(t *testing.T) {
	findings := scanK8sFixture(t, "../../examples/insecure-k8s.yaml")

	want := map[string]Severity{
		"PF-K8S-001": SeverityCritical,
		"PF-K8S-002": SeverityHigh,
		"PF-K8S-003": SeverityHigh,
		"PF-K8S-004": SeverityMedium,
	}

	for ruleID, severity := range want {
		f := findByRuleID(findings, ruleID)
		if f == nil {
			t.Errorf("expected a finding for %s, got none", ruleID)
			continue
		}
		if f.Severity != severity {
			t.Errorf("%s: expected severity %s, got %s", ruleID, severity, f.Severity)
		}
	}

	// PF-K8S-005 (missing resource limits) fires for both the Deployment
	// and the bare Pod in the fixture.
	count := 0
	for _, f := range findings {
		if f.RuleID == "PF-K8S-005" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 PF-K8S-005 findings, got %d", count)
	}
}

func TestEvaluate_AWSFixture(t *testing.T) {
	findings := scanFixture(t, "../../examples/insecure-aws.tf")

	want := map[string]Severity{
		"PF-AWS-001": SeverityHigh,
		"PF-AWS-010": SeverityCritical,
	}

	if len(findings) != len(want) {
		t.Fatalf("expected %d findings, got %d: %+v", len(want), len(findings), findings)
	}

	for ruleID, severity := range want {
		f := findByRuleID(findings, ruleID)
		if f == nil {
			t.Errorf("expected a finding for %s, got none", ruleID)
			continue
		}
		if f.Severity != severity {
			t.Errorf("%s: expected severity %s, got %s", ruleID, severity, f.Severity)
		}
	}
}
