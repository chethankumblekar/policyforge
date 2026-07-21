package engine

import (
	"context"
	"testing"

	"github.com/chethankumblekar/policyforge/internal/normalizer"
	"github.com/chethankumblekar/policyforge/internal/parser/terraform"
)

func scanFixture(t *testing.T, path string) []Finding {
	t.Helper()

	resources, err := terraform.ParseDir(path)
	if err != nil {
		t.Fatalf("ParseDir(%q) returned error: %v", path, err)
	}

	findings, err := Evaluate(context.Background(), normalizer.Normalize(resources))
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	return findings
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
