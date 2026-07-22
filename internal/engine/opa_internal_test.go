package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chethankumblekar/policyforge/internal/normalizer"
)

func TestRuleIDFromMessage(t *testing.T) {
	cases := map[string]string{
		"PF-AZ-001: storage account allows public access": "PF-AZ-001",
		"no colon here":         "UNKNOWN",
		"":                      "UNKNOWN",
		"PF-K8S-005: no limits": "PF-K8S-005",
	}

	for msg, want := range cases {
		if got := ruleIDFromMessage(msg); got != want {
			t.Errorf("ruleIDFromMessage(%q): expected %q, got %q", msg, want, got)
		}
	}
}

func TestTitleFromMessage(t *testing.T) {
	cases := map[string]string{
		"PF-AZ-001: storage account allows public access": "storage account allows public access",
		"no colon here":                       "no colon here",
		"PF-AZ-002:   leading spaces trimmed": "leading spaces trimmed",
	}

	for msg, want := range cases {
		if got := titleFromMessage(msg); got != want {
			t.Errorf("titleFromMessage(%q): expected %q, got %q", msg, want, got)
		}
	}
}

func TestSeverityFor(t *testing.T) {
	sevMap := map[string]interface{}{"PF-AZ-001": "HIGH", "PF-AZ-002": "MEDIUM"}

	if got := severityFor(sevMap, "PF-AZ-001"); got != SeverityHigh {
		t.Errorf("expected HIGH, got %s", got)
	}
	if got := severityFor(sevMap, "PF-AZ-002"); got != SeverityMedium {
		t.Errorf("expected MEDIUM, got %s", got)
	}
	if got := severityFor(sevMap, "PF-UNKNOWN"); got != SeverityHigh {
		t.Errorf("expected default HIGH for a rule with no severity entry, got %s", got)
	}
	if got := severityFor(nil, "PF-AZ-001"); got != SeverityHigh {
		t.Errorf("expected default HIGH for a nil severity map, got %s", got)
	}
}

func TestCollectFindings_FlatPackage(t *testing.T) {
	r := normalizer.Resource{Name: "example", Source: normalizer.Location{File: "main.tf", Line: 5}}

	node := map[string]interface{}{
		"deny":     []interface{}{"PF-AZ-001: public access"},
		"severity": map[string]interface{}{"PF-AZ-001": "HIGH"},
	}

	findings := collectFindings(node, r)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "PF-AZ-001" || f.Severity != SeverityHigh || f.Resource != "example" {
		t.Errorf("unexpected finding: %+v", f)
	}
	if f.File != "main.tf" || f.Line != 5 {
		t.Errorf("expected source location main.tf:5, got %s:%d", f.File, f.Line)
	}
}

func TestCollectFindings_NestedPackages(t *testing.T) {
	r := normalizer.Resource{Name: "example"}

	// Mirrors the real shape: data.policyforge.<provider>.<pack>.{deny,severity}
	node := map[string]interface{}{
		"azure": map[string]interface{}{
			"cis_foundations": map[string]interface{}{
				"deny":     []interface{}{"PF-AZ-001: msg one"},
				"severity": map[string]interface{}{"PF-AZ-001": "HIGH"},
			},
		},
		"aws": map[string]interface{}{
			"core": map[string]interface{}{
				"deny":     []interface{}{"PF-AWS-001: msg two"},
				"severity": map[string]interface{}{"PF-AWS-001": "CRITICAL"},
			},
		},
	}

	findings := collectFindings(node, r)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings from two nested packages, got %d: %+v", len(findings), findings)
	}

	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}
	if byID["PF-AZ-001"].Severity != SeverityHigh {
		t.Errorf("expected PF-AZ-001 severity HIGH, got %s", byID["PF-AZ-001"].Severity)
	}
	if byID["PF-AWS-001"].Severity != SeverityCritical {
		t.Errorf("expected PF-AWS-001 severity CRITICAL, got %s", byID["PF-AWS-001"].Severity)
	}
}

func TestCollectFindings_NoDenyReturnsNil(t *testing.T) {
	r := normalizer.Resource{Name: "example"}
	if findings := collectFindings(map[string]interface{}{"unrelated": "value"}, r); len(findings) != 0 {
		t.Errorf("expected no findings, got %+v", findings)
	}
	if findings := collectFindings("not a map", r); len(findings) != 0 {
		t.Errorf("expected no findings for a non-map node, got %+v", findings)
	}
}

func TestLoadUserModules_ValidPackageLoads(t *testing.T) {
	dir := t.TempDir()
	writeRego(t, dir, "ok.rego", `package policyforge.custom.naming

deny[msg] { msg := "test" }
`)

	opts, err := loadUserModules(dir)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("expected 1 module option, got %d", len(opts))
	}
}

func TestLoadUserModules_BareNamespaceAllowed(t *testing.T) {
	dir := t.TempDir()
	writeRego(t, dir, "ok.rego", "package policyforge\n\ndeny[msg] { msg := \"test\" }\n")

	if _, err := loadUserModules(dir); err != nil {
		t.Errorf("expected the bare \"policyforge\" package to be accepted, got error: %v", err)
	}
}

func TestLoadUserModules_WrongNamespaceRejected(t *testing.T) {
	dir := t.TempDir()
	writeRego(t, dir, "bad.rego", "package myorg.rules\n\ndeny[msg] { msg := \"test\" }\n")

	if _, err := loadUserModules(dir); err == nil {
		t.Fatal("expected an error for a package outside the policyforge namespace, got nil")
	}
}

func TestLoadUserModules_MissingPackageDeclarationRejected(t *testing.T) {
	dir := t.TempDir()
	writeRego(t, dir, "nopkg.rego", "deny[msg] { msg := \"test\" }\n")

	if _, err := loadUserModules(dir); err == nil {
		t.Fatal("expected an error for a file with no package declaration, got nil")
	}
}

func TestLoadUserModules_NonexistentDirErrors(t *testing.T) {
	if _, err := loadUserModules(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected an error for a nonexistent directory, got nil")
	}
}

func TestEvaluateOPA_EmptyStringPolicyDirIsSkipped(t *testing.T) {
	resource := normalizer.Resource{
		Type:       "storage_account",
		Name:       "example",
		Attributes: map[string]string{"allow_nested_items_to_be_public": "true"},
	}

	findings, err := EvaluateOPA(context.Background(), []normalizer.Resource{resource}, "")
	if err != nil {
		t.Fatalf("expected no error for an empty extraPolicyDirs entry, got %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != "PF-AZ-001" {
		t.Fatalf("expected the built-in PF-AZ-001 finding, got %+v", findings)
	}
}

func TestEvaluateOPA_InvalidCustomPolicyDirWrapsError(t *testing.T) {
	dir := t.TempDir()
	writeRego(t, dir, "bad.rego", "package myorg.rules\n\ndeny[msg] { msg := \"test\" }\n")

	_, err := EvaluateOPA(context.Background(), nil, dir)
	if err == nil {
		t.Fatal("expected an error for an invalid custom policy directory, got nil")
	}
	if !strings.Contains(err.Error(), "loading custom policy directory") {
		t.Errorf("expected error to mention \"loading custom policy directory\", got: %v", err)
	}
}

func TestEvaluateOPA_MalformedRegoSyntaxWrapsPrepareError(t *testing.T) {
	dir := t.TempDir()
	// Valid package/namespace (passes loadUserModules' check), but broken
	// Rego syntax — this only fails later, when rego.New(...).PrepareForEval
	// actually compiles the module.
	writeRego(t, dir, "broken.rego", "package policyforge.custom.broken\n\ndeny[msg] { this is not valid rego (((\n")

	_, err := EvaluateOPA(context.Background(), nil, dir)
	if err == nil {
		t.Fatal("expected an error for malformed Rego syntax, got nil")
	}
	if !strings.Contains(err.Error(), "preparing rego query") {
		t.Errorf("expected error to mention \"preparing rego query\", got: %v", err)
	}
}

func writeRego(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write fixture %s: %v", name, err)
	}
}
