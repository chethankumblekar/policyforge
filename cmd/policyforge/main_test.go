package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAll_MergesAllLanguages(t *testing.T) {
	resources, err := parseAll("../../examples")
	if err != nil {
		t.Fatalf("parseAll returned error: %v", err)
	}

	var haveTF, haveBicep, haveK8s bool
	for _, r := range resources {
		switch {
		case strings.HasPrefix(r.Type, "azurerm_") || strings.HasPrefix(r.Type, "aws_"):
			haveTF = true
		case strings.HasPrefix(r.Type, "Microsoft."):
			haveBicep = true
		case r.Type == "Pod" || r.Type == "Deployment":
			haveK8s = true
		}
	}

	if !haveTF {
		t.Error("expected at least one Terraform resource in the merged set")
	}
	if !haveBicep {
		t.Error("expected at least one Bicep resource in the merged set")
	}
	if !haveK8s {
		t.Error("expected at least one Kubernetes resource in the merged set")
	}
}

func TestParseAll_SingleFile(t *testing.T) {
	resources, err := parseAll("../../examples/insecure.tf")
	if err != nil {
		t.Fatalf("parseAll returned error: %v", err)
	}
	if len(resources) != 3 {
		t.Fatalf("expected 3 resources from insecure.tf, got %d", len(resources))
	}
}

func TestParseAll_NonexistentPathErrors(t *testing.T) {
	if _, err := parseAll("./does-not-exist"); err == nil {
		t.Fatal("expected an error for a nonexistent path, got nil")
	}
}

func TestRunScan_TableFormatExitsNonZeroOnFindings(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runScan([]string{"--path", "../../examples/insecure.tf", "--format", "table"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1 (findings present), got %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PF-AZ-001") {
		t.Errorf("expected table output to mention PF-AZ-001, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "finding(s).") {
		t.Errorf("expected a findings count summary line, got:\n%s", stdout.String())
	}
}

func TestRunScan_JSONFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runScan([]string{"--path", "../../examples/insecure.tf", "--format", "json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"RuleID": "PF-AZ-001"`) {
		t.Errorf("expected JSON output to contain RuleID PF-AZ-001, got:\n%s", stdout.String())
	}
}

func TestRunScan_SARIFFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runScan([]string{"--path", "../../examples/insecure.tf", "--format", "sarif"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"ruleId": "PF-AZ-001"`) {
		t.Errorf("expected SARIF output to contain ruleId PF-AZ-001, got:\n%s", stdout.String())
	}
}

func TestRunScan_NoFindingsExitsZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.tf"), []byte(`resource "azurerm_storage_account" "example" {
  name             = "cleanstorage"
  min_tls_version  = "TLS1_2"
}
`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runScan([]string{"--path", dir, "--format", "table"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "No policy violations found") {
		t.Errorf("expected the clean-scan message, got:\n%s", stdout.String())
	}
}

func TestRunScan_ParseErrorExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.tf"), []byte(`this is not valid HCL {{{`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runScan([]string{"--path", dir}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1 for a parse error, got %d", code)
	}
	if !strings.Contains(stderr.String(), "parse error") {
		t.Errorf("expected stderr to report a parse error, got:\n%s", stderr.String())
	}
}

func TestRunScan_SBOMFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	runScan([]string{"--path", "../../examples/insecure.tf", "--sbom"}, &stdout, &stderr)

	if !strings.Contains(stdout.String(), `"schemaVersion"`) {
		t.Errorf("expected --sbom to emit an SBOM document on stdout, got:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "SBOM generated") {
		t.Errorf("expected the SBOM banner on stderr, got:\n%s", stderr.String())
	}
}

func TestRunScan_CustomPolicyDirMergesFindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "naming.rego"), []byte(`package policyforge.custom.naming

deny[msg] {
	input.type == "storage_account"
	msg := sprintf("PF-CUSTOM-001: %q flagged by custom rule", [input.name])
}

severity["PF-CUSTOM-001"] = "LOW"
`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runScan([]string{"--path", "../../examples/insecure.tf", "--policy-dir", dir, "--format", "json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PF-CUSTOM-001") {
		t.Errorf("expected custom rule finding PF-CUSTOM-001 in output, got:\n%s", stdout.String())
	}
}

func TestRunScan_InvalidCustomPolicyNamespaceErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.rego"), []byte(`package myorg.rules

deny[msg] { msg := "nope" }
`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runScan([]string{"--path", "../../examples/insecure.tf", "--policy-dir", dir}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1 for an invalid custom policy namespace, got %d", code)
	}
	if !strings.Contains(stderr.String(), "policy evaluation error") {
		t.Errorf("expected stderr to report a policy evaluation error, got:\n%s", stderr.String())
	}
}

func TestRun_VersionCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"version"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), version) {
		t.Errorf("expected version output to contain %q, got:\n%s", version, stdout.String())
	}
}

func TestRun_HelpCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"help"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Commands:") {
		t.Errorf("expected usage output, got:\n%s", stdout.String())
	}
}

func TestRun_NoArgsShowsUsageAndErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Commands:") {
		t.Errorf("expected usage output, got:\n%s", stdout.String())
	}
}

func TestRun_UnknownCommandErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"bogus"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown command: bogus") {
		t.Errorf("expected stderr to report the unknown command, got:\n%s", stderr.String())
	}
}
