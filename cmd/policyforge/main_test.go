package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chethankumblekar/policyforge/internal/drift"
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

func TestRunScan_ProvenanceFlagWritesPredicate(t *testing.T) {
	provenancePath := filepath.Join(t.TempDir(), "provenance.json")

	var stdout, stderr bytes.Buffer
	runScan([]string{"--path", "../../examples/insecure.tf", "--provenance", provenancePath}, &stdout, &stderr)

	data, err := os.ReadFile(provenancePath)
	if err != nil {
		t.Fatalf("expected a provenance predicate file, got error: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("provenance predicate is not valid JSON: %v", err)
	}
	builder, _ := decoded["builder"].(map[string]interface{})
	if builder["id"] != "https://github.com/chethankumblekar/policyforge" {
		t.Errorf("expected builder.id to identify policyforge, got %+v", builder)
	}
	materials, _ := decoded["materials"].([]interface{})
	if len(materials) != 1 {
		t.Fatalf("expected 1 material (insecure.tf), got %d: %+v", len(materials), materials)
	}
	if !strings.Contains(stderr.String(), "Provenance predicate written to") {
		t.Errorf("expected a confirmation message on stderr, got:\n%s", stderr.String())
	}
}

func TestRunScan_NoProvenanceFlagWritesNoFile(t *testing.T) {
	dir := t.TempDir()
	provenancePath := filepath.Join(dir, "should-not-exist.json")

	var stdout, stderr bytes.Buffer
	runScan([]string{"--path", "../../examples/insecure.tf"}, &stdout, &stderr)

	if _, err := os.Stat(provenancePath); !os.IsNotExist(err) {
		t.Errorf("expected no provenance file to be written without --provenance, stat error: %v", err)
	}
}

func TestRunSign_WrongArgCountErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSign([]string{}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("expected exit code 2 for wrong argument count, got %d", code)
	}
	if !strings.Contains(stderr.String(), "usage: policyforge sign") {
		t.Errorf("expected a usage message, got:\n%s", stderr.String())
	}
}

func TestRunAttest_WrongArgCountErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAttest([]string{}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("expected exit code 2 for wrong argument count, got %d", code)
	}
}

func TestRunAttest_MissingPredicateFlagErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAttest([]string{"some-file.json"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("expected exit code 2 when --predicate is missing, got %d", code)
	}
	if !strings.Contains(stderr.String(), "--predicate is required") {
		t.Errorf("expected an error about the missing --predicate flag, got:\n%s", stderr.String())
	}
}

func TestRunSign_MissingCosignErrors(t *testing.T) {
	if _, err := exec.LookPath("cosign"); err == nil {
		t.Skip("cosign is installed; this test only covers the missing-binary path")
	}

	dir := t.TempDir()
	blobPath := filepath.Join(dir, "blob.txt")
	if err := os.WriteFile(blobPath, []byte("hello"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runSign([]string{blobPath}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "sign error") {
		t.Errorf("expected a sign error message, got:\n%s", stderr.String())
	}
}

// TestRunSignAndAttest_LiveIntegration exercises the full CLI plumbing
// (flag parsing → internal/signer → cosign) with a real local key pair.
// Like internal/signer's own live tests, this needs network access to
// rekor.sigstore.dev for cosign's bundle format, so it skips (rather than
// fails) when that's unreachable — see internal/signer/signer_test.go for
// why that's an environment limitation rather than a code defect.
func TestRunSignAndAttest_LiveIntegration(t *testing.T) {
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign not installed on PATH; skipping live integration test")
	}
	t.Setenv("COSIGN_PASSWORD", "")

	dir := t.TempDir()
	keyPrefix := filepath.Join(dir, "cosign")
	if out, err := exec.Command("cosign", "generate-key-pair", "--output-key-prefix", keyPrefix).CombinedOutput(); err != nil {
		t.Fatalf("cosign generate-key-pair failed: %v\n%s", err, out)
	}

	artifactPath := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(artifactPath, []byte(`{"schemaVersion":"policyforge-sbom/0.1"}`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	predicatePath := filepath.Join(dir, "provenance.json")
	if err := os.WriteFile(predicatePath, []byte(`{"builder":{"id":"test"}}`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	signBundle := filepath.Join(dir, "sign.bundle.json")
	var stdout, stderr bytes.Buffer
	code := runSign([]string{"--key", keyPrefix + ".key", "--bundle", signBundle, artifactPath}, &stdout, &stderr)
	if code != 0 {
		if strings.Contains(stderr.String(), "rekor") {
			t.Skipf("skipping: cosign's bundle format needs network access to Rekor, which isn't reachable in this environment:\n%s", stderr.String())
		}
		t.Fatalf("runSign exited %d:\n%s", code, stderr.String())
	}

	attestBundle := filepath.Join(dir, "attest.bundle.json")
	stdout.Reset()
	stderr.Reset()
	code = runAttest([]string{"--key", keyPrefix + ".key", "--predicate", predicatePath, "--bundle", attestBundle, artifactPath}, &stdout, &stderr)
	if code != 0 {
		if strings.Contains(stderr.String(), "rekor") {
			t.Skipf("skipping: cosign's bundle format needs network access to Rekor, which isn't reachable in this environment:\n%s", stderr.String())
		}
		t.Fatalf("runAttest exited %d:\n%s", code, stderr.String())
	}
}

func TestRunDrift_MissingSubscriptionIDErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runDrift([]string{"--path", "../../examples"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("expected exit code 2 when --subscription-id is missing, got %d", code)
	}
	if !strings.Contains(stderr.String(), "--subscription-id is required") {
		t.Errorf("expected an error about the missing flag, got:\n%s", stderr.String())
	}
}

func TestRunDrift_ParseErrorExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.tf"), []byte(`this is not valid HCL {{{`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runDrift([]string{"--path", dir, "--subscription-id", "00000000-0000-0000-0000-000000000000"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1 for a parse error, got %d", code)
	}
	if !strings.Contains(stderr.String(), "parse error") {
		t.Errorf("expected stderr to report a parse error, got:\n%s", stderr.String())
	}
}

// TestRunDrift_QueryErrorSurfacesCleanly documents an honest limitation:
// this sandbox has no real Azure credentials, so drift can only be
// exercised up to the point where Query fails to authenticate. It should
// fail fast with a clear, actionable error rather than hang.
func TestRunDrift_QueryErrorSurfacesCleanly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runDrift([]string{"--path", "../../examples", "--subscription-id", "00000000-0000-0000-0000-000000000000"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1 when Azure Resource Graph can't be queried, got %d", code)
	}
	if !strings.Contains(stderr.String(), "drift error") {
		t.Errorf("expected a drift error message, got:\n%s", stderr.String())
	}
}

func TestPrintDriftResult_NoDrift(t *testing.T) {
	var buf bytes.Buffer
	printDriftResult(&buf, drift.Result{})

	if !strings.Contains(buf.String(), "No drift detected") {
		t.Errorf("expected the clean-drift message, got:\n%s", buf.String())
	}
}

func TestPrintDriftResult_WithFindingsAndNotFound(t *testing.T) {
	var buf bytes.Buffer
	printDriftResult(&buf, drift.Result{
		Findings: []drift.Finding{{Resource: "examplestorage", Attribute: "min_tls_version", Declared: "TLS1_2", Live: "TLS1_0"}},
		NotFound: []drift.NotFound{{Resource: "ghostvault", Type: "key_vault"}},
	})

	out := buf.String()
	for _, want := range []string{"examplestorage", "min_tls_version", "TLS1_2", "TLS1_0", "ghostvault", "1 drift finding(s)", "1 missing resource(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected drift output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestRunScan_UploadRequiresOrgAndProject(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runScan([]string{"--path", "../../examples/insecure.tf", "--upload", "http://localhost:0"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("expected exit code 2 when --org/--project are missing, got %d", code)
	}
	if !strings.Contains(stderr.String(), "--org and --project are required") {
		t.Errorf("expected an error about missing --org/--project, got:\n%s", stderr.String())
	}
}

func TestRunScan_UploadFlagPostsFindings(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/scans" || r.Method != http.MethodPost {
			t.Errorf("expected POST /api/scans, got %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("failed to decode upload body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{"id": 42, "url": "/scans/42"})
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runScan([]string{"--path", "../../examples/insecure.tf", "--upload", srv.URL, "--org", "acme", "--project", "infra-repo"}, &stdout, &stderr)

	if code != 1 { // insecure.tf has HIGH/CRITICAL findings
		t.Fatalf("expected exit code 1, got %d; stderr=%s", code, stderr.String())
	}
	if gotBody["org"] != "acme" || gotBody["project"] != "infra-repo" {
		t.Errorf("expected org=acme project=infra-repo in the upload body, got %+v", gotBody)
	}
	findings, _ := gotBody["findings"].([]interface{})
	if len(findings) == 0 {
		t.Error("expected the upload body to include findings")
	}
	if !strings.Contains(stderr.String(), "Uploaded to portal: "+srv.URL+"/scans/42") {
		t.Errorf("expected an upload confirmation message, got:\n%s", stderr.String())
	}
}

func TestRunScan_UploadServerErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runScan([]string{"--path", "../../examples/insecure.tf", "--upload", srv.URL, "--org", "acme", "--project", "infra-repo"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "upload error") {
		t.Errorf("expected an upload error message, got:\n%s", stderr.String())
	}
}

func TestRunScan_UploadUnreachablePortalSurfacesError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runScan([]string{"--path", "../../examples/insecure.tf", "--upload", "http://127.0.0.1:1", "--org", "acme", "--project", "infra-repo"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "upload error") {
		t.Errorf("expected an upload error message, got:\n%s", stderr.String())
	}
}
