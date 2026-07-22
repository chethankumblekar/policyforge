// Command policyforge is the CLI entrypoint for the PolicyForge
// policy-as-code scanner.
//
// Usage:
//
//	policyforge scan --path ./examples --format table
//	policyforge scan --path ./examples --format sarif > results.sarif
//	policyforge version
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/chethankumblekar/policyforge/internal/drift"
	"github.com/chethankumblekar/policyforge/internal/engine"
	"github.com/chethankumblekar/policyforge/internal/normalizer"
	"github.com/chethankumblekar/policyforge/internal/parser"
	"github.com/chethankumblekar/policyforge/internal/parser/bicep"
	"github.com/chethankumblekar/policyforge/internal/parser/k8s"
	"github.com/chethankumblekar/policyforge/internal/parser/terraform"
	"github.com/chethankumblekar/policyforge/internal/provenance"
	"github.com/chethankumblekar/policyforge/internal/sbom"
	"github.com/chethankumblekar/policyforge/internal/signer"
)

const version = "0.1.0-dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI and returns the process exit code. Everything
// below this is written against explicit stdout/stderr writers instead of
// calling fmt.Print*/os.Exit directly, so the whole command surface is
// exercised by cmd/policyforge's tests in-process rather than via a
// subprocess.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		usage(stdout)
		return 1
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "sign":
		return runSign(args[1:], stdout, stderr)
	case "attest":
		return runAttest(args[1:], stdout, stderr)
	case "drift":
		return runDrift(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, "policyforge version", version)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n", args[0])
		usage(stdout)
		return 1
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `policyforge - open-source policy-as-code scanner for Terraform, Bicep, and Kubernetes

Commands:
  scan      Scan IaC files against policy rule packs
  sign      Sign a scan artifact (SBOM/SARIF/JSON) with cosign
  attest    Attach a SLSA provenance attestation to a scan artifact with cosign
  drift     Compare declared IaC configuration against live Azure resources
  version   Print the CLI version

Run 'policyforge scan --help', 'policyforge sign --help',
'policyforge attest --help', or 'policyforge drift --help' for
command-specific options.`)
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", ".", "path to a directory of IaC files to scan")
	format := fs.String("format", "table", "output format: table | sarif | json")
	genSBOM := fs.Bool("sbom", false, "also generate an SBOM alongside scan results")
	policyDir := fs.String("policy-dir", "", "optional path to a directory of additional user-authored .rego policy files")
	provenanceOut := fs.String("provenance", "", "optional path to write a SLSA provenance predicate describing this scan run, for use with 'policyforge attest'")
	uploadURL := fs.String("upload", "", "optional base URL of a PolicyForge portal (see enterprise/portal) to POST these findings to, e.g. http://localhost:8090")
	org := fs.String("org", "", "organization name to tag the upload with (required with --upload)")
	project := fs.String("project", "", "project name to tag the upload with (required with --upload)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *uploadURL != "" && (*org == "" || *project == "") {
		fmt.Fprintln(stderr, "scan error: --org and --project are required with --upload")
		return 2
	}

	startedOn := time.Now()

	// 1. Parse every supported IaC language found in the target path.
	resources, err := parseAll(*path)
	if err != nil {
		fmt.Fprintf(stderr, "parse error: %v\n", err)
		return 1
	}

	// 2. Normalize into the unified internal resource model.
	normalized := normalizer.Normalize(resources)

	// 3. Evaluate against the embedded Rego rule packs, plus any custom
	// policy pack the user pointed --policy-dir at.
	findings, err := engine.Evaluate(context.Background(), normalized, *policyDir)
	if err != nil {
		fmt.Fprintf(stderr, "policy evaluation error: %v\n", err)
		return 1
	}

	switch *format {
	case "sarif":
		fmt.Fprintln(stdout, engine.ToSARIF(findings))
	case "json":
		fmt.Fprintln(stdout, engine.ToJSON(findings))
	default:
		engine.PrintTable(stdout, findings)
	}

	if *genSBOM {
		doc := sbom.Generate(normalized)
		fmt.Fprintln(stderr, "\nSBOM generated:")
		fmt.Fprintln(stdout, sbom.ToJSON(doc))
	}

	if *uploadURL != "" {
		id, err := uploadFindings(*uploadURL, *org, *project, findings)
		if err != nil {
			fmt.Fprintf(stderr, "upload error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stderr, "\nUploaded to portal: %s/scans/%d\n", *uploadURL, id)
	}

	if *provenanceOut != "" {
		if err := writeProvenance(*provenanceOut, map[string]string{
			"path":      *path,
			"format":    *format,
			"policyDir": *policyDir,
		}, materialFiles(resources), startedOn, time.Now()); err != nil {
			fmt.Fprintf(stderr, "provenance error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stderr, "\nProvenance predicate written to %s (attach it with 'policyforge attest').\n", *provenanceOut)
	}

	if engine.HasFailures(findings) {
		return 1
	}
	return 0
}

// materialFiles collects the unique source files a set of parsed
// resources came from, for use as a provenance predicate's materials.
func materialFiles(resources []parser.Resource) []string {
	seen := make(map[string]struct{}, len(resources))
	var files []string
	for _, r := range resources {
		if _, ok := seen[r.File]; ok {
			continue
		}
		seen[r.File] = struct{}{}
		files = append(files, r.File)
	}
	return files
}

// uploadFindings POSTs findings to baseURL+"/api/scans" (see
// enterprise/portal), tagged with org/project, and returns the assigned
// scan ID.
func uploadFindings(baseURL, org, project string, findings []engine.Finding) (int, error) {
	body, err := json.Marshal(struct {
		Org      string           `json:"org"`
		Project  string           `json:"project"`
		Findings []engine.Finding `json:"findings"`
	}{Org: org, Project: project, Findings: findings})
	if err != nil {
		return 0, fmt.Errorf("encoding upload payload: %w", err)
	}

	resp, err := http.Post(baseURL+"/api/scans", "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("posting to %s: %w", baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("portal returned %s: %s", resp.Status, string(msg))
	}

	var decoded struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return 0, fmt.Errorf("decoding portal response: %w", err)
	}
	return decoded.ID, nil
}

// writeProvenance builds a SLSA provenance predicate and writes it as
// JSON to path.
func writeProvenance(path string, params map[string]string, materials []string, startedOn, finishedOn time.Time) error {
	pred, err := provenance.Generate(params, materials, startedOn, finishedOn)
	if err != nil {
		return fmt.Errorf("building provenance predicate: %w", err)
	}
	out, err := provenance.ToJSON(pred)
	if err != nil {
		return fmt.Errorf("rendering provenance predicate: %w", err)
	}
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return fmt.Errorf("writing provenance predicate: %w", err)
	}
	return nil
}

func runSign(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String("key", "", "path to a local private key file, or a KMS URI (azurekms://, awskms://, gcpkms://); omit for Sigstore keyless signing")
	bundlePath := fs.String("bundle", "", "path to write cosign's verification bundle (signature + certificate); required by modern cosign")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: policyforge sign [--key path] [--bundle path] <file>")
		return 2
	}

	out, err := signer.SignBlob(fs.Arg(0), signer.SignOptions{Key: *key, Bundle: *bundlePath})
	if err != nil {
		fmt.Fprintf(stderr, "sign error: %v\n", err)
		return 1
	}
	if out != "" {
		fmt.Fprint(stdout, out)
	}
	return 0
}

func runAttest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String("key", "", "path to a local private key file, or a KMS URI (azurekms://, awskms://, gcpkms://); omit for Sigstore keyless signing")
	predicatePath := fs.String("predicate", "", "path to the attestation predicate (e.g. a SLSA provenance predicate from 'policyforge scan --provenance')")
	predicateType := fs.String("type", "slsaprovenance", "predicate type (e.g. slsaprovenance, or a custom predicate type URI)")
	bundlePath := fs.String("bundle", "", "path to write cosign's verification bundle; required by modern cosign")
	outputAttestation := fs.String("output-attestation", "", "optional path to also write the raw attestation content")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: policyforge attest --predicate path [--type type] [--key path] [--bundle path] <file>")
		return 2
	}
	if *predicatePath == "" {
		fmt.Fprintln(stderr, "attest error: --predicate is required")
		return 2
	}

	out, err := signer.AttestBlob(fs.Arg(0), signer.AttestOptions{
		Key:               *key,
		PredicatePath:     *predicatePath,
		PredicateType:     *predicateType,
		Bundle:            *bundlePath,
		OutputAttestation: *outputAttestation,
	})
	if err != nil {
		fmt.Fprintf(stderr, "attest error: %v\n", err)
		return 1
	}
	if out != "" {
		fmt.Fprint(stdout, out)
	}
	return 0
}

func runDrift(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("drift", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", ".", "path to a directory of IaC files to check for drift")
	subscriptionID := fs.String("subscription-id", "", "Azure subscription ID to query for live resource state (required)")
	query := fs.String("query", "", "optional custom Resource Graph KQL query; defaults to querying every resource type PolicyForge can compare")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *subscriptionID == "" {
		fmt.Fprintln(stderr, "drift error: --subscription-id is required")
		return 2
	}

	resources, err := parseAll(*path)
	if err != nil {
		fmt.Fprintf(stderr, "parse error: %v\n", err)
		return 1
	}
	normalized := normalizer.Normalize(resources)

	kqlQuery := *query
	if kqlQuery == "" {
		kqlQuery = drift.DefaultQuery()
	}

	live, err := drift.Query(context.Background(), *subscriptionID, kqlQuery)
	if err != nil {
		fmt.Fprintf(stderr, "drift error: querying Azure Resource Graph: %v\n", err)
		return 1
	}

	result := drift.Compare(normalized, live)
	printDriftResult(stdout, result)

	if len(result.Findings) > 0 || len(result.NotFound) > 0 {
		return 1
	}
	return 0
}

func printDriftResult(w io.Writer, result drift.Result) {
	if len(result.Findings) == 0 && len(result.NotFound) == 0 {
		fmt.Fprintln(w, "✔ No drift detected.")
		return
	}

	for _, f := range result.Findings {
		fmt.Fprintf(w, "DRIFT   %-30s %-35s declared=%q live=%q\n", f.Resource, f.Attribute, f.Declared, f.Live)
	}
	for _, nf := range result.NotFound {
		fmt.Fprintf(w, "MISSING %-30s declared type=%s has no matching live resource\n", nf.Resource, nf.Type)
	}
	fmt.Fprintf(w, "\n%d drift finding(s), %d missing resource(s).\n", len(result.Findings), len(result.NotFound))
}

// parseAll runs every language-specific parser (Terraform, Bicep,
// Kubernetes) over path and merges their results. Each parser only acts
// on the file extensions it owns, so this is safe to call on a directory
// containing a mix of IaC languages, or on a single file.
func parseAll(path string) ([]parser.Resource, error) {
	var all []parser.Resource

	tf, err := terraform.ParseDir(path)
	if err != nil {
		return nil, fmt.Errorf("terraform: %w", err)
	}
	all = append(all, tf...)

	bp, err := bicep.ParseDir(path)
	if err != nil {
		return nil, fmt.Errorf("bicep: %w", err)
	}
	all = append(all, bp...)

	kr, err := k8s.ParseDir(path)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: %w", err)
	}
	all = append(all, kr...)

	return all, nil
}
