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
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/chethankumblekar/policyforge/internal/engine"
	"github.com/chethankumblekar/policyforge/internal/normalizer"
	"github.com/chethankumblekar/policyforge/internal/parser"
	"github.com/chethankumblekar/policyforge/internal/parser/bicep"
	"github.com/chethankumblekar/policyforge/internal/parser/k8s"
	"github.com/chethankumblekar/policyforge/internal/parser/terraform"
	"github.com/chethankumblekar/policyforge/internal/sbom"
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
  version   Print the CLI version

Run 'policyforge scan --help' for scan options.`)
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", ".", "path to a directory of IaC files to scan")
	format := fs.String("format", "table", "output format: table | sarif | json")
	genSBOM := fs.Bool("sbom", false, "also generate an SBOM alongside scan results")
	policyDir := fs.String("policy-dir", "", "optional path to a directory of additional user-authored .rego policy files")
	if err := fs.Parse(args); err != nil {
		return 2
	}

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

	if engine.HasFailures(findings) {
		return 1
	}
	return 0
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
