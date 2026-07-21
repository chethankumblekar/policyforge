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
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "version":
		fmt.Println("policyforge version", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`policyforge - open-source policy-as-code scanner for Terraform, Bicep, and Kubernetes

Commands:
  scan      Scan IaC files against policy rule packs
  version   Print the CLI version

Run 'policyforge scan --help' for scan options.`)
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	path := fs.String("path", ".", "path to a directory of IaC files to scan")
	format := fs.String("format", "table", "output format: table | sarif | json")
	genSBOM := fs.Bool("sbom", false, "also generate an SBOM alongside scan results")
	policyDir := fs.String("policy-dir", "", "optional path to a directory of additional user-authored .rego policy files")
	fs.Parse(args)

	// 1. Parse every supported IaC language found in the target path.
	resources, err := parseAll(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %v\n", err)
		os.Exit(1)
	}

	// 2. Normalize into the unified internal resource model.
	normalized := normalizer.Normalize(resources)

	// 3. Evaluate against the embedded Rego rule packs, plus any custom
	// policy pack the user pointed --policy-dir at.
	findings, err := engine.Evaluate(context.Background(), normalized, *policyDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policy evaluation error: %v\n", err)
		os.Exit(1)
	}

	switch *format {
	case "sarif":
		fmt.Println(engine.ToSARIF(findings))
	case "json":
		fmt.Println(engine.ToJSON(findings))
	default:
		engine.PrintTable(findings)
	}

	if *genSBOM {
		doc := sbom.Generate(normalized)
		fmt.Fprintln(os.Stderr, "\nSBOM generated:")
		fmt.Println(sbom.ToJSON(doc))
	}

	if engine.HasFailures(findings) {
		os.Exit(1)
	}
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
