// Package engine evaluates normalized resources against policy rules and
// renders findings in several output formats.
//
// Evaluation runs real OPA/Rego rule packs (see opa.go and policies/)
// rather than hardcoded Go checks, so adding a policy rule never requires
// a Go code change.
package engine

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/chethankumblekar/policyforge/internal/normalizer"
)

// Severity levels, ordered low to high.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Finding is a single policy violation surfaced for a resource.
type Finding struct {
	RuleID      string
	Title       string
	Severity    Severity
	Resource    string
	File        string
	Line        int
	Description string
}

// Evaluate runs every embedded Rego rule pack against the given resources,
// plus any user-authored rule packs found under extraPolicyDirs (custom
// policy authoring).
func Evaluate(ctx context.Context, resources []normalizer.Resource, extraPolicyDirs ...string) ([]Finding, error) {
	return EvaluateOPA(ctx, resources, extraPolicyDirs...)
}

// HasFailures reports whether any HIGH or CRITICAL findings exist, used
// to set the CLI's exit code for CI/CD gating.
func HasFailures(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity == SeverityHigh || f.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// PrintTable writes a human-readable findings table to stdout.
func PrintTable(findings []Finding) {
	if len(findings) == 0 {
		fmt.Println("✔ No policy violations found.")
		return
	}

	fmt.Printf("%-10s %-10s %-40s %s\n", "RULE", "SEVERITY", "RESOURCE", "LOCATION")
	for _, f := range findings {
		fmt.Printf("%-10s %-10s %-40s %s:%d\n", f.RuleID, f.Severity, f.Resource, f.File, f.Line)
		fmt.Printf("           %s\n", f.Title)
	}
	fmt.Printf("\n%d finding(s).\n", len(findings))
}

// ToJSON renders findings as a JSON array.
func ToJSON(findings []Finding) string {
	b, _ := json.MarshalIndent(findings, "", "  ")
	return string(b)
}

// sarifLog and related types implement just enough of the SARIF 2.1.0
// schema for GitHub code scanning / Azure DevOps to ingest results.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func severityToSARIFLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// ToSARIF renders findings as a SARIF 2.1.0 log, ready to upload via
// github/codeql-action/upload-sarif or Azure DevOps' SARIF task.
func ToSARIF(findings []Finding) string {
	run := sarifRun{
		Tool: sarifTool{
			Driver: sarifDriver{Name: "policyforge", Version: "0.1.0-dev"},
		},
	}

	for _, f := range findings {
		run.Results = append(run.Results, sarifResult{
			RuleID: f.RuleID,
			Level:  severityToSARIFLevel(f.Severity),
			Message: sarifMessage{
				Text: f.Description,
			},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.File},
					Region:           sarifRegion{StartLine: f.Line},
				},
			}},
		})
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}

	b, _ := json.MarshalIndent(log, "", "  ")
	return string(b)
}
