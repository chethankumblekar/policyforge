// Package engine evaluates normalized resources against policy rules and
// renders findings in several output formats.
//
// v0.1 implements a small set of checks as native Go functions so the CLI
// is fully runnable today. Phase 1 (see docs/roadmap in the project plan)
// replaces evaluateNative with real OPA/Rego evaluation, loading .rego
// files from policies/, while keeping this package's public API
// (Evaluate, ToSARIF, ToJSON, PrintTable, HasFailures) unchanged so the
// CLI and CI/CD integrations don't need to change.
package engine

import (
	"encoding/json"
	"fmt"
	"strings"

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

// Evaluate runs all built-in checks against the given resources.
func Evaluate(resources []normalizer.Resource) []Finding {
	var findings []Finding

	for _, r := range resources {
		findings = append(findings, evaluateNative(r)...)
	}

	return findings
}

// evaluateNative holds the v0.1 hardcoded rule set. Each corresponds to a
// CIS Azure Foundations Benchmark control; the .rego equivalents live in
// policies/azure/cis-foundations for when the OPA engine is wired in.
func evaluateNative(r normalizer.Resource) []Finding {
	var findings []Finding

	switch r.Type {
	case "storage_account":
		if strings.EqualFold(r.Attributes["allow_nested_items_to_be_public"], "true") {
			findings = append(findings, Finding{
				RuleID:      "PF-AZ-001",
				Title:       "Storage account allows public blob access",
				Severity:    SeverityHigh,
				Resource:    r.Name,
				File:        r.Source.File,
				Line:        r.Source.Line,
				Description: "allow_nested_items_to_be_public should be false. Maps to CIS Azure Foundations 3.6.",
			})
		}
		if !strings.EqualFold(r.Attributes["min_tls_version"], "TLS1_2") {
			findings = append(findings, Finding{
				RuleID:      "PF-AZ-002",
				Title:       "Storage account does not enforce TLS 1.2 minimum",
				Severity:    SeverityMedium,
				Resource:    r.Name,
				File:        r.Source.File,
				Line:        r.Source.Line,
				Description: "min_tls_version should be set to TLS1_2. Maps to CIS Azure Foundations 3.1.",
			})
		}

	case "nsg_rule":
		if r.Attributes["direction"] == "Inbound" &&
			(r.Attributes["source_address_prefix"] == "*" || r.Attributes["source_address_prefix"] == "0.0.0.0/0") &&
			strings.EqualFold(r.Attributes["access"], "Allow") {
			findings = append(findings, Finding{
				RuleID:      "PF-AZ-010",
				Title:       "NSG rule allows unrestricted inbound access",
				Severity:    SeverityCritical,
				Resource:    r.Name,
				File:        r.Source.File,
				Line:        r.Source.Line,
				Description: "Inbound rule with source_address_prefix \"*\" allows traffic from any IP. Maps to CIS Azure Foundations 6.1/6.2.",
			})
		}

	case "key_vault":
		if !strings.EqualFold(r.Attributes["purge_protection_enabled"], "true") {
			findings = append(findings, Finding{
				RuleID:      "PF-AZ-020",
				Title:       "Key Vault purge protection disabled",
				Severity:    SeverityMedium,
				Resource:    r.Name,
				File:        r.Source.File,
				Line:        r.Source.Line,
				Description: "purge_protection_enabled should be true to prevent permanent data loss from accidental/malicious deletion.",
			})
		}
	}

	return findings
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
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
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
	RuleID  string          `json:"ruleId"`
	Level   string          `json:"level"`
	Message sarifMessage    `json:"message"`
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
				Text: fmt.Sprintf("%s: %s", f.Title, f.Description),
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
