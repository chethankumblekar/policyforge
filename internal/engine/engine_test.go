package engine

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestHasFailures(t *testing.T) {
	cases := []struct {
		name     string
		findings []Finding
		want     bool
	}{
		{"empty", nil, false},
		{"only low", []Finding{{Severity: SeverityLow}}, false},
		{"only medium", []Finding{{Severity: SeverityMedium}}, false},
		{"has high", []Finding{{Severity: SeverityLow}, {Severity: SeverityHigh}}, true},
		{"has critical", []Finding{{Severity: SeverityCritical}}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasFailures(tc.findings); got != tc.want {
				t.Errorf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestPrintTable_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	PrintTable(&buf, nil)

	if !strings.Contains(buf.String(), "No policy violations found") {
		t.Errorf("expected the clean-scan message, got:\n%s", buf.String())
	}
}

func TestPrintTable_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	PrintTable(&buf, []Finding{
		{RuleID: "PF-AZ-001", Title: "public blob access", Severity: SeverityHigh, Resource: "example", File: "main.tf", Line: 3},
	})

	out := buf.String()
	for _, want := range []string{"PF-AZ-001", "HIGH", "example", "main.tf:3", "public blob access", "1 finding(s)."} {
		if !strings.Contains(out, want) {
			t.Errorf("expected table output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestToJSON_RoundTrips(t *testing.T) {
	findings := []Finding{
		{RuleID: "PF-AZ-001", Title: "t", Severity: SeverityHigh, Resource: "r", File: "f", Line: 1, Description: "d"},
	}

	out := ToJSON(findings)

	var decoded []Finding
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("ToJSON output did not parse as valid JSON: %v", err)
	}
	if len(decoded) != 1 || decoded[0].RuleID != "PF-AZ-001" {
		t.Errorf("expected round-tripped finding PF-AZ-001, got %+v", decoded)
	}
}

func TestToJSON_EmptyFindings(t *testing.T) {
	out := ToJSON(nil)
	if strings.TrimSpace(out) != "null" {
		t.Errorf("expected JSON \"null\" for nil findings, got %q", out)
	}
}

func TestToSARIF_ProducesValidSARIFShape(t *testing.T) {
	findings := []Finding{
		{RuleID: "PF-AZ-010", Title: "t", Severity: SeverityCritical, Resource: "r", File: "main.tf", Line: 11, Description: "NSG rule allows unrestricted inbound"},
	}

	out := ToSARIF(findings)

	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("ToSARIF output did not parse as valid JSON: %v", err)
	}
	if decoded["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", decoded["version"])
	}

	runs, _ := decoded["runs"].([]interface{})
	if len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}
	run, _ := runs[0].(map[string]interface{})
	results, _ := run["results"].([]interface{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	result, _ := results[0].(map[string]interface{})
	if result["ruleId"] != "PF-AZ-010" {
		t.Errorf("expected ruleId PF-AZ-010, got %v", result["ruleId"])
	}
	if result["level"] != "error" {
		t.Errorf("expected level \"error\" for a CRITICAL finding, got %v", result["level"])
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	cases := map[Severity]string{
		SeverityCritical:  "error",
		SeverityHigh:      "error",
		SeverityMedium:    "warning",
		SeverityLow:       "note",
		Severity("BOGUS"): "note",
	}

	for sev, want := range cases {
		if got := severityToSARIFLevel(sev); got != want {
			t.Errorf("severity %s: expected level %q, got %q", sev, want, got)
		}
	}
}

func TestToSARIF_EmptyFindingsHasNoResults(t *testing.T) {
	out := ToSARIF(nil)

	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("ToSARIF output did not parse as valid JSON: %v", err)
	}
	runs, _ := decoded["runs"].([]interface{})
	run, _ := runs[0].(map[string]interface{})
	if run["results"] != nil {
		t.Errorf("expected no results for an empty findings list, got %v", run["results"])
	}
}
