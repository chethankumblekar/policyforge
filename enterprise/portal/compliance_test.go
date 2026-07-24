package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuildComplianceReport_FailingProjectShowsUpUnderMappedControl(t *testing.T) {
	scans := []ScanRun{
		{ID: 1, Org: "acme", Project: "infra-repo", CreatedAt: time.Now(), Findings: []Finding{
			{RuleID: "PF-AZ-001", Severity: "HIGH"},
		}},
		{ID: 2, Org: "acme", Project: "clean-repo", CreatedAt: time.Now(), Findings: nil},
	}

	report := BuildComplianceReport(scans)

	cc61 := findControl(t, report.Frameworks["SOC2"], "CC6.1")
	if len(cc61.FailingProjects) != 1 {
		t.Fatalf("expected 1 failing project for CC6.1, got %d: %+v", len(cc61.FailingProjects), cc61.FailingProjects)
	}
	if cc61.FailingProjects[0].Project != "infra-repo" {
		t.Errorf("expected infra-repo to fail CC6.1, got %q", cc61.FailingProjects[0].Project)
	}

	cc67 := findControl(t, report.Frameworks["SOC2"], "CC6.7")
	if len(cc67.FailingProjects) != 0 {
		t.Errorf("expected no failing projects for CC6.7 (no TLS findings ingested), got %+v", cc67.FailingProjects)
	}
}

func TestBuildComplianceReport_OnlyLatestScanPerProjectCounts(t *testing.T) {
	scans := []ScanRun{
		{ID: 1, Org: "acme", Project: "infra-repo", CreatedAt: time.Now(), Findings: []Finding{
			{RuleID: "PF-AWS-010", Severity: "CRITICAL"},
		}},
	}
	time.Sleep(2 * time.Millisecond)
	scans = append(scans, ScanRun{
		ID: 2, Org: "acme", Project: "infra-repo", CreatedAt: time.Now(), Findings: nil,
	})

	report := BuildComplianceReport(scans)

	cc66 := findControl(t, report.Frameworks["SOC2"], "CC6.6")
	if len(cc66.FailingProjects) != 0 {
		t.Errorf("expected the clean rescan to supersede the earlier failing scan, got %+v", cc66.FailingProjects)
	}
}

func TestBuildComplianceReport_UnmappedRuleIDsAreReported(t *testing.T) {
	report := BuildComplianceReport(nil)

	pciUnmapped := report.UnmappedRuleIDs["PCI DSS"]
	found := false
	for _, r := range pciUnmapped {
		if r == "PF-K8S-005" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PF-K8S-005 to be reported as unmapped for PCI DSS, got %v", pciUnmapped)
	}
}

// A control with no failing projects must marshal FailingProjects as `[]`,
// not `null` — the frontend calls .length on it unconditionally (see
// web/src/app/compliance/page.tsx's ControlRow), which throws on null.
func TestBuildComplianceReport_EmptyFailingProjectsMarshalsAsEmptyArray(t *testing.T) {
	report := BuildComplianceReport(nil)

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	if strings.Contains(string(encoded), `"failingProjects":null`) {
		t.Errorf("expected failingProjects to marshal as [], found null in: %s", encoded)
	}
}

func findControl(t *testing.T, statuses []ControlStatus, id string) ControlStatus {
	t.Helper()
	for _, s := range statuses {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("control %q not found among %+v", id, statuses)
	return ControlStatus{}
}
