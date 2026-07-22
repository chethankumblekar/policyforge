package main

import "testing"

func TestStore_AddAssignsIncrementingIDs(t *testing.T) {
	s := NewStore()

	first := s.Add("acme", "infra-repo", nil)
	second := s.Add("acme", "k8s-manifests", nil)

	if first.ID != 1 || second.ID != 2 {
		t.Fatalf("expected IDs 1 and 2, got %d and %d", first.ID, second.ID)
	}
}

func TestStore_GetFindsByID(t *testing.T) {
	s := NewStore()
	added := s.Add("acme", "infra-repo", []Finding{{RuleID: "PF-AZ-001", Severity: "HIGH"}})

	got, ok := s.Get(added.ID)
	if !ok {
		t.Fatal("expected to find the added scan run")
	}
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "PF-AZ-001" {
		t.Errorf("expected the stored findings to round-trip, got %+v", got.Findings)
	}
}

func TestStore_GetMissingIDReturnsFalse(t *testing.T) {
	s := NewStore()
	if _, ok := s.Get(999); ok {
		t.Error("expected ok=false for a nonexistent scan ID")
	}
}

func TestStore_AllReturnsMostRecentFirst(t *testing.T) {
	s := NewStore()
	first := s.Add("acme", "a", nil)
	second := s.Add("acme", "b", nil)

	all := s.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 scan runs, got %d", len(all))
	}
	if all[0].ID != second.ID || all[1].ID != first.ID {
		t.Errorf("expected most-recent-first order, got IDs %d, %d", all[0].ID, all[1].ID)
	}
}

func TestScanRun_SeverityCountsIncludesZeroSeverities(t *testing.T) {
	run := ScanRun{Findings: []Finding{{Severity: "CRITICAL"}, {Severity: "CRITICAL"}, {Severity: "LOW"}}}

	counts := run.SeverityCounts()
	if counts["CRITICAL"] != 2 {
		t.Errorf("expected CRITICAL=2, got %d", counts["CRITICAL"])
	}
	if counts["LOW"] != 1 {
		t.Errorf("expected LOW=1, got %d", counts["LOW"])
	}
	// HIGH/MEDIUM never occurred, but templates index this map
	// unconditionally — it must still report 0, not be absent.
	if counts["HIGH"] != 0 || counts["MEDIUM"] != 0 {
		t.Errorf("expected HIGH and MEDIUM to be present at 0, got %+v", counts)
	}
}
