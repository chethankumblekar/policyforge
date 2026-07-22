package main

import (
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestNewStore_CreatesFileOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "portal.db")
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	defer store.Close()

	if _, err := store.Add("acme", "infra-repo", nil); err != nil {
		t.Fatalf("Add returned error: %v", err)
	}

	// Reopening the same path must see the previously written data —
	// proving this is real persistence, not the original in-memory
	// prototype.
	reopened, err := NewStore(path)
	if err != nil {
		t.Fatalf("reopening store returned error: %v", err)
	}
	defer reopened.Close()

	all, err := reopened.All()
	if err != nil {
		t.Fatalf("All returned error: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected the scan written by the first Store instance to survive reopening, got %d scans", len(all))
	}
}

func TestStore_AddAssignsIncrementingIDs(t *testing.T) {
	s := openTestStore(t)

	first, err := s.Add("acme", "infra-repo", nil)
	if err != nil {
		t.Fatalf("Add returned error: %v", err)
	}
	second, err := s.Add("acme", "k8s-manifests", nil)
	if err != nil {
		t.Fatalf("Add returned error: %v", err)
	}

	if first.ID != 1 || second.ID != 2 {
		t.Fatalf("expected IDs 1 and 2, got %d and %d", first.ID, second.ID)
	}
}

func TestStore_GetFindsByID(t *testing.T) {
	s := openTestStore(t)
	added, err := s.Add("acme", "infra-repo", []Finding{{RuleID: "PF-AZ-001", Severity: "HIGH"}})
	if err != nil {
		t.Fatalf("Add returned error: %v", err)
	}

	got, ok, err := s.Get(added.ID)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected to find the added scan run")
	}
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "PF-AZ-001" {
		t.Errorf("expected the stored findings to round-trip, got %+v", got.Findings)
	}
}

func TestStore_GetMissingIDReturnsFalse(t *testing.T) {
	s := openTestStore(t)
	_, ok, err := s.Get(999)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for a nonexistent scan ID")
	}
}

func TestStore_AllReturnsMostRecentFirst(t *testing.T) {
	s := openTestStore(t)
	first, err := s.Add("acme", "a", nil)
	if err != nil {
		t.Fatalf("Add returned error: %v", err)
	}
	second, err := s.Add("acme", "b", nil)
	if err != nil {
		t.Fatalf("Add returned error: %v", err)
	}

	all, err := s.All()
	if err != nil {
		t.Fatalf("All returned error: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 scan runs, got %d", len(all))
	}
	if all[0].ID != second.ID || all[1].ID != first.ID {
		t.Errorf("expected most-recent-first order, got IDs %d, %d", all[0].ID, all[1].ID)
	}
}

func TestStore_AddNilFindingsRoundTripsAsEmpty(t *testing.T) {
	s := openTestStore(t)
	added, err := s.Add("acme", "infra-repo", nil)
	if err != nil {
		t.Fatalf("Add returned error: %v", err)
	}

	got, ok, err := s.Get(added.ID)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected to find the added scan run")
	}
	if len(got.Findings) != 0 {
		t.Errorf("expected 0 findings, got %+v", got.Findings)
	}
}

func TestNewStore_InvalidPathErrors(t *testing.T) {
	if _, err := NewStore(filepath.Join(t.TempDir(), "does-not-exist", "portal.db")); err == nil {
		t.Fatal("expected an error for a path whose parent directory doesn't exist, got nil")
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
