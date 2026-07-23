package main

import (
	"path/filepath"
	"testing"
	"time"
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

func TestStore_SessionRoundTrip(t *testing.T) {
	s := openTestStore(t)
	expiresAt := time.Now().Add(time.Hour)

	if err := s.CreateSession("sess-1", "user@example.com", "Test User", expiresAt); err != nil {
		t.Fatalf("CreateSession returned error: %v", err)
	}

	got, ok, err := s.GetSession("sess-1")
	if err != nil {
		t.Fatalf("GetSession returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected to find the created session")
	}
	if got.Email != "user@example.com" || got.Name != "Test User" {
		t.Errorf("expected email/name to round-trip, got %+v", got)
	}
}

func TestStore_GetSessionMissingReturnsFalse(t *testing.T) {
	s := openTestStore(t)
	_, ok, err := s.GetSession("does-not-exist")
	if err != nil {
		t.Fatalf("GetSession returned error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for a nonexistent session")
	}
}

func TestStore_GetSessionExpiredReturnsFalse(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateSession("sess-expired", "user@example.com", "Test User", time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("CreateSession returned error: %v", err)
	}

	_, ok, err := s.GetSession("sess-expired")
	if err != nil {
		t.Fatalf("GetSession returned error: %v", err)
	}
	if ok {
		t.Error("expected an already-expired session to report ok=false")
	}
}

func TestStore_DeleteSession(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateSession("sess-1", "user@example.com", "Test User", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreateSession returned error: %v", err)
	}

	if err := s.DeleteSession("sess-1"); err != nil {
		t.Fatalf("DeleteSession returned error: %v", err)
	}

	_, ok, err := s.GetSession("sess-1")
	if err != nil {
		t.Fatalf("GetSession returned error: %v", err)
	}
	if ok {
		t.Error("expected the session to be gone after DeleteSession")
	}
}

func TestStore_DeleteSessionMissingIsNotAnError(t *testing.T) {
	s := openTestStore(t)
	if err := s.DeleteSession("never-existed"); err != nil {
		t.Errorf("expected deleting a nonexistent session to be a no-op, got error: %v", err)
	}
}

func TestStore_AddAuditEventAndList(t *testing.T) {
	s := openTestStore(t)

	if err := s.AddAuditEvent("scan_ingested", "admin", "acme/infra-repo — scan #1, 3 finding(s)"); err != nil {
		t.Fatalf("AddAuditEvent returned error: %v", err)
	}
	if err := s.AddAuditEvent("login", "user@example.com", "logged in via SSO"); err != nil {
		t.Fatalf("AddAuditEvent returned error: %v", err)
	}

	events, err := s.AuditEvents()
	if err != nil {
		t.Fatalf("AuditEvents returned error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 audit events, got %d", len(events))
	}
	// Most recent first.
	if events[0].EventType != "login" || events[0].Actor != "user@example.com" {
		t.Errorf("expected the most recent event (login) first, got %+v", events[0])
	}
	if events[1].EventType != "scan_ingested" || events[1].Actor != "admin" {
		t.Errorf("expected the older event (scan_ingested) second, got %+v", events[1])
	}
}

func TestStore_AuditEventsEmptyReturnsNoRows(t *testing.T) {
	s := openTestStore(t)
	events, err := s.AuditEvents()
	if err != nil {
		t.Fatalf("AuditEvents returned error: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 audit events, got %d", len(events))
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
