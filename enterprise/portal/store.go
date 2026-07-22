package main

import (
	"sort"
	"sync"
	"time"
)

// Finding mirrors the JSON shape of internal/engine.Finding (the OSS
// CLI's own --format json output), so a scan's JSON is postable to
// /api/scans verbatim — no separate client-side transformation needed.
type Finding struct {
	RuleID      string `json:"RuleID"`
	Title       string `json:"Title"`
	Severity    string `json:"Severity"`
	Resource    string `json:"Resource"`
	File        string `json:"File"`
	Line        int    `json:"Line"`
	Description string `json:"Description"`
}

// ScanRun is one ingested scan.
type ScanRun struct {
	ID        int
	Org       string
	Project   string
	CreatedAt time.Time
	Findings  []Finding
}

// SeverityCounts tallies findings per severity, always including all four
// known severities (even at zero) so templates don't need existence
// checks.
func (s ScanRun) SeverityCounts() map[string]int {
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, f := range s.Findings {
		counts[f.Severity]++
	}
	return counts
}

// Store is a process-lifetime, in-memory scan run store. This is a local
// prototype (see enterprise/DESIGN.md) — there is deliberately no
// persistence, auth, or multi-tenancy isolation here yet.
type Store struct {
	mu     sync.Mutex
	nextID int
	scans  []ScanRun
}

func NewStore() *Store {
	return &Store{nextID: 1}
}

// Add stores a new scan run and returns it with its assigned ID and
// ingestion timestamp.
func (s *Store) Add(org, project string, findings []Finding) ScanRun {
	s.mu.Lock()
	defer s.mu.Unlock()

	run := ScanRun{
		ID:        s.nextID,
		Org:       org,
		Project:   project,
		CreatedAt: time.Now(),
		Findings:  findings,
	}
	s.nextID++
	s.scans = append(s.scans, run)
	return run
}

// All returns every scan run, most recently ingested first.
func (s *Store) All() []ScanRun {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]ScanRun, len(s.scans))
	copy(out, s.scans)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Get looks up a scan run by ID.
func (s *Store) Get(id int) (ScanRun, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, r := range s.scans {
		if r.ID == id {
			return r, true
		}
	}
	return ScanRun{}, false
}
