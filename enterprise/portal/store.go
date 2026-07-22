package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
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

// Store persists scan runs in a SQLite database file (via the pure-Go,
// CGO-free modernc.org/sqlite driver, so this stays a single static
// binary in Docker) — real persistence, replacing the original in-memory
// prototype, per enterprise/DESIGN.md's move toward a real self-hosted
// product.
type Store struct {
	db *sql.DB
}

// NewStore opens (creating if needed) a SQLite database at dbPath and
// ensures its schema exists.
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database %s: %w", dbPath, err)
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS scans (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			org           TEXT NOT NULL,
			project       TEXT NOT NULL,
			created_at    TEXT NOT NULL,
			findings_json TEXT NOT NULL
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}

	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Add stores a new scan run and returns it with its assigned ID and
// ingestion timestamp.
func (s *Store) Add(org, project string, findings []Finding) (ScanRun, error) {
	if findings == nil {
		findings = []Finding{}
	}
	findingsJSON, err := json.Marshal(findings)
	if err != nil {
		return ScanRun{}, fmt.Errorf("encoding findings: %w", err)
	}

	createdAt := time.Now()
	res, err := s.db.Exec(
		`INSERT INTO scans (org, project, created_at, findings_json) VALUES (?, ?, ?, ?)`,
		org, project, createdAt.Format(time.RFC3339Nano), string(findingsJSON),
	)
	if err != nil {
		return ScanRun{}, fmt.Errorf("inserting scan: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return ScanRun{}, fmt.Errorf("reading inserted scan id: %w", err)
	}

	return ScanRun{ID: int(id), Org: org, Project: project, CreatedAt: createdAt, Findings: findings}, nil
}

// All returns every scan run, most recently ingested first.
func (s *Store) All() ([]ScanRun, error) {
	rows, err := s.db.Query(`SELECT id, org, project, created_at, findings_json FROM scans ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("querying scans: %w", err)
	}
	defer rows.Close()

	var out []ScanRun
	for rows.Next() {
		run, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

// Get looks up a scan run by ID.
func (s *Store) Get(id int) (ScanRun, bool, error) {
	row := s.db.QueryRow(`SELECT id, org, project, created_at, findings_json FROM scans WHERE id = ?`, id)

	run, err := scanRow(row)
	if err == sql.ErrNoRows {
		return ScanRun{}, false, nil
	}
	if err != nil {
		return ScanRun{}, false, err
	}
	return run, true, nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows, so scanRow
// works for Get's single-row lookup and All's multi-row iteration alike.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanRow(rs rowScanner) (ScanRun, error) {
	var run ScanRun
	var createdAt, findingsJSON string

	if err := rs.Scan(&run.ID, &run.Org, &run.Project, &createdAt, &findingsJSON); err != nil {
		return ScanRun{}, err
	}

	t, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return ScanRun{}, fmt.Errorf("parsing created_at: %w", err)
	}
	run.CreatedAt = t

	if err := json.Unmarshal([]byte(findingsJSON), &run.Findings); err != nil {
		return ScanRun{}, fmt.Errorf("decoding findings: %w", err)
	}

	return run, nil
}
