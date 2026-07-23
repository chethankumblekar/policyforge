package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
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

// ScanRun is one ingested scan. SBOM/Provenance are the raw JSON bodies
// POSTed alongside findings (see ingestRequest in handlers.go) — the
// portal stores and displays them as opaque documents rather than
// parsing their fields, matching enterprise/DESIGN.md's non-goal of
// re-implementing anything the CLI itself already produced. Both are
// empty strings when a scan was ingested without --sbom/--provenance.
type ScanRun struct {
	ID         int
	Org        string
	Project    string
	CreatedAt  time.Time
	Findings   []Finding
	SBOM       string
	Provenance string
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

	// Added after the initial schema — migrateAddColumn makes adding
	// them to a database file created by an older portal version safe.
	if err := migrateAddColumn(db, "scans", "sbom_json", "TEXT"); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrateAddColumn(db, "scans", "provenance_json", "TEXT"); err != nil {
		db.Close()
		return nil, err
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id         TEXT PRIMARY KEY,
			email      TEXT NOT NULL,
			name       TEXT NOT NULL,
			expires_at TEXT NOT NULL
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_events (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT NOT NULL,
			actor      TEXT NOT NULL,
			detail     TEXT NOT NULL,
			created_at TEXT NOT NULL
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}

	return &Store{db: db}, nil
}

// migrateAddColumn adds column to table if it isn't already there. SQLite
// has no "ADD COLUMN IF NOT EXISTS", so this just treats the "duplicate
// column" error a repeat run produces as success — a lightweight
// alternative to a full migration framework for a schema this small.
func migrateAddColumn(db *sql.DB, table, column, ddl string) error {
	_, err := db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, ddl))
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		return fmt.Errorf("adding column %s.%s: %w", table, column, err)
	}
	return nil
}

// Session is one logged-in dashboard user's SSO session (see sso.go).
// Sessions are stored in the same SQLite file as scans, so a login
// survives a portal restart the same way scan history does.
type Session struct {
	ID        string
	Email     string
	Name      string
	ExpiresAt time.Time
}

// CreateSession stores a new session.
func (s *Store) CreateSession(id, email, name string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO sessions (id, email, name, expires_at) VALUES (?, ?, ?, ?)`,
		id, email, name, expiresAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("inserting session: %w", err)
	}
	return nil
}

// GetSession looks up a session by ID, treating an expired session the
// same as a missing one (ok=false) rather than erroring — callers just
// need to know whether to treat the caller as logged in.
func (s *Store) GetSession(id string) (Session, bool, error) {
	row := s.db.QueryRow(`SELECT id, email, name, expires_at FROM sessions WHERE id = ?`, id)

	var sess Session
	var expiresAt string
	err := row.Scan(&sess.ID, &sess.Email, &sess.Name, &expiresAt)
	if err == sql.ErrNoRows {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, fmt.Errorf("querying session: %w", err)
	}

	t, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return Session{}, false, fmt.Errorf("parsing session expires_at: %w", err)
	}
	sess.ExpiresAt = t

	if time.Now().After(sess.ExpiresAt) {
		return Session{}, false, nil
	}
	return sess, true, nil
}

// DeleteSession removes a session (logout). Deleting a session that
// doesn't exist is not an error.
func (s *Store) DeleteSession(id string) error {
	if _, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id); err != nil {
		return fmt.Errorf("deleting session: %w", err)
	}
	return nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// AuditEvent is one entry in the portal's audit log — a scan ingested, a
// user logging in or out. See enterprise/DESIGN.md's "Audit trail" scope
// item: an immutable log of who/what happened, for compliance evidence.
// There's no update or delete on this table by design.
type AuditEvent struct {
	ID        int
	EventType string
	Actor     string
	Detail    string
	CreatedAt time.Time
}

// AddAuditEvent records one audit log entry. actor identifies who/what
// triggered it — a Basic Auth username for CLI/CI ingestion, or an SSO
// session's email for login/logout — and detail is a short human-readable
// description (e.g. "acme/infra-repo — scan #3, 21 finding(s)").
func (s *Store) AddAuditEvent(eventType, actor, detail string) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_events (event_type, actor, detail, created_at) VALUES (?, ?, ?, ?)`,
		eventType, actor, detail, time.Now().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("inserting audit event: %w", err)
	}
	return nil
}

// AuditEvents returns every audit event, most recent first.
func (s *Store) AuditEvents() ([]AuditEvent, error) {
	rows, err := s.db.Query(`SELECT id, event_type, actor, detail, created_at FROM audit_events ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("querying audit events: %w", err)
	}
	defer rows.Close()

	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var createdAt string
		if err := rows.Scan(&e.ID, &e.EventType, &e.Actor, &e.Detail, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning audit event: %w", err)
		}
		t, err := time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, fmt.Errorf("parsing audit event created_at: %w", err)
		}
		e.CreatedAt = t
		out = append(out, e)
	}
	return out, rows.Err()
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

const scanColumns = `id, org, project, created_at, findings_json, sbom_json, provenance_json`

// All returns every scan run, most recently ingested first.
func (s *Store) All() ([]ScanRun, error) {
	rows, err := s.db.Query(`SELECT ` + scanColumns + ` FROM scans ORDER BY created_at DESC`)
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
	row := s.db.QueryRow(`SELECT `+scanColumns+` FROM scans WHERE id = ?`, id)

	run, err := scanRow(row)
	if err == sql.ErrNoRows {
		return ScanRun{}, false, nil
	}
	if err != nil {
		return ScanRun{}, false, err
	}
	return run, true, nil
}

// SetArtifacts attaches an SBOM and/or SLSA provenance predicate (as raw
// JSON, exactly as posted to /api/scans) to an already-ingested scan.
// Passing "" for either leaves that scan without one, matching a CLI
// invocation that ran without --sbom/--provenance.
func (s *Store) SetArtifacts(scanID int, sbomJSON, provenanceJSON string) error {
	_, err := s.db.Exec(
		`UPDATE scans SET sbom_json = ?, provenance_json = ? WHERE id = ?`,
		nullIfEmpty(sbomJSON), nullIfEmpty(provenanceJSON), scanID,
	)
	if err != nil {
		return fmt.Errorf("updating scan artifacts: %w", err)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows, so scanRow
// works for Get's single-row lookup and All's multi-row iteration alike.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanRow(rs rowScanner) (ScanRun, error) {
	var run ScanRun
	var createdAt, findingsJSON string
	var sbomJSON, provenanceJSON sql.NullString

	if err := rs.Scan(&run.ID, &run.Org, &run.Project, &createdAt, &findingsJSON, &sbomJSON, &provenanceJSON); err != nil {
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
	run.SBOM = sbomJSON.String
	run.Provenance = provenanceJSON.String

	return run, nil
}
