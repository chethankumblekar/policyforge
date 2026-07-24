// Package main's HTTP handlers. The dashboard UI itself lives in web/ (a
// Next.js app) — this file is a pure JSON API: ingestion (POST
// /api/scans, Basic-Auth-gated, the CLI/CI-pipeline path) and read
// endpoints (GET /api/scans, GET /api/scans/{id}, GET /api/session,
// GET /api/audit, GET /api/compliance, gated the same way the dashboard
// is — SSO session or Basic Auth, see main.go) that the Next.js frontend
// calls for data.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// ingestRequest is the JSON body /api/scans accepts: the same Finding
// shape internal/engine.ToJSON already produces, plus org/project so the
// portal can group scans by where they came from. SBOM/Provenance are
// optional — present only when the CLI invocation that posted this scan
// also passed --sbom/--provenance (see cmd/policyforge's uploadFindings)
// — and are stored as opaque JSON (json.RawMessage), not decoded into
// portal-side types; see ScanRun's doc comment for why.
type ingestRequest struct {
	Org        string          `json:"org"`
	Project    string          `json:"project"`
	Findings   []Finding       `json:"findings"`
	SBOM       json.RawMessage `json:"sbom,omitempty"`
	Provenance json.RawMessage `json:"provenance,omitempty"`
}

type ingestResponse struct {
	ID  int    `json:"id"`
	URL string `json:"url"`
}

func handleIngest(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ingestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Org == "" || req.Project == "" {
			http.Error(w, "\"org\" and \"project\" are required", http.StatusBadRequest)
			return
		}

		run, err := store.Add(req.Org, req.Project, req.Findings)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if len(req.SBOM) > 0 || len(req.Provenance) > 0 {
			if err := store.SetArtifacts(run.ID, string(req.SBOM), string(req.Provenance)); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		// The Basic Auth username is the closest thing to an actor
		// identity CLI/CI ingestion has (see auth.go — Basic Auth is the
		// only auth /api/scans ever uses, regardless of SSO); r.BasicAuth
		// already passed validation in the basicAuth middleware, so this
		// just re-reads the same header. Auth disabled (empty
		// credentials) means there's no actor at all to report.
		actor, _, ok := r.BasicAuth()
		if !ok {
			actor = "anonymous"
		}
		detail := fmt.Sprintf("%s/%s — scan #%d, %d finding(s)", req.Org, req.Project, run.ID, len(run.Findings))
		if err := store.AddAuditEvent("scan_ingested", actor, detail); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(ingestResponse{
			ID:  run.ID,
			URL: "/scans/" + strconv.Itoa(run.ID),
		})
	}
}

// scanSummary is the list-view JSON shape: everything the scan list page
// needs, without repeating every finding's full detail. HasSBOM/
// HasProvenance are just presence flags — the full documents are only
// in scanDetail, so the list view stays small.
type scanSummary struct {
	ID             int            `json:"id"`
	Org            string         `json:"org"`
	Project        string         `json:"project"`
	CreatedAt      string         `json:"createdAt"`
	SeverityCounts map[string]int `json:"severityCounts"`
	Total          int            `json:"total"`
	HasSBOM        bool           `json:"hasSBOM"`
	HasProvenance  bool           `json:"hasProvenance"`
}

func handleScansList(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scans, err := store.All()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		summaries := make([]scanSummary, 0, len(scans))
		for _, s := range scans {
			summaries = append(summaries, scanSummary{
				ID:             s.ID,
				Org:            s.Org,
				Project:        s.Project,
				CreatedAt:      s.CreatedAt.Format(rfc3339Milli),
				SeverityCounts: s.SeverityCounts(),
				Total:          len(s.Findings),
				HasSBOM:        s.SBOM != "",
				HasProvenance:  s.Provenance != "",
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summaries)
	}
}

// scanDetail is the detail-view JSON shape: the summary fields plus every
// finding, and the full SBOM/provenance documents (opaque JSON — see
// ScanRun) when the scan was ingested with them.
type scanDetail struct {
	scanSummary
	Findings   []Finding       `json:"findings"`
	SBOM       json.RawMessage `json:"sbom,omitempty"`
	Provenance json.RawMessage `json:"provenance,omitempty"`
}

func handleScanDetailAPI(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil {
			http.NotFound(w, r)
			return
		}

		run, ok, err := store.Get(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}

		var sbomRaw, provenanceRaw json.RawMessage
		if run.SBOM != "" {
			sbomRaw = json.RawMessage(run.SBOM)
		}
		if run.Provenance != "" {
			provenanceRaw = json.RawMessage(run.Provenance)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scanDetail{
			scanSummary: scanSummary{
				ID:             run.ID,
				Org:            run.Org,
				Project:        run.Project,
				CreatedAt:      run.CreatedAt.Format(rfc3339Milli),
				SeverityCounts: run.SeverityCounts(),
				Total:          len(run.Findings),
				HasSBOM:        run.SBOM != "",
				HasProvenance:  run.Provenance != "",
			},
			Findings:   run.Findings,
			SBOM:       sbomRaw,
			Provenance: provenanceRaw,
		})
	}
}

// sessionResponse describes who's logged in, for Next.js's middleware to
// use as its auth-gate check (see web/middleware.ts) and to show "logged
// in as ..." in the dashboard chrome. This endpoint is only reachable at
// all if the caller already passed whichever auth gate is active (SSO
// session or Basic Auth — see main.go's route wiring), so its own body
// only needs to carry the SSO identity when there is one; a Basic-Auth
// caller with no SSO configured is still "authenticated" by virtue of
// having reached the handler; Basic Auth doesn't carry a display name, so
// User is empty in that case.
type sessionResponse struct {
	Authenticated bool   `json:"authenticated"`
	Email         string `json:"email,omitempty"`
	Name          string `json:"name,omitempty"`
}

func handleSession() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := sessionResponse{Authenticated: true}
		if sess, ok := sessionFromContext(r.Context()); ok {
			resp.Email = sess.Email
			resp.Name = sess.Name
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// auditEventResponse is the JSON shape for one audit log entry.
type auditEventResponse struct {
	ID        int    `json:"id"`
	EventType string `json:"eventType"`
	Actor     string `json:"actor"`
	Detail    string `json:"detail"`
	CreatedAt string `json:"createdAt"`
}

func handleAuditList(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		events, err := store.AuditEvents()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		out := make([]auditEventResponse, 0, len(events))
		for _, e := range events {
			out = append(out, auditEventResponse{
				ID:        e.ID,
				EventType: e.EventType,
				Actor:     e.Actor,
				Detail:    e.Detail,
				CreatedAt: e.CreatedAt.Format(rfc3339Milli),
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	}
}

// handleComplianceReport rolls up every project's latest ingested scan
// into SOC2/PCI control coverage — see compliance.go's BuildComplianceReport
// and enterprise/DESIGN.md's Scope entry for this feature.
func handleComplianceReport(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scans, err := store.All()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(BuildComplianceReport(scans))
	}
}

const rfc3339Milli = "2006-01-02T15:04:05.000Z07:00"
