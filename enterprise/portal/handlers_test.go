package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func mustAdd(t *testing.T, store *Store, org, project string, findings []Finding) ScanRun {
	t.Helper()
	run, err := store.Add(org, project, findings)
	if err != nil {
		t.Fatalf("store.Add returned error: %v", err)
	}
	return run
}

// newAPIMux wires the same route layout main.go does (minus SSO, which
// sso_test.go covers separately), for tests that want the real mux
// dispatch (method-based routing, path values) rather than calling
// handlers directly.
func newAPIMux(store *Store, authUser, authPass string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /api/scans", basicAuth(authUser, authPass, http.HandlerFunc(handleIngest(store))))
	mux.Handle("GET /api/scans", basicAuth(authUser, authPass, http.HandlerFunc(handleScansList(store))))
	mux.Handle("GET /api/scans/{id}", basicAuth(authUser, authPass, http.HandlerFunc(handleScanDetailAPI(store))))
	mux.Handle("GET /api/session", basicAuth(authUser, authPass, http.HandlerFunc(handleSession())))
	mux.Handle("GET /api/audit", basicAuth(authUser, authPass, http.HandlerFunc(handleAuditList(store))))
	return mux
}

func TestHandleIngest_ValidRequestStoresAndReturnsID(t *testing.T) {
	store := newTestStore(t)
	body := `{"org":"acme","project":"infra-repo","findings":[{"RuleID":"PF-AZ-001","Severity":"HIGH"}]}`

	req := httptest.NewRequest(http.MethodPost, "/api/scans", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleIngest(store)(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ingestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if resp.ID != 1 || resp.URL != "/scans/1" {
		t.Errorf("expected id=1 url=/scans/1, got %+v", resp)
	}

	run, ok, err := store.Get(1)
	if err != nil {
		t.Fatalf("store.Get returned error: %v", err)
	}
	if !ok || len(run.Findings) != 1 {
		t.Fatalf("expected the finding to be stored, got %+v", run)
	}
}

func TestHandleIngest_MissingOrgOrProjectRejected(t *testing.T) {
	store := newTestStore(t)
	body := `{"org":"","project":"infra-repo","findings":[]}`

	req := httptest.NewRequest(http.MethodPost, "/api/scans", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleIngest(store)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandleIngest_InvalidJSONRejected(t *testing.T) {
	store := newTestStore(t)
	req := httptest.NewRequest(http.MethodPost, "/api/scans", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	handleIngest(store)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandleIngest_WrongMethodRejected(t *testing.T) {
	store := newTestStore(t)
	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	rec := httptest.NewRecorder()
	handleIngest(store)(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestHandleIngest_RecordsAuditEvent(t *testing.T) {
	store := newTestStore(t)
	body := `{"org":"acme","project":"infra-repo","findings":[{"RuleID":"PF-AZ-001","Severity":"HIGH"}]}`

	req := httptest.NewRequest(http.MethodPost, "/api/scans", strings.NewReader(body))
	req.SetBasicAuth("ci-pipeline", "secret")
	rec := httptest.NewRecorder()
	handleIngest(store)(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	events, err := store.AuditEvents()
	if err != nil {
		t.Fatalf("AuditEvents returned error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].EventType != "scan_ingested" || events[0].Actor != "ci-pipeline" {
		t.Errorf("expected event_type=scan_ingested actor=ci-pipeline, got %+v", events[0])
	}
}

func TestHandleIngest_NoCredentialsRecordsAnonymousActor(t *testing.T) {
	store := newTestStore(t)
	body := `{"org":"acme","project":"infra-repo","findings":[]}`

	req := httptest.NewRequest(http.MethodPost, "/api/scans", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleIngest(store)(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	events, err := store.AuditEvents()
	if err != nil {
		t.Fatalf("AuditEvents returned error: %v", err)
	}
	if len(events) != 1 || events[0].Actor != "anonymous" {
		t.Fatalf("expected 1 audit event with actor=anonymous, got %+v", events)
	}
}

func TestHandleIngest_StoresSBOMAndProvenance(t *testing.T) {
	store := newTestStore(t)
	body := `{"org":"acme","project":"infra-repo","findings":[],` +
		`"sbom":{"schemaVersion":"policyforge-sbom/0.1","artifacts":[]},` +
		`"provenance":{"buildType":"https://example/scan@v1"}}`

	req := httptest.NewRequest(http.MethodPost, "/api/scans", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleIngest(store)(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	run, ok, err := store.Get(1)
	if err != nil {
		t.Fatalf("store.Get returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected to find the ingested scan")
	}
	if run.SBOM == "" {
		t.Error("expected the SBOM to be stored")
	}
	if run.Provenance == "" {
		t.Error("expected the provenance predicate to be stored")
	}
}

func TestHandleIngest_WithoutSBOMOrProvenanceLeavesThemEmpty(t *testing.T) {
	store := newTestStore(t)
	body := `{"org":"acme","project":"infra-repo","findings":[]}`

	req := httptest.NewRequest(http.MethodPost, "/api/scans", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleIngest(store)(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	run, _, err := store.Get(1)
	if err != nil {
		t.Fatalf("store.Get returned error: %v", err)
	}
	if run.SBOM != "" || run.Provenance != "" {
		t.Errorf("expected no SBOM/provenance stored, got SBOM=%q Provenance=%q", run.SBOM, run.Provenance)
	}
}

func TestHandleScansList_ReportsHasSBOMAndHasProvenance(t *testing.T) {
	store := newTestStore(t)
	run := mustAdd(t, store, "acme", "infra-repo", nil)
	if err := store.SetArtifacts(run.ID, `{"schemaVersion":"policyforge-sbom/0.1"}`, ""); err != nil {
		t.Fatalf("SetArtifacts returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	rec := httptest.NewRecorder()
	handleScansList(store)(rec, req)

	var scans []scanSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &scans); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(scans) != 1 {
		t.Fatalf("expected 1 scan, got %d", len(scans))
	}
	if !scans[0].HasSBOM {
		t.Error("expected hasSBOM=true")
	}
	if scans[0].HasProvenance {
		t.Error("expected hasProvenance=false")
	}
}

func TestHandleScanDetailAPI_IncludesSBOMAndProvenanceWhenPresent(t *testing.T) {
	store := newTestStore(t)
	run := mustAdd(t, store, "acme", "infra-repo", nil)
	if err := store.SetArtifacts(run.ID, `{"schemaVersion":"policyforge-sbom/0.1"}`, `{"buildType":"x"}`); err != nil {
		t.Fatalf("SetArtifacts returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/scans/1", nil)
	req.SetPathValue("id", "1")
	rec := httptest.NewRecorder()
	handleScanDetailAPI(store)(rec, req)

	var detail scanDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(detail.SBOM) == 0 {
		t.Error("expected a non-empty sbom field")
	}
	if len(detail.Provenance) == 0 {
		t.Error("expected a non-empty provenance field")
	}
	if !detail.HasSBOM || !detail.HasProvenance {
		t.Errorf("expected hasSBOM and hasProvenance both true, got %+v", detail.scanSummary)
	}
}

func TestHandleScanDetailAPI_OmitsSBOMAndProvenanceWhenAbsent(t *testing.T) {
	store := newTestStore(t)
	mustAdd(t, store, "acme", "infra-repo", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/scans/1", nil)
	req.SetPathValue("id", "1")
	rec := httptest.NewRecorder()
	handleScanDetailAPI(store)(rec, req)

	var raw map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if _, ok := raw["sbom"]; ok {
		t.Errorf("expected no \"sbom\" key when absent, got %+v", raw)
	}
	if _, ok := raw["provenance"]; ok {
		t.Errorf("expected no \"provenance\" key when absent, got %+v", raw)
	}
}

func TestHandleAuditList_ReturnsEvents(t *testing.T) {
	store := newTestStore(t)
	if err := store.AddAuditEvent("login", "user@example.com", "logged in via SSO"); err != nil {
		t.Fatalf("AddAuditEvent returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	rec := httptest.NewRecorder()
	handleAuditList(store)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var events []auditEventResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(events) != 1 || events[0].EventType != "login" || events[0].Actor != "user@example.com" {
		t.Errorf("expected 1 login event for user@example.com, got %+v", events)
	}
}

func TestHandleAuditList_EmptyReturnsEmptyArrayNotNull(t *testing.T) {
	store := newTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	rec := httptest.NewRecorder()
	handleAuditList(store)(rec, req)

	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("expected an empty JSON array \"[]\", got %q", rec.Body.String())
	}
}

func TestHandleScansList_ReturnsSummaries(t *testing.T) {
	store := newTestStore(t)
	mustAdd(t, store, "acme", "infra-repo", []Finding{
		{RuleID: "PF-AZ-001", Severity: "HIGH"},
		{RuleID: "PF-AZ-010", Severity: "CRITICAL"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	rec := httptest.NewRecorder()
	handleScansList(store)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var scans []scanSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &scans); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(scans) != 1 {
		t.Fatalf("expected 1 scan, got %d", len(scans))
	}
	if scans[0].Org != "acme" || scans[0].Project != "infra-repo" {
		t.Errorf("expected org=acme project=infra-repo, got %+v", scans[0])
	}
	if scans[0].Total != 2 {
		t.Errorf("expected total=2, got %d", scans[0].Total)
	}
	if scans[0].SeverityCounts["CRITICAL"] != 1 || scans[0].SeverityCounts["HIGH"] != 1 {
		t.Errorf("expected severity counts CRITICAL=1 HIGH=1, got %+v", scans[0].SeverityCounts)
	}
}

func TestHandleScansList_EmptyReturnsEmptyArrayNotNull(t *testing.T) {
	store := newTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	rec := httptest.NewRecorder()
	handleScansList(store)(rec, req)

	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("expected an empty JSON array \"[]\" (so frontend code can always .map() it), got %q", rec.Body.String())
	}
}

func TestHandleScanDetailAPI_ReturnsFindings(t *testing.T) {
	store := newTestStore(t)
	mustAdd(t, store, "acme", "infra-repo", []Finding{
		{RuleID: "PF-AZ-001", Severity: "HIGH", Title: "public access", Resource: "example", File: "main.tf", Line: 3},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/scans/1", nil)
	req.SetPathValue("id", "1")
	rec := httptest.NewRecorder()
	handleScanDetailAPI(store)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var detail scanDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(detail.Findings) != 1 || detail.Findings[0].RuleID != "PF-AZ-001" {
		t.Errorf("expected 1 finding PF-AZ-001, got %+v", detail.Findings)
	}
}

func TestHandleScanDetailAPI_UnknownIDIs404(t *testing.T) {
	store := newTestStore(t)
	req := httptest.NewRequest(http.MethodGet, "/api/scans/999", nil)
	req.SetPathValue("id", "999")
	rec := httptest.NewRecorder()
	handleScanDetailAPI(store)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestHandleScanDetailAPI_NonNumericIDIs404(t *testing.T) {
	store := newTestStore(t)
	req := httptest.NewRequest(http.MethodGet, "/api/scans/abc", nil)
	req.SetPathValue("id", "abc")
	rec := httptest.NewRecorder()
	handleScanDetailAPI(store)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestHandleSession_ReportsAuthenticated(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	rec := httptest.NewRecorder()
	handleSession()(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp sessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if !resp.Authenticated {
		t.Error("expected authenticated=true (reaching this handler already implies the caller passed the auth gate)")
	}
}

// TestFullServer_EndToEnd wires the real mux (as main() does, minus SSO)
// and drives it with an actual httptest.Server, exercising
// ingest -> list -> detail as a genuine HTTP round trip.
func TestFullServer_EndToEnd(t *testing.T) {
	store := newTestStore(t)
	mux := newAPIMux(store, "", "")
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ingestBody, _ := json.Marshal(ingestRequest{
		Org:     "acme",
		Project: "infra-repo",
		Findings: []Finding{
			{RuleID: "PF-AZ-010", Severity: "CRITICAL", Title: "unrestricted inbound"},
		},
	})
	resp, err := http.Post(srv.URL+"/api/scans", "application/json", bytes.NewReader(ingestBody))
	if err != nil {
		t.Fatalf("POST /api/scans failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var ingested ingestResponse
	json.NewDecoder(resp.Body).Decode(&ingested)
	resp.Body.Close()

	listResp, err := http.Get(srv.URL + "/api/scans")
	if err != nil {
		t.Fatalf("GET /api/scans failed: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", listResp.StatusCode)
	}

	detailResp, err := http.Get(srv.URL + "/api/scans/1")
	if err != nil {
		t.Fatalf("GET /api/scans/1 failed: %v", err)
	}
	defer detailResp.Body.Close()
	if detailResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", detailResp.StatusCode)
	}
}

func TestFullServer_BasicAuth(t *testing.T) {
	store := newTestStore(t)
	mux := newAPIMux(store, "admin", "secret")

	srv := httptest.NewServer(mux)
	defer srv.Close()

	noAuthResp, err := http.Get(srv.URL + "/api/scans")
	if err != nil {
		t.Fatalf("GET /api/scans failed: %v", err)
	}
	noAuthResp.Body.Close()
	if noAuthResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 with no credentials, got %d", noAuthResp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/scans", nil)
	req.SetBasicAuth("admin", "wrong-password")
	wrongResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/scans failed: %v", err)
	}
	wrongResp.Body.Close()
	if wrongResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong credentials, got %d", wrongResp.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/scans", nil)
	req2.SetBasicAuth("admin", "secret")
	okResp, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("GET /api/scans failed: %v", err)
	}
	okResp.Body.Close()
	if okResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with correct credentials, got %d", okResp.StatusCode)
	}
}

func TestBasicAuth_DisabledWhenCredentialsEmpty(t *testing.T) {
	store := newTestStore(t)
	mux := newAPIMux(store, "", "")

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/scans")
	if err != nil {
		t.Fatalf("GET /api/scans failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with auth disabled (empty user/pass), got %d", resp.StatusCode)
	}
}
