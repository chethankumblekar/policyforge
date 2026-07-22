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

// TestHandleIndex_RendersIndexContentNotScanContent is a regression test
// for a real bug: html/template.ParseFS merges every file into one
// namespace, so if index.html and scan.html both defined a block named
// "content", whichever file parsed last silently won for every page —
// the scan list page would render the scan-detail template instead. The
// fix names each page's block uniquely (index-content/scan-content) and
// renders explicitly by name (see render() in handlers.go).
func TestHandleIndex_RendersIndexContentNotScanContent(t *testing.T) {
	store := newTestStore(t)
	mustAdd(t, store, "acme", "infra-repo", []Finding{{RuleID: "PF-AZ-001", Severity: "HIGH", Title: "public access"}})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handleIndex(store)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Scan runs") {
		t.Errorf("expected the index page heading \"Scan runs\", got:\n%s", body)
	}
	if !strings.Contains(body, "acme / infra-repo") {
		t.Errorf("expected the scan list row, got:\n%s", body)
	}
	if strings.Contains(body, "All scans") {
		t.Errorf("index page rendered scan-detail content (the back-link \"All scans\") instead of its own — template block collision regressed:\n%s", body)
	}
}

func TestHandleIndex_UnknownPathIs404(t *testing.T) {
	store := newTestStore(t)
	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	rec := httptest.NewRecorder()
	handleIndex(store)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestHandleIndex_EmptyStateMessage(t *testing.T) {
	store := newTestStore(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handleIndex(store)(rec, req)

	if !strings.Contains(rec.Body.String(), "No scans ingested yet") {
		t.Errorf("expected the empty-state message, got:\n%s", rec.Body.String())
	}
}

func TestHandleScanDetail_RendersFindingsAndCounts(t *testing.T) {
	store := newTestStore(t)
	mustAdd(t, store, "acme", "infra-repo", []Finding{
		{RuleID: "PF-AZ-001", Severity: "HIGH", Title: "public access", Resource: "example", File: "main.tf", Line: 3},
	})

	req := httptest.NewRequest(http.MethodGet, "/scans/1", nil)
	rec := httptest.NewRecorder()
	handleScanDetail(store)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"PF-AZ-001", "public access", "main.tf:3", "All scans", "acme / infra-repo"} {
		if !strings.Contains(body, want) {
			t.Errorf("expected scan detail page to contain %q, got:\n%s", want, body)
		}
	}
}

func TestHandleScanDetail_UnknownIDIs404(t *testing.T) {
	store := newTestStore(t)
	req := httptest.NewRequest(http.MethodGet, "/scans/999", nil)
	rec := httptest.NewRecorder()
	handleScanDetail(store)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestHandleScanDetail_NonNumericIDIs404(t *testing.T) {
	store := newTestStore(t)
	req := httptest.NewRequest(http.MethodGet, "/scans/abc", nil)
	rec := httptest.NewRecorder()
	handleScanDetail(store)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestHandleScanDetail_CleanScanShowsNoViolationsMessage(t *testing.T) {
	store := newTestStore(t)
	mustAdd(t, store, "acme", "infra-repo", nil)

	req := httptest.NewRequest(http.MethodGet, "/scans/1", nil)
	rec := httptest.NewRecorder()
	handleScanDetail(store)(rec, req)

	if !strings.Contains(rec.Body.String(), "No policy violations") {
		t.Errorf("expected the clean-scan message, got:\n%s", rec.Body.String())
	}
}

// TestFullServer_EndToEnd wires the real mux (as main() does) and drives
// it with an actual httptest.Server, exercising ingest -> list -> detail
// as a genuine HTTP round trip rather than calling handlers directly.
func TestFullServer_EndToEnd(t *testing.T) {
	store := newTestStore(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex(store))
	mux.HandleFunc("/scans/", handleScanDetail(store))
	mux.HandleFunc("/api/scans", handleIngest(store))

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

	listResp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", listResp.StatusCode)
	}

	detailResp, err := http.Get(srv.URL + ingested.URL)
	if err != nil {
		t.Fatalf("GET %s failed: %v", ingested.URL, err)
	}
	defer detailResp.Body.Close()
	if detailResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", detailResp.StatusCode)
	}
}

// TestFullServer_BasicAuth verifies the auth middleware actually protects
// the real mux end to end: no credentials → 401, wrong credentials → 401,
// correct credentials → 200.
func TestFullServer_BasicAuth(t *testing.T) {
	store := newTestStore(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex(store))
	handler := basicAuth("admin", "secret", mux)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	noAuthResp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	noAuthResp.Body.Close()
	if noAuthResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 with no credentials, got %d", noAuthResp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.SetBasicAuth("admin", "wrong-password")
	wrongResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	wrongResp.Body.Close()
	if wrongResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong credentials, got %d", wrongResp.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req2.SetBasicAuth("admin", "secret")
	okResp, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	okResp.Body.Close()
	if okResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with correct credentials, got %d", okResp.StatusCode)
	}
}

func TestBasicAuth_DisabledWhenCredentialsEmpty(t *testing.T) {
	store := newTestStore(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex(store))

	srv := httptest.NewServer(basicAuth("", "", mux))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with auth disabled (empty user/pass), got %d", resp.StatusCode)
	}
}
