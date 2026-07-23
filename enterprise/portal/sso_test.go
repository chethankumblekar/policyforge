package main

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// newTestSSOServer wires a real SSO instance (backed by a mock IdP) into
// the same route layout main.go uses, so this exercises the actual
// production wiring rather than calling handlers in isolation.
func newTestSSOServer(t *testing.T) (*httptest.Server, *mockOIDCServer, *Store) {
	t.Helper()

	store := newTestStore(t)
	const clientID = "test-client-id"
	mock := newMockOIDCServer(t, clientID)

	sso, err := NewSSO(context.Background(), store, mock.srv.URL, clientID, "test-secret", "http://placeholder/auth/callback")
	if err != nil {
		t.Fatalf("NewSSO returned error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", sso.handleLogin())
	mux.HandleFunc("/auth/callback", sso.handleCallback())
	mux.HandleFunc("/logout", sso.handleLogout())
	mux.Handle("GET /api/scans", sso.requireSession(http.HandlerFunc(handleScansList(store))))
	mux.Handle("GET /api/scans/{id}", sso.requireSession(http.HandlerFunc(handleScanDetailAPI(store))))
	mux.Handle("GET /api/session", sso.requireSession(http.HandlerFunc(handleSession())))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, mock, store
}

func noRedirectClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("creating cookie jar: %v", err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// TestSSO_FullLoginFlow drives the entire OIDC dance against a real mock
// IdP: unauthenticated API access is a plain 401 (deciding to redirect a
// browser to /login is the Next.js frontend's job — see web/src/proxy.ts
// — not this JSON API's), /login redirects to the IdP with a state
// cookie, the callback (simulating the IdP's redirect back with a real
// signed ID token) creates a session, and the API is then reachable.
func TestSSO_FullLoginFlow(t *testing.T) {
	srv, mock, _ := newTestSSOServer(t)
	client := noRedirectClient(t)

	// 1. Unauthenticated API access is a plain 401.
	resp, err := client.Get(srv.URL + "/api/scans")
	if err != nil {
		t.Fatalf("GET /api/scans failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}

	// 2. /login redirects to the mock IdP's authorization endpoint and
	// sets a state cookie — the cookie jar picks it up automatically.
	loginResp, err := client.Get(srv.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login failed: %v", err)
	}
	loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from /login, got %d", loginResp.StatusCode)
	}
	authorizeURL, err := url.Parse(loginResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing authorize redirect: %v", err)
	}
	if !strings.HasPrefix(authorizeURL.String(), mock.srv.URL+"/authorize") {
		t.Fatalf("expected a redirect to the mock IdP's /authorize, got %s", authorizeURL.String())
	}
	state := authorizeURL.Query().Get("state")
	if state == "" {
		t.Fatal("expected a non-empty state parameter in the authorize URL")
	}

	// 3. Simulate the IdP's redirect back to /auth/callback with a real
	// authorization code and the same state — the cookie jar replays the
	// state cookie set in step 2 automatically.
	code := mock.issueCode("user@example.com", "Test User")
	callbackURL := srv.URL + "/auth/callback?code=" + code + "&state=" + state
	callbackResp, err := client.Get(callbackURL)
	if err != nil {
		t.Fatalf("GET /auth/callback failed: %v", err)
	}
	callbackResp.Body.Close()
	if callbackResp.StatusCode != http.StatusFound || callbackResp.Header.Get("Location") != "/" {
		t.Fatalf("expected 302 to / after a valid callback, got %d Location=%q", callbackResp.StatusCode, callbackResp.Header.Get("Location"))
	}

	// 4. The dashboard API is now reachable.
	dashResp, err := client.Get(srv.URL + "/api/scans")
	if err != nil {
		t.Fatalf("GET /api/scans failed: %v", err)
	}
	defer dashResp.Body.Close()
	if dashResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after login, got %d", dashResp.StatusCode)
	}

	// 5. Logout clears the session; the dashboard requires login again.
	logoutResp, err := client.Get(srv.URL + "/logout")
	if err != nil {
		t.Fatalf("GET /logout failed: %v", err)
	}
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusFound || logoutResp.Header.Get("Location") != "/login" {
		t.Fatalf("expected 302 to /login after logout, got %d", logoutResp.StatusCode)
	}

	afterLogoutResp, err := client.Get(srv.URL + "/api/scans")
	if err != nil {
		t.Fatalf("GET /api/scans failed: %v", err)
	}
	afterLogoutResp.Body.Close()
	if afterLogoutResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d", afterLogoutResp.StatusCode)
	}
}

func TestSSO_CallbackRejectsMismatchedState(t *testing.T) {
	srv, mock, _ := newTestSSOServer(t)
	client := noRedirectClient(t)

	loginResp, err := client.Get(srv.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login failed: %v", err)
	}
	loginResp.Body.Close()

	code := mock.issueCode("user@example.com", "Test User")
	// Wrong state entirely — the cookie jar still carries the real state
	// cookie from /login, but the query parameter here doesn't match it.
	resp, err := client.Get(srv.URL + "/auth/callback?code=" + code + "&state=wrong-state")
	if err != nil {
		t.Fatalf("GET /auth/callback failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for mismatched state, got %d", resp.StatusCode)
	}
}

func TestSSO_CallbackRejectsMissingStateCookie(t *testing.T) {
	srv, mock, _ := newTestSSOServer(t)
	client := noRedirectClient(t)

	// Skip /login entirely, so there's no state cookie at all.
	code := mock.issueCode("user@example.com", "Test User")
	resp, err := client.Get(srv.URL + "/auth/callback?code=" + code + "&state=anything")
	if err != nil {
		t.Fatalf("GET /auth/callback failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 with no state cookie, got %d", resp.StatusCode)
	}
}

func TestSSO_CallbackRejectsInvalidCode(t *testing.T) {
	srv, _, _ := newTestSSOServer(t)
	client := noRedirectClient(t)

	loginResp, err := client.Get(srv.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login failed: %v", err)
	}
	loginResp.Body.Close()
	authorizeURL, _ := url.Parse(loginResp.Header.Get("Location"))
	state := authorizeURL.Query().Get("state")

	resp, err := client.Get(srv.URL + "/auth/callback?code=never-issued&state=" + state)
	if err != nil {
		t.Fatalf("GET /auth/callback failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for an invalid/unknown code, got %d", resp.StatusCode)
	}
}

func TestSSO_CallbackRejectsTokenWithNoEmailClaim(t *testing.T) {
	srv, mock, _ := newTestSSOServer(t)
	client := noRedirectClient(t)

	loginResp, _ := client.Get(srv.URL + "/login")
	loginResp.Body.Close()
	authorizeURL, _ := url.Parse(loginResp.Header.Get("Location"))
	state := authorizeURL.Query().Get("state")

	code := mock.issueCode("", "No Email User")
	resp, err := client.Get(srv.URL + "/auth/callback?code=" + code + "&state=" + state)
	if err != nil {
		t.Fatalf("GET /auth/callback failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for an id_token with no email claim, got %d", resp.StatusCode)
	}
}

func TestSSO_RequireSessionIsNoOpWhenNil(t *testing.T) {
	var sso *SSO
	called := false
	handler := sso.requireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if !called {
		t.Error("expected a nil *SSO's requireSession to pass through to next unconditionally")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestSSO_RequireSessionRejectsExpiredSession(t *testing.T) {
	srv, mock, store := newTestSSOServer(t)
	client := noRedirectClient(t)

	loginResp, _ := client.Get(srv.URL + "/login")
	loginResp.Body.Close()
	authorizeURL, _ := url.Parse(loginResp.Header.Get("Location"))
	state := authorizeURL.Query().Get("state")

	code := mock.issueCode("user@example.com", "Test User")
	callbackResp, err := client.Get(srv.URL + "/auth/callback?code=" + code + "&state=" + state)
	if err != nil {
		t.Fatalf("GET /auth/callback failed: %v", err)
	}
	callbackResp.Body.Close()

	// Force every session this store knows about to have already expired.
	all, err := store.db.Query(`SELECT id FROM sessions`)
	if err != nil {
		t.Fatalf("querying sessions: %v", err)
	}
	var ids []string
	for all.Next() {
		var id string
		all.Scan(&id)
		ids = append(ids, id)
	}
	all.Close()
	for _, id := range ids {
		if _, err := store.db.Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, "2000-01-01T00:00:00Z", id); err != nil {
			t.Fatalf("expiring session: %v", err)
		}
	}

	resp, err := client.Get(srv.URL + "/api/scans")
	if err != nil {
		t.Fatalf("GET /api/scans failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected an expired session to be treated as logged out (401), got %d", resp.StatusCode)
	}
}
