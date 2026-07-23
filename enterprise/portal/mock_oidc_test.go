package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// mockOIDCServer is a minimal OIDC identity provider for tests: it serves
// discovery, JWKS, and token-exchange endpoints, and mints real
// RS256-signed ID tokens verifiable by github.com/coreos/go-oidc — the
// same library sso.go uses to talk to a real IdP (Entra ID or otherwise).
// There's no /authorize endpoint that renders a login page, since tests
// drive the callback directly with a pre-issued code rather than
// simulating a user clicking through a real IdP's UI.
type mockOIDCServer struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	clientID string
	codes    map[string]mockClaims
}

type mockClaims struct {
	Email string
	Name  string
}

func newMockOIDCServer(t *testing.T, clientID string) *mockOIDCServer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating mock IdP key: %v", err)
	}

	m := &mockOIDCServer{key: key, clientID: clientID, codes: map[string]mockClaims{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 m.srv.URL,
			"authorization_endpoint": m.srv.URL + "/authorize",
			"token_endpoint":         m.srv.URL + "/token",
			"jwks_uri":               m.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{Key: &m.key.PublicKey, KeyID: "test-key-1", Algorithm: "RS256", Use: "sig"}
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		claims, ok := m.codes[r.FormValue("code")]
		if !ok {
			http.Error(w, "invalid or unknown code", http.StatusBadRequest)
			return
		}
		delete(m.codes, r.FormValue("code")) // codes are single-use, like a real IdP

		idToken, err := m.signIDToken(claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "mock-access-token",
			"id_token":     idToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

// issueCode registers a fresh single-use authorization code that will
// resolve to the given claims when exchanged at /token — standing in for
// a real IdP's login/consent step, which happens in a browser, not code.
func (m *mockOIDCServer) issueCode(email, name string) string {
	code := "mock-code-" + email
	m.codes[code] = mockClaims{Email: email, Name: name}
	return code
}

func (m *mockOIDCServer) signIDToken(claims mockClaims) (string, error) {
	signerOpts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key-1")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: m.key}, signerOpts)
	if err != nil {
		return "", err
	}

	now := time.Now()
	type idTokenClaims struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}

	return jwt.Signed(signer).
		Claims(jwt.Claims{
			Issuer:   m.srv.URL,
			Audience: jwt.Audience{m.clientID},
			Subject:  claims.Email,
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
		}).
		Claims(idTokenClaims{Email: claims.Email, Name: claims.Name}).
		Serialize()
}
