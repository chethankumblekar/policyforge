// SSO adds per-user dashboard login via OIDC — implemented against the
// generic OpenID Connect spec (discovery + authorization code flow +
// ID token verification), not anything Entra-ID-specific, so it works
// with Entra ID, Google Workspace, Okta, Auth0, or any other compliant
// IdP. For Entra ID specifically: register an app in your tenant's
// Azure AD, set its redirect URI to <this portal's URL>/auth/callback,
// and configure:
//
//	OIDC_ISSUER_URL=https://login.microsoftonline.com/<tenant-id>/v2.0
//	OIDC_CLIENT_ID=<application (client) ID>
//	OIDC_CLIENT_SECRET=<a client secret from Certificates & secrets>
//	OIDC_REDIRECT_URL=https://<this portal's public URL>/auth/callback
//
// This is deliberately additive to the existing Basic Auth gate (see
// auth.go), not a replacement: /api/scans (machine/CLI ingestion) always
// stays Basic-Auth-gated regardless of whether SSO is configured, since
// that's a different actor (a CI pipeline, not a human at a browser) —
// see main.go for how the two compose. When SSO isn't configured at all
// (any of the four env vars above unset), the dashboard keeps working
// exactly as it did before this file existed, gated only by Basic Auth.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	sessionCookieName = "session"
	stateCookieName   = "oidc_state"
	sessionTTL        = 24 * time.Hour
)

// SSO wraps an OIDC provider + oauth2 client for dashboard login.
type SSO struct {
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
	store        *Store
}

// NewSSO discovers issuerURL's OIDC configuration (its
// /.well-known/openid-configuration document) and returns an SSO ready to
// mount login/callback/logout routes.
func NewSSO(ctx context.Context, store *Store, issuerURL, clientID, clientSecret, redirectURL string) (*SSO, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("discovering OIDC provider %s: %w", issuerURL, err)
	}

	return &SSO{
		oauth2Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
		store:    store,
	}, nil
}

// handleLogin starts the OIDC authorization code flow: stash a random
// state value in a short-lived cookie (checked back in handleCallback to
// guard against CSRF), then redirect to the IdP's consent/login page.
func (s *SSO) handleLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := randomString(32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     stateCookieName,
			Value:    state,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   300,
		})
		http.Redirect(w, r, s.oauth2Config.AuthCodeURL(state), http.StatusFound)
	}
}

// handleCallback completes the flow: verifies the state cookie, exchanges
// the authorization code for tokens, verifies the ID token's signature
// and claims, and creates a session the dashboard middleware will accept.
func (s *SSO) handleCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stateCookie, err := r.Cookie(stateCookieName)
		if err != nil || r.URL.Query().Get("state") != stateCookie.Value {
			http.Error(w, "invalid or missing OIDC state", http.StatusBadRequest)
			return
		}

		token, err := s.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "exchanging authorization code: "+err.Error(), http.StatusUnauthorized)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "token response had no id_token", http.StatusUnauthorized)
			return
		}
		idToken, err := s.verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			http.Error(w, "verifying id_token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		var claims struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "reading id_token claims: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if claims.Email == "" {
			http.Error(w, "id_token has no email claim", http.StatusUnauthorized)
			return
		}

		sessionID, err := randomString(32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		expiresAt := time.Now().Add(sessionTTL)
		if err := s.store.CreateSession(sessionID, claims.Email, claims.Name, expiresAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.store.AddAuditEvent("login", claims.Email, "logged in via SSO"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  expiresAt,
		})
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// handleLogout deletes the session server-side and clears the cookie.
func (s *SSO) handleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookieName); err == nil {
			if sess, ok, _ := s.store.GetSession(c.Value); ok {
				_ = s.store.AddAuditEvent("logout", sess.Email, "logged out")
			}
			_ = s.store.DeleteSession(c.Value)
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

// requireSession wraps next so its routes need a valid session — i.e.
// the dashboard, when SSO is configured. A nil *SSO makes this a no-op
// passthrough, so callers can always wrap with it unconditionally; when
// SSO isn't configured, dashboard access falls back to whatever
// basicAuth(...) already wraps it with in main.go.
// requireSession gates access with a plain 401 (not a redirect) when
// there's no valid session: every route it wraps is a JSON API endpoint
// (see main.go — GET /api/scans, /api/scans/{id}, /api/session) called by
// both the browser's own client-side fetches and the Next.js frontend's
// proxy.ts, both of which use fetch() — and fetch() auto-follows
// redirects by default. A 302 here previously meant an unauthenticated
// fetch would silently chase /login -> the IdP -> back to /auth/callback
// with no real browser session driving it, landing on a confusing final
// status that was neither a clean success nor a clean failure. Deciding
// "redirect the browser to /login" is the frontend's job now (see
// web/src/proxy.ts) — this only ever needs to answer "is this request
// authenticated," which a 401 says unambiguously.
func (s *SSO) requireSession(next http.Handler) http.Handler {
	if s == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookieName)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		sess, ok, err := s.store.GetSession(c.Value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, sess))
		next.ServeHTTP(w, r)
	})
}

type sessionContextKey struct{}

// sessionFromContext returns the logged-in session a request carries, if
// any — set by requireSession, read by handlers that want to show
// "logged in as ..." in the dashboard chrome.
func sessionFromContext(ctx context.Context) (Session, bool) {
	sess, ok := ctx.Value(sessionContextKey{}).(Session)
	return sess, ok
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random string: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
