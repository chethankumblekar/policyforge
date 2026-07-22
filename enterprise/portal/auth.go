package main

import (
	"crypto/subtle"
	"net/http"
)

// basicAuth wraps next with HTTP Basic Auth, checked against user/pass
// using constant-time comparison to avoid leaking credential-length/match
// timing. This is the whole auth story for now: a single shared
// credential, matching the "network-gated" access model decided for the
// self-hosted enterprise portal — not per-user accounts or Entra ID SSO
// (that's a real fast-follow, not implemented here). If user or pass is
// empty, auth is disabled entirely (the local-dev/prototype default) —
// operators exposing this beyond localhost must set both.
func basicAuth(user, pass string, next http.Handler) http.Handler {
	if user == "" || pass == "" {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, ok := r.BasicAuth()
		if !ok || !constantTimeEqual(gotUser, user) || !constantTimeEqual(gotPass, pass) {
			w.Header().Set("WWW-Authenticate", `Basic realm="PolicyForge Portal"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
