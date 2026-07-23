// Command portal is a self-hosted PolicyForge enterprise API: an
// ingestion endpoint (POST /api/scans) plus read endpoints the Next.js
// dashboard (see web/) renders from, backed by a local SQLite file. See
// ../DESIGN.md for the full scope and the decisions this v1 makes
// concrete: self-hosted (you run this yourself — there is no
// PolicyForge-operated SaaS), and API access is network-gated (whoever
// has the URL and the shared Basic Auth credential below). The dashboard
// itself can optionally require real per-user login via OIDC/Entra ID
// SSO — see sso.go — falling back to the same Basic Auth credential when
// SSO isn't configured.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := flag.String("addr", ":8090", "address to listen on")
	dbPath := flag.String("db", envOr("PORTAL_DB_PATH", "portal.db"), "path to the SQLite database file (env PORTAL_DB_PATH)")
	authUser := flag.String("auth-user", os.Getenv("PORTAL_AUTH_USER"), "username for HTTP Basic Auth (env PORTAL_AUTH_USER); leave both user and pass empty to disable auth")
	authPass := flag.String("auth-pass", os.Getenv("PORTAL_AUTH_PASS"), "password for HTTP Basic Auth (env PORTAL_AUTH_PASS)")
	oidcIssuer := flag.String("oidc-issuer-url", os.Getenv("OIDC_ISSUER_URL"), "OIDC issuer URL for dashboard SSO (env OIDC_ISSUER_URL), e.g. https://login.microsoftonline.com/<tenant-id>/v2.0 for Entra ID")
	oidcClientID := flag.String("oidc-client-id", os.Getenv("OIDC_CLIENT_ID"), "OIDC client ID (env OIDC_CLIENT_ID)")
	oidcClientSecret := flag.String("oidc-client-secret", os.Getenv("OIDC_CLIENT_SECRET"), "OIDC client secret (env OIDC_CLIENT_SECRET)")
	oidcRedirectURL := flag.String("oidc-redirect-url", os.Getenv("OIDC_REDIRECT_URL"), "OIDC redirect URL, e.g. http://localhost:8090/auth/callback (env OIDC_REDIRECT_URL)")
	flag.Parse()

	store, err := NewStore(*dbPath)
	if err != nil {
		log.Fatalf("opening store: %v", err)
	}
	defer store.Close()

	var sso *SSO
	if *oidcIssuer != "" || *oidcClientID != "" || *oidcClientSecret != "" || *oidcRedirectURL != "" {
		if *oidcIssuer == "" || *oidcClientID == "" || *oidcClientSecret == "" || *oidcRedirectURL == "" {
			log.Fatal("OIDC SSO is partially configured — oidc-issuer-url, oidc-client-id, oidc-client-secret, and oidc-redirect-url must all be set together")
		}
		sso, err = NewSSO(context.Background(), store, *oidcIssuer, *oidcClientID, *oidcClientSecret, *oidcRedirectURL)
		if err != nil {
			log.Fatalf("configuring OIDC SSO: %v", err)
		}
	}

	// dashboardAuth gates the read API the Next.js frontend calls: an SSO
	// session if configured, otherwise the same shared Basic Auth
	// credential /api/scans (ingestion) always uses.
	dashboardAuth := func(h http.Handler) http.Handler {
		if sso != nil {
			return sso.requireSession(h)
		}
		return basicAuth(*authUser, *authPass, h)
	}

	mux := http.NewServeMux()
	mux.Handle("POST /api/scans", basicAuth(*authUser, *authPass, http.HandlerFunc(handleIngest(store))))
	mux.Handle("GET /api/scans", dashboardAuth(http.HandlerFunc(handleScansList(store))))
	mux.Handle("GET /api/scans/{id}", dashboardAuth(http.HandlerFunc(handleScanDetailAPI(store))))
	mux.Handle("GET /api/session", dashboardAuth(http.HandlerFunc(handleSession())))

	if sso != nil {
		mux.HandleFunc("/login", sso.handleLogin())
		mux.HandleFunc("/auth/callback", sso.handleCallback())
		mux.HandleFunc("/logout", sso.handleLogout())
	}

	fmt.Printf("PolicyForge portal API listening on http://localhost%s (data: %s)\n", *addr, *dbPath)
	fmt.Println("Run the Next.js dashboard in web/ to browse it (see web/README.md).")
	if *authUser == "" || *authPass == "" {
		warning := "WARNING: no --auth-user/--auth-pass set — /api/scans is open to anyone who can reach this address"
		if sso == nil {
			warning += ", and so is every read endpoint the dashboard calls (SSO isn't configured either)"
		}
		fmt.Println(warning)
	}
	if sso != nil {
		fmt.Println("Dashboard SSO enabled — login required at /login.")
	}
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
