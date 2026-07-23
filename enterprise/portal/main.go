// Command portal is a self-hosted PolicyForge enterprise dashboard: an
// ingestion API (POST /api/scans) plus a small dashboard UI, backed by a
// local SQLite file. See ../DESIGN.md for the full scope and the
// decisions this v1 makes concrete: self-hosted (you run this yourself —
// there is no PolicyForge-operated SaaS), and API access is
// network-gated (whoever has the URL and the shared Basic Auth
// credential below). The dashboard itself can optionally require real
// per-user login via OIDC/Entra ID SSO — see sso.go — falling back to the
// same Basic Auth credential when SSO isn't configured.
package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

//go:embed templates/*.html
var templateFS embed.FS

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

	dashboard := http.NewServeMux()
	dashboard.HandleFunc("/", handleIndex(store))
	dashboard.HandleFunc("/scans/", handleScanDetail(store))

	mux := http.NewServeMux()
	mux.Handle("/api/scans", basicAuth(*authUser, *authPass, http.HandlerFunc(handleIngest(store))))

	if sso != nil {
		mux.HandleFunc("/login", sso.handleLogin())
		mux.HandleFunc("/auth/callback", sso.handleCallback())
		mux.HandleFunc("/logout", sso.handleLogout())
		mux.Handle("/", sso.requireSession(dashboard))
	} else {
		mux.Handle("/", basicAuth(*authUser, *authPass, dashboard))
	}

	fmt.Printf("PolicyForge portal listening on http://localhost%s (data: %s)\n", *addr, *dbPath)
	if *authUser == "" || *authPass == "" {
		warning := "WARNING: no --auth-user/--auth-pass set — /api/scans is open to anyone who can reach this address"
		if sso == nil {
			warning += ", and so is the dashboard (SSO isn't configured either)"
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
