// Command portal is a self-hosted PolicyForge enterprise dashboard: an
// ingestion API (POST /api/scans) plus a small dashboard UI, backed by a
// local SQLite file. See ../DESIGN.md for the full scope and the
// decisions this v1 makes concrete: self-hosted (you run this yourself —
// there is no PolicyForge-operated SaaS), and access is network-gated
// (whoever has the URL and the shared credential below) rather than
// per-user Entra ID SSO, which remains a fast-follow, not built here.
package main

import (
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
	flag.Parse()

	store, err := NewStore(*dbPath)
	if err != nil {
		log.Fatalf("opening store: %v", err)
	}
	defer store.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex(store))
	mux.HandleFunc("/scans/", handleScanDetail(store))
	mux.HandleFunc("/api/scans", handleIngest(store))

	handler := basicAuth(*authUser, *authPass, mux)

	fmt.Printf("PolicyForge portal listening on http://localhost%s (data: %s)\n", *addr, *dbPath)
	if *authUser == "" || *authPass == "" {
		fmt.Println("WARNING: no --auth-user/--auth-pass set — the dashboard and ingestion API are open to anyone who can reach this address.")
	}
	log.Fatal(http.ListenAndServe(*addr, handler))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
