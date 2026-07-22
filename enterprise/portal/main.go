// Command portal is a local, in-memory prototype of the PolicyForge
// enterprise dashboard sketched in ../DESIGN.md. It is NOT the real
// enterprise product — no auth, no persistence, no multi-tenant
// isolation, no license gating. It exists so the ingestion API shape and
// dashboard UX can be seen running end to end with the OSS CLI before any
// of the open architecture questions in DESIGN.md are settled.
package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"net/http"
)

//go:embed templates/*.html
var templateFS embed.FS

func main() {
	addr := flag.String("addr", ":8090", "address to listen on")
	flag.Parse()

	store := NewStore()

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex(store))
	mux.HandleFunc("/scans/", handleScanDetail(store))
	mux.HandleFunc("/api/scans", handleIngest(store))

	fmt.Printf("PolicyForge portal (prototype) listening on http://localhost%s\n", *addr)
	fmt.Println("This is a local, in-memory demo — see enterprise/DESIGN.md for the real architecture plan.")
	log.Fatal(http.ListenAndServe(*addr, mux))
}
