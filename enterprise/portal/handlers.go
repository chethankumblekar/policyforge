package main

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"
)

var tmpl = template.Must(template.New("").Funcs(template.FuncMap{
	"lower": strings.ToLower,
}).ParseFS(templateFS, "templates/*.html"))

// render executes contentTemplate into a buffer first, then wraps the
// result in the shared page chrome ("base"). Content templates are
// rendered in their own ExecuteTemplate call (rather than base.html
// including them by a fixed name) because html/template merges every
// parsed file into one shared namespace — a `{{define "content"}}` block
// per page would collide, with whichever file parses last silently
// winning for every page.
func render(w http.ResponseWriter, title, contentTemplate string, data interface{}) error {
	var body bytes.Buffer
	if err := tmpl.ExecuteTemplate(&body, contentTemplate, data); err != nil {
		return err
	}

	return tmpl.ExecuteTemplate(w, "base", struct {
		Title string
		Body  template.HTML
	}{Title: title, Body: template.HTML(body.String())})
}

// ingestRequest is the JSON body /api/scans accepts: the same Finding
// shape internal/engine.ToJSON already produces, plus org/project so the
// portal can group scans by where they came from.
type ingestRequest struct {
	Org      string    `json:"org"`
	Project  string    `json:"project"`
	Findings []Finding `json:"findings"`
}

type ingestResponse struct {
	ID  int    `json:"id"`
	URL string `json:"url"`
}

func handleIngest(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ingestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Org == "" || req.Project == "" {
			http.Error(w, "\"org\" and \"project\" are required", http.StatusBadRequest)
			return
		}

		run, err := store.Add(req.Org, req.Project, req.Findings)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(ingestResponse{
			ID:  run.ID,
			URL: "/scans/" + strconv.Itoa(run.ID),
		})
	}
}

func handleIndex(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		scans, err := store.All()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := struct {
			Scans []ScanRun
		}{
			Scans: scans,
		}

		if err := render(w, "Scan runs", "index-content", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func handleScanDetail(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := strings.TrimPrefix(r.URL.Path, "/scans/")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		run, ok, err := store.Get(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}

		data := struct {
			Scan   ScanRun
			Counts map[string]int
		}{
			Scan:   run,
			Counts: run.SeverityCounts(),
		}

		if err := render(w, "Scan #"+idStr, "scan-content", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
