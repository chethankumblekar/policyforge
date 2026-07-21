// Package sbom generates a minimal software-bill-of-materials document
// describing the infrastructure resources discovered during a scan.
//
// v0.1 emits a small Syft-compatible JSON shape covering the resources
// PolicyForge itself parsed. This is intentionally scoped down for now —
// Phase 3 wires in real artifact/container SBOM generation and
// Sigstore/cosign signing per the project plan.
package sbom

import (
	"encoding/json"
	"time"

	"github.com/chethankumblekar/policyforge/internal/normalizer"
)

// Document is a minimal SBOM shape, loosely compatible with Syft's
// artifact list so downstream tooling (e.g. Grype) can consume it.
type Document struct {
	SchemaVersion string     `json:"schemaVersion"`
	GeneratedAt   string     `json:"generatedAt"`
	Source        string     `json:"source"`
	Artifacts     []Artifact `json:"artifacts"`
}

// Artifact represents one infrastructure resource as a "component" in
// the SBOM, analogous to a package entry in a software SBOM.
type Artifact struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Provider string `json:"provider"`
	Location string `json:"location"`
}

// Generate builds an SBOM Document from the normalized resource set.
func Generate(resources []normalizer.Resource) Document {
	doc := Document{
		SchemaVersion: "policyforge-sbom/0.1",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Source:        "policyforge scan",
	}

	for _, r := range resources {
		doc.Artifacts = append(doc.Artifacts, Artifact{
			Name:     r.Name,
			Type:     r.Type,
			Provider: r.Provider,
			Location: r.Source.File,
		})
	}

	return doc
}

// ToJSON renders a Document as indented JSON.
func ToJSON(doc Document) string {
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}
