// Package provenance builds a SLSA v0.2 provenance predicate describing a
// PolicyForge scan run — what was scanned (materials, as a content
// digest), what invoked it (parameters), and when. The predicate is meant
// to be handed to `cosign attest-blob --type slsaprovenance` (see
// internal/signer), which wraps it in a signed in-toto attestation; this
// package only builds the predicate body itself; no dependency on
// Sigstore or any signing library.
package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sort"
	"time"
)

// BuilderID identifies PolicyForge itself as the entity that produced the
// scan (the SLSA "builder").
const BuilderID = "https://github.com/chethankumblekar/policyforge"

// BuildType identifies what kind of build/process produced the subject
// artifact this provenance is attached to.
const BuildType = "https://github.com/chethankumblekar/policyforge/scan@v1"

// Predicate is a SLSA v0.2 provenance predicate
// (https://slsa.dev/spec/v0.2/provenance).
type Predicate struct {
	Builder    Builder    `json:"builder"`
	BuildType  string     `json:"buildType"`
	Invocation Invocation `json:"invocation"`
	Metadata   Metadata   `json:"metadata"`
	Materials  []Material `json:"materials"`
}

type Builder struct {
	ID string `json:"id"`
}

type Invocation struct {
	Parameters map[string]string `json:"parameters"`
}

type Metadata struct {
	BuildStartedOn  string `json:"buildStartedOn"`
	BuildFinishedOn string `json:"buildFinishedOn"`
}

type Material struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

// Generate builds a Predicate for a scan that ran with the given
// parameters (e.g. {"path": ..., "format": ..., "policyDir": ...}) over
// materialFiles (the IaC files that were actually parsed), started at
// startedOn and finished at finishedOn.
//
// materialFiles is deduplicated and sorted so the output is deterministic
// regardless of parse order.
func Generate(params map[string]string, materialFiles []string, startedOn, finishedOn time.Time) (Predicate, error) {
	unique := make(map[string]struct{}, len(materialFiles))
	for _, f := range materialFiles {
		unique[f] = struct{}{}
	}
	sorted := make([]string, 0, len(unique))
	for f := range unique {
		sorted = append(sorted, f)
	}
	sort.Strings(sorted)

	materials := make([]Material, 0, len(sorted))
	for _, f := range sorted {
		digest, err := sha256File(f)
		if err != nil {
			return Predicate{}, err
		}
		materials = append(materials, Material{
			URI:    "file://" + f,
			Digest: map[string]string{"sha256": digest},
		})
	}

	return Predicate{
		Builder:   Builder{ID: BuilderID},
		BuildType: BuildType,
		Invocation: Invocation{
			Parameters: params,
		},
		Metadata: Metadata{
			BuildStartedOn:  startedOn.UTC().Format(time.RFC3339),
			BuildFinishedOn: finishedOn.UTC().Format(time.RFC3339),
		},
		Materials: materials,
	}, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ToJSON renders a Predicate as indented JSON.
func ToJSON(p Predicate) (string, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
