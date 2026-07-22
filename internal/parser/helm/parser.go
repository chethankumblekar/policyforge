// Package helm renders Helm charts via a locally installed `helm` binary
// (`helm template`) and parses the result with the same logic
// internal/parser/k8s already uses for plain manifests.
//
// Rendering Helm's own templating engine (Go text/template + Sprig +
// chart/subchart value merging) natively rather than shelling out was
// considered and rejected: Helm's engine package pulls in the full
// Kubernetes client-go/apimachinery stack as a transitive dependency even
// for pure offline template rendering — dozens of packages, wildly
// disproportionate for a CLI that otherwise has none of that. Shelling
// out mirrors internal/signer's use of a separately-installed `cosign`
// binary rather than vendoring Sigstore's client libraries.
package helm

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/chethankumblekar/policyforge/internal/parser"
	"github.com/chethankumblekar/policyforge/internal/parser/k8s"
)

// Resource is the parsed shape shared across all IaC-language parsers.
type Resource = parser.Resource

// ErrHelmNotInstalled is wrapped into the error ParseChart/ParseDir
// return when the `helm` binary isn't on PATH. Callers (see
// cmd/policyforge's parseAll) can check for it with errors.Is to treat a
// missing tool as a skippable warning rather than a fatal scan error —
// unlike Terraform/Bicep/Kubernetes, which never need an external binary,
// so an error from those always indicates genuinely malformed input.
var ErrHelmNotInstalled = errors.New("helm not found on PATH")

// ParseDir walks dir looking for Helm chart roots — any directory
// containing a Chart.yaml — and renders + parses each one found. A
// chart's own subdirectories (including any subcharts under charts/) are
// not descended into as separate top-level charts, since `helm template`
// already renders subcharts as part of their parent.
func ParseDir(dir string) ([]Resource, error) {
	var all []Resource

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if _, statErr := os.Stat(filepath.Join(path, "Chart.yaml")); statErr != nil {
			return nil
		}

		resources, perr := ParseChart(path)
		if perr != nil {
			return perr
		}
		all = append(all, resources...)
		return filepath.SkipDir
	})

	return all, err
}

// ParseChart renders a single Helm chart directory via `helm template`
// and parses the rendered Kubernetes manifests, attributing each
// resource back to the actual template file it came from (using the
// `# Source: <chart>/templates/...` comments helm emits per document) —
// not just the chart directory as a whole.
func ParseChart(chartDir string) ([]Resource, error) {
	if _, err := exec.LookPath("helm"); err != nil {
		return nil, fmt.Errorf("%w — install it from https://helm.sh/docs/intro/install/ to scan Helm charts", ErrHelmNotInstalled)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command("helm", "template", chartDir)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("helm template %s: %w: %s", chartDir, err, strings.TrimSpace(stderr.String()))
	}

	var resources []Resource
	for _, doc := range splitBySource(stdout.String(), chartDir) {
		if strings.TrimSpace(doc.content) == "" {
			continue
		}
		docResources, err := k8s.ParseReader(strings.NewReader(doc.content), doc.file)
		if err != nil {
			return nil, fmt.Errorf("parsing rendered chart %s (%s): %w", chartDir, doc.file, err)
		}
		resources = append(resources, docResources...)
	}

	return resources, nil
}

type sourcedDoc struct {
	file    string
	content string
}

// splitBySource splits `helm template`'s combined stdout into one group
// per `# Source: <path>` comment, translating helm's reported path (which
// starts with the chart's Chart.yaml `name`, not necessarily the chart's
// actual directory name) into a real path under chartDir by keeping only
// the portion after that first path segment.
func splitBySource(rendered, chartDir string) []sourcedDoc {
	var docs []sourcedDoc
	var current strings.Builder
	currentFile := chartDir

	flush := func() {
		// A "---" document separator (with no other content) commonly
		// precedes the very first "# Source:" comment; skip emitting an
		// empty group for it rather than passing meaningless content
		// downstream.
		if strings.Trim(current.String(), "-\n \t") != "" {
			docs = append(docs, sourcedDoc{file: currentFile, content: current.String()})
		}
		current.Reset()
	}

	for _, line := range strings.Split(rendered, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "# Source: "); ok {
			flush()
			currentFile = resolveSourcePath(chartDir, rest)
			continue
		}
		current.WriteString(line)
		current.WriteString("\n")
	}
	flush()

	return docs
}

// resolveSourcePath turns a helm "# Source:" value (e.g.
// "mychart/templates/deployment.yaml") into a real filesystem path under
// chartDir, by discarding only its first path segment (the chart name)
// rather than assuming that name matches chartDir's own base name.
func resolveSourcePath(chartDir, sourceValue string) string {
	sourceValue = filepath.ToSlash(sourceValue)
	if idx := strings.Index(sourceValue, "/"); idx != -1 {
		return filepath.Join(chartDir, sourceValue[idx+1:])
	}
	return filepath.Join(chartDir, sourceValue)
}
