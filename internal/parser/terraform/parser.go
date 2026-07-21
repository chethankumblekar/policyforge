// Package terraform provides a minimal Terraform HCL resource-block
// parser for PolicyForge v0.1.
//
// This is intentionally a lightweight, dependency-free scanner (regex-based
// block extraction) so the CLI is runnable end-to-end without a network
// fetch for hashicorp/hcl. The Phase 1 milestone (see docs/roadmap) swaps
// this out for a real HCL AST parser once the module is vendored.
package terraform

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Resource represents a single parsed Terraform resource block.
type Resource struct {
	Type       string            // e.g. "azurerm_storage_account"
	Name       string            // e.g. "example"
	Attributes map[string]string // flattened top-level key/value pairs
	File       string            // source file path
	Line       int               // starting line number, for SARIF locations
}

var resourceHeaderRe = regexp.MustCompile(`^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*{`)
var attrRe = regexp.MustCompile(`^\s*([a-zA-Z0-9_]+)\s*=\s*(.+?)\s*$`)

// ParseDir walks dir and parses every *.tf file it finds.
func ParseDir(dir string) ([]Resource, error) {
	var all []Resource

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".tf") {
			return nil
		}
		resources, ferr := ParseFile(path)
		if ferr != nil {
			return ferr
		}
		all = append(all, resources...)
		return nil
	})

	return all, err
}

// ParseFile parses a single .tf file into a slice of Resource blocks.
//
// This is a naive brace-depth scanner: it identifies `resource "type" "name" {`
// headers, then captures top-level `key = value` lines until the matching
// closing brace. Nested blocks (e.g. network_rules { ... }) are skipped for
// attribute extraction in v0.1, but still counted for brace depth so parsing
// doesn't break.
func ParseFile(path string) ([]Resource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var resources []Resource

	for i := 0; i < len(lines); i++ {
		m := resourceHeaderRe.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}

		r := Resource{
			Type:       m[1],
			Name:       m[2],
			Attributes: map[string]string{},
			File:       path,
			Line:       i + 1,
		}

		depth := 1
		j := i + 1
		for ; j < len(lines) && depth > 0; j++ {
			line := lines[j]
			depth += strings.Count(line, "{")
			depth -= strings.Count(line, "}")

			// Only capture attributes at the resource's top level (depth == 1
			// means we're still inside the resource block, not a nested one).
			if depth == 1 {
				if am := attrRe.FindStringSubmatch(line); am != nil {
					key := am[1]
					val := strings.Trim(am[2], `"`)
					r.Attributes[key] = val
				}
			}
		}

		resources = append(resources, r)
		i = j - 1
	}

	return resources, nil
}
