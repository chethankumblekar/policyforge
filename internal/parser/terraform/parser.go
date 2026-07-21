// Package terraform provides a Terraform HCL resource-block parser for
// PolicyForge, built on the real HCL v2 AST (hashicorp/hcl/v2/hclsyntax)
// rather than regex/line scanning.
//
// Only literal attribute values are captured (strings, numbers, bools, and
// tuples/lists of those) — expressions that reference variables, other
// resources, or functions can't be resolved without a full Terraform
// evaluation context, so they're left out of the flattened attribute map.
// This matches what the policy engine actually needs: rules only inspect
// resource configuration that is a literal in the source.
package terraform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/chethankumblekar/policyforge/internal/parser"
)

// Resource is the parsed shape shared across all IaC-language parsers.
type Resource = parser.Resource

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
func ParseFile(path string) ([]Resource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	file, diags := hclsyntax.ParseConfig(data, path, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("parsing %s: %w", path, diags)
	}

	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("parsing %s: unexpected body type", path)
	}

	var resources []Resource

	for _, block := range body.Blocks {
		if block.Type != "resource" || len(block.Labels) != 2 {
			continue
		}

		r := Resource{
			Type:       block.Labels[0],
			Name:       block.Labels[1],
			Attributes: map[string]string{},
			File:       path,
			Line:       block.DefRange().Start.Line,
		}

		for name, attr := range block.Body.Attributes {
			if s, ok := literalString(attr.Expr); ok {
				r.Attributes[name] = s
			}
		}

		resources = append(resources, r)
	}

	return resources, nil
}

// literalString evaluates expr with no variables/functions available and
// renders the result as the flat string form the policy engine expects.
// Expressions that aren't resolvable to a literal (references, function
// calls, etc.) are reported as not-ok so callers can skip them.
func literalString(expr hclsyntax.Expression) (string, bool) {
	val, diags := expr.Value(nil)
	if diags.HasErrors() || !val.IsWhollyKnown() {
		return "", false
	}
	return ctyToString(val)
}

func ctyToString(val cty.Value) (string, bool) {
	if val.IsNull() {
		return "", false
	}

	t := val.Type()
	switch {
	case t == cty.String:
		return val.AsString(), true
	case t == cty.Bool:
		if val.True() {
			return "true", true
		}
		return "false", true
	case t == cty.Number:
		return val.AsBigFloat().Text('f', -1), true
	case t.IsTupleType() || t.IsListType() || t.IsSetType():
		var elems []string
		for it := val.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			s, ok := ctyToString(ev)
			if !ok {
				return "", false
			}
			elems = append(elems, fmt.Sprintf("%q", s))
		}
		return "[" + strings.Join(elems, ",") + "]", true
	default:
		return "", false
	}
}
