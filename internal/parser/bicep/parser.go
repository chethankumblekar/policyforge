// Package bicep provides a native Bicep resource-block parser for
// PolicyForge — no `bicep build`/ARM compilation step, no external
// compiler dependency.
//
// Like the Terraform parser, this only captures literal top-level and
// `properties { ... }` attribute values from `resource <name> '<type>@<api
// version>' = { ... }` declarations. Attribute names are translated from
// their ARM property name (e.g. "allowBlobPublicAccess") to the same
// canonical key Terraform's azurerm provider uses (e.g.
// "allow_nested_items_to_be_public") wherever a policy rule pack depends
// on it, so the existing Azure Rego rules evaluate Bicep and Terraform
// resources identically — see armAttrKeyMap below and
// internal/normalizer's typeMap.
package bicep

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/chethankumblekar/policyforge/internal/parser"
)

// Resource is the parsed shape shared across all IaC-language parsers.
type Resource = parser.Resource

var resourceHeaderRe = regexp.MustCompile(`^\s*resource\s+[A-Za-z0-9_]+\s+'([^']+)'\s*=\s*{`)
var attrRe = regexp.MustCompile(`^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$`)
var propertiesHeaderRe = regexp.MustCompile(`^\s*properties\s*:\s*{`)

// armAttrKeyMap translates ARM property names into the canonical attribute
// keys PolicyForge's Azure Rego rule pack expects, per ARM resource type.
var armAttrKeyMap = map[string]map[string]string{
	"Microsoft.Storage/storageAccounts": {
		"allowBlobPublicAccess": "allow_nested_items_to_be_public",
		"minimumTlsVersion":     "min_tls_version",
	},
	"Microsoft.Network/networkSecurityGroups/securityRules": {
		"direction":           "direction",
		"access":              "access",
		"sourceAddressPrefix": "source_address_prefix",
	},
	"Microsoft.KeyVault/vaults": {
		"enablePurgeProtection": "purge_protection_enabled",
	},
}

// ParseDir walks dir and parses every *.bicep file it finds.
func ParseDir(dir string) ([]Resource, error) {
	var all []Resource

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".bicep") {
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

// ParseFile parses a single .bicep file into a slice of Resource blocks.
//
// This is a brace-depth scanner, like the original Terraform parser: it
// identifies `resource <name> '<type>@<version>' = {` headers, then
// captures `key: value` lines at the resource's top level AND one level
// deeper inside a nested `properties: { ... }` block (where ARM resources
// conventionally put their actual configuration).
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

		armType := m[1]
		if at := strings.Index(armType, "@"); at != -1 {
			armType = armType[:at]
		}
		keyMap := armAttrKeyMap[armType]

		r := Resource{
			Type:       armType,
			Attributes: map[string]string{},
			File:       path,
			Line:       i + 1,
		}

		depth := 1
		propertiesDepth := 0 // 0 means "not currently inside properties"
		j := i + 1
		for ; j < len(lines) && depth > 0; j++ {
			line := lines[j]

			if depth == 1 && propertiesHeaderRe.MatchString(line) {
				propertiesDepth = depth + 1
			}

			depth += strings.Count(line, "{")
			depth -= strings.Count(line, "}")

			if propertiesDepth != 0 && depth < propertiesDepth {
				propertiesDepth = 0
			}

			atTopLevel := depth == 1
			atPropertiesLevel := propertiesDepth != 0 && depth == propertiesDepth

			if !atTopLevel && !atPropertiesLevel {
				continue
			}

			am := attrRe.FindStringSubmatch(line)
			if am == nil {
				continue
			}
			key := am[1]
			val := strings.Trim(strings.TrimSpace(strings.TrimSuffix(am[2], ",")), `'`)

			if atTopLevel && key == "name" {
				r.Name = val
				continue
			}

			if mapped, ok := keyMap[key]; ok {
				r.Attributes[mapped] = val
			}
		}

		if r.Name == "" {
			r.Name = "unnamed"
		}

		resources = append(resources, r)
		i = j - 1
	}

	return resources, nil
}
