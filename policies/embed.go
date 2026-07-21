// Package policies embeds the Rego rule packs into the compiled binary so
// `policyforge` runs against its full policy set regardless of the working
// directory it's invoked from (e.g. after `go install ...@latest`, where no
// checkout of this repository is present alongside the binary).
package policies

import "embed"

//go:embed azure aws
var FS embed.FS
