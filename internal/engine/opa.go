//go:build opa
// +build opa

// This file implements the Phase 1 milestone: real OPA/Rego evaluation,
// replacing the native Go checks in engine.go with actual .rego policy
// files loaded from policies/.
//
// IT IS NOT WIRED IN BY DEFAULT (behind the "opa" build tag) because this
// sandbox environment cannot fetch github.com/open-policy-agent/opa's
// transitive dependencies (golang.org/x/sys is not reachable here).
//
// To activate this on your own machine, with full internet access:
//
//   go get github.com/open-policy-agent/opa/rego@v0.70.0
//   go build -tags opa ./...
//
// Then swap the call in cmd/policyforge/main.go from engine.Evaluate to
// engine.EvaluateOPA, and delete the "opa" build tag once you're ready
// to make this the default path (remove the native evaluateNative rules
// in engine.go at that point, or keep them as a fallback).
package engine

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"

	"github.com/chethankumblekar/policyforge/internal/normalizer"
)

// EvaluateOPA runs every resource through the .rego rule packs under
// policyDir (e.g. "policies/azure/cis-foundations"), collecting any
// `deny[msg]` results as findings.
//
// Unlike evaluateNative, rule content lives entirely in .rego files —
// adding a new check means adding a new deny rule, no Go code changes.
func EvaluateOPA(ctx context.Context, policyDir string, resources []normalizer.Resource) ([]Finding, error) {
	query, err := rego.New(
		rego.Query("data.policyforge.azure.cis_foundations.deny"),
		rego.Load([]string{policyDir}, nil),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("preparing rego query: %w", err)
	}

	var findings []Finding

	for _, r := range resources {
		input := map[string]interface{}{
			"type":       r.Type,
			"name":       r.Name,
			"attributes": r.Attributes,
		}

		results, err := query.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			return nil, fmt.Errorf("evaluating resource %s: %w", r.Name, err)
		}

		for _, result := range results {
			for _, expr := range result.Expressions {
				msgs, ok := expr.Value.([]interface{})
				if !ok {
					continue
				}
				for _, m := range msgs {
					msg, _ := m.(string)
					findings = append(findings, Finding{
						RuleID:      ruleIDFromMessage(msg),
						Title:       msg,
						Severity:    SeverityHigh, // TODO: derive from rule metadata once rule packs carry severity annotations
						Resource:    r.Name,
						File:        r.Source.File,
						Line:        r.Source.Line,
						Description: msg,
					})
				}
			}
		}
	}

	return findings, nil
}

// ruleIDFromMessage extracts the "PF-AZ-001"-style prefix that rule packs
// are expected to include at the start of their deny message.
func ruleIDFromMessage(msg string) string {
	for i, c := range msg {
		if c == ':' {
			return msg[:i]
		}
	}
	return "UNKNOWN"
}
