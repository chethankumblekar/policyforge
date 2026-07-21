// Real OPA/Rego evaluation, replacing the v0.1 native Go checks. Rule
// packs live entirely as .rego files under policies/ (embedded into the
// binary via policies.FS, see policies/embed.go) — adding a new check
// means adding a new deny rule, no Go code changes.
package engine

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	"github.com/open-policy-agent/opa/rego"

	"github.com/chethankumblekar/policyforge/internal/normalizer"
	"github.com/chethankumblekar/policyforge/policies"
)

// EvaluateOPA runs every resource through every .rego rule pack embedded
// under policies/, collecting `deny[msg]` results as findings. Rule packs
// are discovered purely by walking whatever data.policyforge tree the
// loaded modules produce, so adding a new package under policies/ (e.g.
// policies/aws/core) needs no changes here.
func EvaluateOPA(ctx context.Context, resources []normalizer.Resource) ([]Finding, error) {
	modules, err := loadModules(policies.FS)
	if err != nil {
		return nil, fmt.Errorf("loading policy modules: %w", err)
	}

	opts := append([]func(*rego.Rego){rego.Query("data.policyforge")}, modules...)
	query, err := rego.New(opts...).PrepareForEval(ctx)
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
				findings = append(findings, collectFindings(expr.Value, r)...)
			}
		}
	}

	return findings, nil
}

// loadModules reads every .rego file out of fsys and returns them as
// rego.Module options, so the caller can load an embed.FS the same way
// rego.Load would read from disk.
func loadModules(fsys fs.FS) ([]func(*rego.Rego), error) {
	var opts []func(*rego.Rego)

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}
		content, rerr := fs.ReadFile(fsys, path)
		if rerr != nil {
			return rerr
		}
		opts = append(opts, rego.Module(path, string(content)))
		return nil
	})

	return opts, err
}

// collectFindings walks a data.policyforge result node looking for
// "deny"/"severity" pairs at any depth, since rule packs can nest under
// arbitrary provider/pack-name namespaces (policyforge.azure.cis_foundations,
// policyforge.aws.core, ...).
func collectFindings(node interface{}, r normalizer.Resource) []Finding {
	obj, ok := node.(map[string]interface{})
	if !ok {
		return nil
	}

	var findings []Finding

	if denyRaw, ok := obj["deny"].([]interface{}); ok {
		sevMap, _ := obj["severity"].(map[string]interface{})
		for _, m := range denyRaw {
			msg, _ := m.(string)
			ruleID := ruleIDFromMessage(msg)
			findings = append(findings, Finding{
				RuleID:      ruleID,
				Title:       titleFromMessage(msg),
				Severity:    severityFor(sevMap, ruleID),
				Resource:    r.Name,
				File:        r.Source.File,
				Line:        r.Source.Line,
				Description: msg,
			})
		}
	}

	for key, child := range obj {
		if key == "deny" || key == "severity" {
			continue
		}
		findings = append(findings, collectFindings(child, r)...)
	}

	return findings
}

// severityFor looks up a rule ID's severity from a package's severity
// object, defaulting to HIGH if the rule pack didn't declare one.
func severityFor(sevMap map[string]interface{}, ruleID string) Severity {
	if sevMap != nil {
		if s, ok := sevMap[ruleID].(string); ok {
			return Severity(s)
		}
	}
	return SeverityHigh
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

// titleFromMessage strips the "PF-AZ-001: " rule-ID prefix a deny message
// is expected to lead with, since the table/SARIF output already lists
// the rule ID in its own column.
func titleFromMessage(msg string) string {
	for i, c := range msg {
		if c == ':' {
			return strings.TrimSpace(msg[i+1:])
		}
	}
	return msg
}
