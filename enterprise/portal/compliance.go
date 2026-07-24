package main

// ControlMapping is one framework control and the RuleIDs whose violation
// bears on it. These are common-practice reference mappings for
// illustrating coverage (e.g. what a SOC2/PCI-minded reviewer would
// plausibly associate a rule with) — not a certified auditor crosswalk;
// see enterprise/DESIGN.md's Scope entry for this feature.
type ControlMapping struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	RuleIDs []string `json:"ruleIDs"`
}

// soc2Controls and pciControls enumerate every mapped control for each
// framework, covering PolicyForge's full current RuleID set (PF-AZ-*,
// PF-AWS-*, PF-K8S-*, see policies/). Not every rule maps to every
// framework — PF-K8S-005 (missing resource limits) has no PCI mapping,
// and that gap is shown rather than papered over.
var soc2Controls = []ControlMapping{
	{ID: "CC6.1", Title: "CC6.1 — Logical access security", RuleIDs: []string{"PF-AZ-001", "PF-AWS-001"}},
	{ID: "CC6.6", Title: "CC6.6 — Boundary protection against external threats", RuleIDs: []string{"PF-AZ-010", "PF-AWS-010", "PF-K8S-002"}},
	{ID: "CC6.7", Title: "CC6.7 — Transmission security", RuleIDs: []string{"PF-AZ-002"}},
	{ID: "CC6.8", Title: "CC6.8 — Prevents unauthorized or malicious software", RuleIDs: []string{"PF-K8S-001", "PF-K8S-003", "PF-K8S-004"}},
	{ID: "A1.2", Title: "A1.2 — Availability safeguards", RuleIDs: []string{"PF-AZ-020", "PF-K8S-005"}},
}

var pciControls = []ControlMapping{
	{ID: "1.3", Title: "PCI DSS 1.3 — Restrict traffic between network segments", RuleIDs: []string{"PF-AZ-010", "PF-AWS-010", "PF-K8S-002"}},
	{ID: "3.6", Title: "PCI DSS 3.6 — Cryptographic key management", RuleIDs: []string{"PF-AZ-020"}},
	{ID: "4.2.1", Title: "PCI DSS 4.2.1 — Strong cryptography for transmission", RuleIDs: []string{"PF-AZ-002"}},
	{ID: "7.1", Title: "PCI DSS 7.1 — Restrict access to only those with business need", RuleIDs: []string{"PF-AZ-001", "PF-AWS-001"}},
	{ID: "7.2.1", Title: "PCI DSS 7.2.1 — Least privilege", RuleIDs: []string{"PF-K8S-001", "PF-K8S-003", "PF-K8S-004"}},
}

// ProjectFailure is one (org, project)'s latest scan failing a control —
// i.e. its most recent scan has an open finding for one of the control's
// mapped RuleIDs.
type ProjectFailure struct {
	Org      string    `json:"org"`
	Project  string    `json:"project"`
	ScanID   int       `json:"scanID"`
	Findings []Finding `json:"findings"`
}

// ControlStatus is one control's coverage status across every project's
// latest scan.
type ControlStatus struct {
	ControlMapping
	FailingProjects []ProjectFailure `json:"failingProjects"`
}

// ComplianceReport is the full rollup: every mapped control for each
// framework, plus which of PolicyForge's RuleIDs aren't mapped to a given
// framework at all (so the report is upfront about its own coverage gaps
// rather than implying completeness).
type ComplianceReport struct {
	Frameworks      map[string][]ControlStatus `json:"frameworks"`
	UnmappedRuleIDs map[string][]string        `json:"unmappedRuleIDs"`
}

// allRuleIDs is every RuleID PolicyForge's rule packs currently produce
// (see policies/azure, policies/aws, policies/k8s) — kept here just to
// compute UnmappedRuleIDs; it does not gate which findings are considered,
// since BuildComplianceReport only ever looks up RuleIDs a control
// actually names.
var allRuleIDs = []string{
	"PF-AZ-001", "PF-AZ-002", "PF-AZ-010", "PF-AZ-020",
	"PF-AWS-001", "PF-AWS-010",
	"PF-K8S-001", "PF-K8S-002", "PF-K8S-003", "PF-K8S-004", "PF-K8S-005",
}

// BuildComplianceReport rolls up findings from the latest scan per (org,
// project) into SOC2/PCI control coverage. Only the most recent scan for
// each project counts — an older failing scan superseded by a clean
// rescan should no longer show as failing.
func BuildComplianceReport(scans []ScanRun) ComplianceReport {
	latest := latestScanPerProject(scans)

	report := ComplianceReport{
		Frameworks:      map[string][]ControlStatus{},
		UnmappedRuleIDs: map[string][]string{},
	}
	for name, controls := range map[string][]ControlMapping{"SOC2": soc2Controls, "PCI DSS": pciControls} {
		report.Frameworks[name] = buildControlStatuses(controls, latest)
		report.UnmappedRuleIDs[name] = unmappedRuleIDs(controls)
	}
	return report
}

// latestScanPerProject returns, for every distinct (org, project) pair
// appearing in scans, the one with the newest CreatedAt.
func latestScanPerProject(scans []ScanRun) []ScanRun {
	type key struct{ org, project string }
	latest := map[key]ScanRun{}
	for _, s := range scans {
		k := key{s.Org, s.Project}
		if existing, ok := latest[k]; !ok || s.CreatedAt.After(existing.CreatedAt) {
			latest[k] = s
		}
	}

	out := make([]ScanRun, 0, len(latest))
	for _, s := range latest {
		out = append(out, s)
	}
	return out
}

func buildControlStatuses(controls []ControlMapping, latestScans []ScanRun) []ControlStatus {
	statuses := make([]ControlStatus, 0, len(controls))
	for _, c := range controls {
		mapped := map[string]bool{}
		for _, r := range c.RuleIDs {
			mapped[r] = true
		}

		failing := []ProjectFailure{}
		for _, scan := range latestScans {
			var findings []Finding
			for _, f := range scan.Findings {
				if mapped[f.RuleID] {
					findings = append(findings, f)
				}
			}
			if len(findings) > 0 {
				failing = append(failing, ProjectFailure{
					Org:      scan.Org,
					Project:  scan.Project,
					ScanID:   scan.ID,
					Findings: findings,
				})
			}
		}

		statuses = append(statuses, ControlStatus{ControlMapping: c, FailingProjects: failing})
	}
	return statuses
}

func unmappedRuleIDs(controls []ControlMapping) []string {
	mapped := map[string]bool{}
	for _, c := range controls {
		for _, r := range c.RuleIDs {
			mapped[r] = true
		}
	}

	var out []string
	for _, r := range allRuleIDs {
		if !mapped[r] {
			out = append(out, r)
		}
	}
	return out
}
