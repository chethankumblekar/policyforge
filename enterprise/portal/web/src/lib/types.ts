// Mirrors the JSON shapes enterprise/portal/handlers.go's API produces —
// see scanSummary/scanDetail/Finding in that file.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type SeverityCounts = Record<Severity, number>;

export type Finding = {
  RuleID: string;
  Title: string;
  Severity: Severity;
  Resource: string;
  File: string;
  Line: number;
  Description: string;
};

export type ScanSummary = {
  id: number;
  org: string;
  project: string;
  createdAt: string;
  severityCounts: SeverityCounts;
  total: number;
  hasSBOM: boolean;
  hasProvenance: boolean;
};

// sbom/provenance are the CLI's own JSON output (internal/sbom.Document,
// internal/provenance.Predicate) verbatim — the portal never parses their
// fields, so they're typed as unknown here too and just rendered as-is.
export type ScanDetail = ScanSummary & {
  findings: Finding[];
  sbom?: unknown;
  provenance?: unknown;
};

export type SessionInfo = {
  authenticated: boolean;
  email?: string;
  name?: string;
};

export type AuditEvent = {
  id: number;
  eventType: string;
  actor: string;
  detail: string;
  createdAt: string;
};

// Mirrors enterprise/portal/compliance.go's ControlMapping/ControlStatus/
// ComplianceReport. Control mappings are common-practice reference
// mappings for illustrating rule coverage, not a certified crosswalk.
export type ControlMapping = {
  id: string;
  title: string;
  ruleIDs: string[];
};

export type ProjectFailure = {
  org: string;
  project: string;
  scanID: number;
  findings: Finding[];
};

export type ControlStatus = ControlMapping & {
  failingProjects: ProjectFailure[];
};

export type ComplianceReport = {
  frameworks: Record<string, ControlStatus[]>;
  unmappedRuleIDs: Record<string, string[]>;
};
