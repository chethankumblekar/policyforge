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
};

export type ScanDetail = ScanSummary & {
  findings: Finding[];
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
