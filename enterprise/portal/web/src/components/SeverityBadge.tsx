import type { Severity } from "@/lib/types";

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  return <span className={`badge badge--${severity.toLowerCase()}`}>{severity}</span>;
}
