import type { Severity, SeverityCounts } from "@/lib/types";

const ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/**
 * The one signature visual element of the dashboard: a segmented,
 * proportional bar reading critical -> low, like a heat readout of how
 * dangerous a scan is. Ties back to the "temper colors" palette (steel
 * visibly glows hotter the more heat goes into it) and — unlike a
 * decorative stat-tile grid — actually encodes the real severity
 * distribution, at both list-row and hero scale.
 */
export function SeverityBar({
  counts,
  size = "sm",
}: {
  counts: SeverityCounts;
  size?: "sm" | "lg";
}) {
  const total = ORDER.reduce((sum, k) => sum + counts[k], 0);

  if (total === 0) {
    return <div className={`severity-bar severity-bar--${size} severity-bar--empty`} />;
  }

  return (
    <div className={`severity-bar severity-bar--${size}`}>
      {ORDER.map((k) => {
        const pct = (counts[k] / total) * 100;
        if (pct === 0) return null;
        return (
          <div
            key={k}
            className={`severity-bar__segment severity-bar__segment--${k.toLowerCase()}`}
            style={{ width: `${pct}%` }}
            title={`${k}: ${counts[k]}`}
          />
        );
      })}
    </div>
  );
}
