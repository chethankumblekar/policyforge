"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { SeverityBar } from "@/components/SeverityBar";
import type { ScanSummary } from "@/lib/types";

export default function ScanListPage() {
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/scans")
      .then((r) => {
        if (!r.ok) throw new Error(`portal API returned ${r.status}`);
        return r.json();
      })
      .then((data) => {
        if (!cancelled) setScans(data);
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section>
      <h1>Scan runs</h1>
      <p className="lede">
        Every scan ingested via <code>POST /api/scans</code> (e.g.{" "}
        <code>policyforge scan --upload</code>).
      </p>

      {error && <p className="error">Couldn&rsquo;t load scans: {error}</p>}
      {!error && scans === null && <p className="muted">Loading&hellip;</p>}

      {scans?.length === 0 && (
        <p className="empty">
          No scans recorded yet. Run:
          <br />
          <code>
            policyforge scan --path . --upload http://localhost:8090 --org
            acme --project infra-repo
          </code>
        </p>
      )}

      {scans && scans.length > 0 && (
        <ul className="scan-log">
          {scans.map((s) => (
            <li key={s.id} className="scan-log__row">
              <Link href={`/scans/${s.id}`} className="scan-log__link">
                <span className="scan-log__id">#{s.id}</span>
                <span className="scan-log__meta">
                  <span className="scan-log__project">
                    {s.org} / {s.project}
                  </span>
                  <span className="scan-log__time">
                    {new Date(s.createdAt).toLocaleString()}
                  </span>
                </span>
                <SeverityBar counts={s.severityCounts} />
                <span className="scan-log__total">
                  {s.total} finding{s.total === 1 ? "" : "s"}
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
