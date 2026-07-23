"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { SeverityBar } from "@/components/SeverityBar";
import { SeverityBadge } from "@/components/SeverityBadge";
import type { ScanDetail } from "@/lib/types";

export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/scans/${params.id}`)
      .then((r) => {
        if (!r.ok) {
          throw new Error(r.status === 404 ? "Scan not found" : `portal API returned ${r.status}`);
        }
        return r.json();
      })
      .then((data) => {
        if (!cancelled) setScan(data);
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [params.id]);

  if (error) {
    return (
      <section>
        <Link href="/" className="back-link">
          &larr; All scans
        </Link>
        <p className="error">{error}</p>
      </section>
    );
  }

  if (!scan) {
    return <p className="muted">Loading&hellip;</p>;
  }

  const c = scan.severityCounts;

  return (
    <section>
      <Link href="/" className="back-link">
        &larr; All scans
      </Link>
      <h1>
        Scan #{scan.id} &mdash; {scan.org} / {scan.project}
      </h1>
      <p className="lede">{new Date(scan.createdAt).toLocaleString()}</p>

      <div className="hero-spectrum">
        <SeverityBar counts={c} size="lg" />
        <div className="hero-spectrum__counts">
          <span className="count count--critical">
            <strong>{c.CRITICAL}</strong> critical
          </span>
          <span className="count count--high">
            <strong>{c.HIGH}</strong> high
          </span>
          <span className="count count--medium">
            <strong>{c.MEDIUM}</strong> medium
          </span>
          <span className="count count--low">
            <strong>{c.LOW}</strong> low
          </span>
        </div>
      </div>

      {scan.findings.length === 0 ? (
        <p className="empty">✔ No policy violations in this scan.</p>
      ) : (
        <ul className="findings">
          {scan.findings.map((f, i) => (
            <li key={i} className="findings__row">
              <div className="findings__meta">
                <code className="findings__rule">{f.RuleID}</code>
                <SeverityBadge severity={f.Severity} />
                <span className="findings__resource">{f.Resource}</span>
                <span className="findings__location">
                  {f.File}:{f.Line}
                </span>
              </div>
              <div className="findings__title">{f.Title}</div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
