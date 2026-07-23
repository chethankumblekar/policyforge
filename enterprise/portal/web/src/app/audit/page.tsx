"use client";

import { useEffect, useState } from "react";
import type { AuditEvent } from "@/lib/types";

export default function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/audit")
      .then((r) => {
        if (!r.ok) throw new Error(`portal API returned ${r.status}`);
        return r.json();
      })
      .then((data) => {
        if (!cancelled) setEvents(data);
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
      <h1>Audit log</h1>
      <p className="lede">
        Every scan ingested and every dashboard login/logout, most recent
        first — an immutable record for compliance evidence.
      </p>

      {error && <p className="error">Couldn&rsquo;t load the audit log: {error}</p>}
      {!error && events === null && <p className="muted">Loading&hellip;</p>}

      {events?.length === 0 && (
        <p className="empty">No audit events recorded yet.</p>
      )}

      {events && events.length > 0 && (
        <ul className="findings">
          {events.map((e) => (
            <li key={e.id} className="findings__row">
              <div className="findings__meta">
                <code className="findings__rule">{e.eventType}</code>
                <span className="findings__resource">{e.actor}</span>
                <span className="findings__location">
                  {new Date(e.createdAt).toLocaleString()}
                </span>
              </div>
              <div className="findings__title">{e.detail}</div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
