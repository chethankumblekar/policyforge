"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import type { SessionInfo } from "@/lib/types";

export function Header() {
  const [session, setSession] = useState<SessionInfo | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/session")
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!cancelled) setSession(data);
      })
      .catch(() => {
        if (!cancelled) setSession(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const displayName = session?.name || session?.email;

  return (
    <header className="topbar">
      <span className="brand-mark">POLICYFORGE</span>
      <span className="brand-sub">self-hosted portal</span>
      <nav className="topnav">
        <Link href="/">Scan runs</Link>
        <Link href="/audit">Audit log</Link>
        <Link href="/compliance">Compliance</Link>
        {displayName && (
          <>
            <span className="topnav-user">{displayName}</span>
            <a href="/logout">Logout</a>
          </>
        )}
      </nav>
    </header>
  );
}
