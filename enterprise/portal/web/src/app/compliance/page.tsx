"use client";

import { useEffect, useState } from "react";
import { SeverityBadge } from "@/components/SeverityBadge";
import type { ComplianceReport, ControlStatus } from "@/lib/types";

const FRAMEWORK_ORDER = ["SOC2", "PCI DSS"];

export default function CompliancePage() {
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/compliance")
      .then((r) => {
        if (!r.ok) throw new Error(`portal API returned ${r.status}`);
        return r.json();
      })
      .then((data) => {
        if (!cancelled) setReport(data);
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return (
      <section>
        <h1>Compliance</h1>
        <p className="error">Couldn&rsquo;t load the compliance report: {error}</p>
      </section>
    );
  }

  if (!report) {
    return <p className="muted">Loading&hellip;</p>;
  }

  return (
    <section>
      <h1>Compliance</h1>
      <p className="lede">
        Rule-level findings rolled up into SOC2/PCI control coverage,
        computed from each project&rsquo;s latest ingested scan. These are
        common-practice reference mappings for illustrating coverage, not a
        certified auditor crosswalk.
      </p>

      {FRAMEWORK_ORDER.map((name) => {
        const controls = report.frameworks[name] ?? [];
        const unmapped = report.unmappedRuleIDs[name] ?? [];
        return (
          <div key={name} className="compliance-framework">
            <h2 className="compliance-framework__title">{name}</h2>
            <ul className="findings">
              {controls.map((c) => (
                <ControlRow key={c.id} control={c} />
              ))}
            </ul>
            {unmapped.length > 0 && (
              <p className="muted compliance-framework__unmapped">
                Not mapped to {name}: {unmapped.join(", ")}
              </p>
            )}
          </div>
        );
      })}
    </section>
  );
}

function ControlRow({ control }: { control: ControlStatus }) {
  const failing = control.failingProjects.length;

  return (
    <li className="findings__row">
      <div className="findings__meta">
        <code className="findings__rule">{control.id}</code>
        <span
          className={`compliance-status compliance-status--${failing > 0 ? "fail" : "pass"}`}
        >
          {failing > 0
            ? `${failing} project${failing === 1 ? "" : "s"} with open findings`
            : "No open findings"}
        </span>
        <span className="findings__location">{control.ruleIDs.join(", ")}</span>
      </div>
      <div className="findings__title">{control.title}</div>

      {failing > 0 && (
        <details className="compliance-details">
          <summary>
            {failing} failing project{failing === 1 ? "" : "s"}
          </summary>
          <ul className="findings">
            {control.failingProjects.map((p) => (
              <li key={`${p.org}/${p.project}`} className="findings__row">
                <div className="findings__meta">
                  <span className="findings__resource">
                    {p.org}/{p.project}
                  </span>
                  <span className="findings__location">scan #{p.scanID}</span>
                </div>
                {p.findings.map((f, i) => (
                  <div key={i} className="findings__title">
                    <SeverityBadge severity={f.Severity} /> {f.RuleID} &mdash;{" "}
                    {f.Resource} ({f.File}:{f.Line})
                  </div>
                ))}
              </li>
            ))}
          </ul>
        </details>
      )}
    </li>
  );
}
