# Enterprise module — design doc

**Status: planning only. Nothing in this document is built.** This is a
scope/architecture sketch to align on before any hosted code gets
written — see "Open questions" at the end for the decisions that block
starting implementation.

## What this is

A separately licensed, hosted add-on for teams running the open-source
PolicyForge CLI across many repos/pipelines who want a central place to
see results, enforce org-wide policy, and produce an audit trail. The OSS
core (scanner, rule packs, CI/CD integrations) stays fully open source and
fully useful without this module — the enterprise tier is additive
visibility/governance on top, not a gate on core scanning functionality.

## Scope

- **Hosted dashboard** — aggregate scan results (findings, SBOM,
  provenance/attestation status) across every repo/pipeline that runs
  `policyforge scan`, with trend views and drill-down to individual
  findings.
- **Entra ID SSO** — organization login for the dashboard itself (not
  related to the CLI's use of `DefaultAzureCredential` for drift
  detection, which is a separate, already-shipped OSS feature).
- **Org-wide policy management** — push a shared custom Rego policy set
  (see the OSS `--policy-dir` mechanism) to every team's CLI invocations
  centrally, instead of each repo vendoring its own.
- **Audit trail** — an immutable log of scan runs, findings, policy
  changes, and who/what triggered them, for compliance evidence.
- **Compliance framework mapping** — roll up rule-level findings (already
  tagged with e.g. "CIS Azure Foundations 3.6") into SOC2/PCI control
  coverage reports.

## How the OSS CLI would connect (sketch)

The CLI already produces everything the dashboard needs as structured
JSON (`--format json`, `--sbom`, `--provenance`) — no scanning logic
duplicates into the hosted side. The integration point is additive:

```
policyforge scan --path . --format json --upload \
  --org-token $POLICYFORGE_ORG_TOKEN
```

`--upload` would POST the scan's JSON findings (+ SBOM/provenance, if
generated) to the hosted ingestion API, authenticated by a per-org token
(rotatable, scoped to write-only ingestion — never a credential capable of
reading other orgs' data). This mirrors how the GitHub Action/Azure
DevOps task already run the CLI and act on its output; `--upload` is one
more consumer of the same JSON shape, not a new code path through the
scanner.

## Sketch data model

```
Organization
  └─ Project (maps to a repo/pipeline)
       └─ ScanRun (one `policyforge scan` invocation)
            ├─ Finding[]        (RuleID, Severity, Resource, File, Line — same shape as engine.Finding)
            ├─ SBOM             (if --sbom was used)
            ├─ ProvenancePredicate (if --provenance was used)
            └─ AttestationRef   (if the artifact was cosign-attested; store the bundle location, not re-verify it server-side unless asked)
AuditEvent (org-scoped: scan ingested, policy pushed, user login, ...)
CompliancePack (a named rollup of RuleIDs -> a framework's control IDs, e.g. "SOC2" -> {PF-AZ-001: CC6.1, ...})
```

## Non-goals (stays out of scope for this module)

- Re-implementing scanning, parsing, or policy evaluation server-side —
  the CLI remains the only place a scan actually runs. The hosted side is
  a viewer/aggregator over CLI output, not a second scanner.
- Storing or brokering Azure/AWS credentials on the user's behalf. Drift
  detection's `DefaultAzureCredential` flow stays entirely client-side in
  the OSS CLI.
- Replacing GitHub code scanning / Azure DevOps' own result surfaces —
  this is a cross-repo rollup for teams who've outgrown per-repo SARIF
  uploads, not a replacement for them.

## Open questions (block starting implementation)

1. **Hosting model** — self-hosted (a Docker Compose/Helm chart the
   customer runs) vs. a fully hosted SaaS PolicyForge operates? This
   changes almost every architecture decision below it (multi-tenancy
   model, auth, data residency).
2. **Licensing mechanics** — how is "enterprise tier" actually gated?
   License key checked by the CLI's `--upload` flag, or purely by
   whether the customer has network access to a hosted/self-hosted
   ingestion endpoint they've paid for?
3. **Tech stack** — no framework has been chosen yet; this doc
   deliberately avoids prescribing one before the hosting model (#1) is
   decided, since that choice constrains it (e.g. a self-hosted option
   favors a single deployable binary/container over a multi-service
   architecture).
4. **Entra ID app registration ownership** — does PolicyForge run one
   multi-tenant app registration customers consent to, or does each
   customer register their own single-tenant app? Affects the SSO
   integration code and onboarding flow.
5. **Retention/data residency** — how long are ingested findings kept,
   and does data residency (e.g. EU-only) need to be a per-org setting
   from day one?

## Next step

Once #1 and #2 above are answered, this doc should be extended with a
concrete tech stack, API contract for `--upload`, and a first-milestone
scope (likely: ingestion API + a read-only dashboard, before SSO/audit
trail/compliance mapping).
