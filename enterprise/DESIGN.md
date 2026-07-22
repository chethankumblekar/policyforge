# Enterprise module — design doc

**Status: hosting model and licensing mechanics are decided (below);
[`portal/`](portal) is now a real, self-hosted v1** — Docker/Compose
packaged, SQLite-persisted, HTTP Basic Auth-gated — not a throwaway
prototype anymore, though still short of the full Scope below (no Entra ID
SSO yet, no audit trail, no compliance mapping, no SBOM/provenance
ingestion). See `portal/README.md` for how to run it.

**Decided:**
- **Hosting model: self-hosted.** The customer runs `portal/` themselves
  (Docker Compose is the packaged path today; a Helm chart for k8s-native
  deployment is a natural fast-follow, not built yet). There is no
  PolicyForge-operated SaaS.
- **Licensing mechanics: network-gated.** There is no license-key logic in
  the CLI or the portal — access is whoever has the URL and the shared
  Basic Auth credential (`PORTAL_AUTH_USER`/`PORTAL_AUTH_PASS`). This is
  intentionally the simplest thing that could work for a self-hosted
  product; per-user accounts (Entra ID SSO, below) is the natural next
  step if/when that coarseness stops being enough.

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

## How the OSS CLI connects

The CLI already produces everything the dashboard needs as structured
JSON (`--format json`, `--sbom`, `--provenance`) — no scanning logic
duplicates into the hosted side. The integration point:

```
policyforge scan --path . --upload http://admin:secret@localhost:8090 --org acme --project infra-repo
```

`--upload` POSTs `{org, project, findings}` to `<url>/api/scans` (see
`portal/handlers.go`), authenticating with HTTP Basic Auth if the URL
carries `user:pass@` userinfo (matching `portal`'s own auth gate — see
`portal/auth.go`). This mirrors how the GitHub Action/Azure DevOps task
already run the CLI and act on its output; `--upload` is one more consumer
of the same JSON shape, not a new code path through the scanner.

**Still not real:** SBOM/provenance ingestion (only findings are posted
today), and everything past ingestion — audit trail, compliance mapping,
Entra ID SSO for per-user dashboard login (Basic Auth is one shared
credential, not accounts).

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

## Resolved

1. ~~**Hosting model**~~ — self-hosted. See portal/Dockerfile + docker-compose.yml.
2. ~~**Licensing mechanics**~~ — network-gated (shared Basic Auth credential, no license-key logic).
3. **Tech stack** — Go + `database/sql` + `modernc.org/sqlite` (pure-Go, no CGO, so the Docker image stays a single static binary) + `html/template` for the dashboard. Chosen for consistency with the OSS CLI's own stack and because a self-hosted single-binary/single-container deployment doesn't need a separate frontend framework or a heavier database to start.

## Open questions (block the next real increment)

1. **Entra ID SSO vs. staying Basic-Auth-only** — is per-user login (with real audit attribution — "who ran this scan") worth the OIDC integration + Entra app registration ownership question (multi-tenant app customers consent to, vs. each customer registering their own), or does the shared-credential model cover enough real usage first? This blocks the audit trail item in Scope, since a meaningful audit log needs to know *who*, not just *that*.
2. **Retention/data residency** — how long are ingested findings kept, and does data residency (e.g. EU-only) need to be a per-org setting? Not urgent while this is a single self-hosted SQLite file the customer already controls, but worth deciding before growing past that.
3. **SBOM/provenance ingestion** — extend `/api/scans` to accept the SBOM and provenance predicate too (not just findings), and the dashboard to show attestation status per scan.
4. **Multi-tenancy within one deployment** — today `org`/`project` are just free-text tags on a scan row, not real isolation (any Basic Auth-holder sees every org's data). Worth a real access-control model once more than one org shares a single self-hosted instance.

## Next step

Pick one of the above — Entra ID SSO is the largest lift and the one most
worth scoping carefully (OIDC flow, session storage, migrating away from
the shared Basic Auth credential without breaking existing `--upload`
scripts) before starting.
