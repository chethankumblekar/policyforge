# Enterprise module — design doc

**Status: hosting model and licensing mechanics are decided (below);
[`portal/`](portal) is a real, self-hosted v1** — Docker/Compose packaged,
SQLite-persisted, HTTP Basic Auth for API/machine access, real per-user
dashboard login via OIDC SSO (Entra ID or any other compliant IdP), a
proper Next.js dashboard UI (`portal/web`), an audit trail of scan
ingestion + logins/logouts, and SBOM/provenance ingestion — not a
throwaway prototype anymore, though still short of the full Scope below
(no compliance framework mapping). See `portal/README.md` for how to run
it and configure SSO.

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
  findings. **Built** (scan list + drill-down + SBOM/provenance status;
  trend views are not) — `portal/web`, a Next.js frontend calling the Go
  API for everything, with a distinctive design system (see
  `portal/web/README.md`) rather than a generic dashboard template. A
  scan ingested with `--sbom`/`--provenance` shows `SBOM`/`Provenance`
  tags in the scan list and an expandable raw-JSON viewer on the scan
  detail page — the portal stores and displays both as opaque JSON (see
  `ScanRun`'s doc comment in `portal/store.go`), never parsing their
  fields, since it's a viewer over what the CLI already produced.
- **Entra ID SSO** — organization login for the dashboard itself (not
  related to the CLI's use of `DefaultAzureCredential` for drift
  detection, which is a separate, already-shipped OSS feature). **Built**
  — see `portal/sso.go`: a generic OIDC client (discovery + authorization
  code flow + ID token verification via `coreos/go-oidc`), so it works
  with Entra ID or any other compliant IdP, configured via
  `OIDC_ISSUER_URL`/`OIDC_CLIENT_ID`/`OIDC_CLIENT_SECRET`/`OIDC_REDIRECT_URL`.
  Sessions persist in the same SQLite file as scans. Verified against a
  real mock IdP (signed/verified JWTs, full authorization-code round
  trip) since no real Entra ID tenant was available to test against —
  the OIDC spec compliance is what makes that substitution valid; pointing
  `OIDC_ISSUER_URL` at `https://login.microsoftonline.com/<tenant-id>/v2.0`
  with a real Entra app registration's client ID/secret is the only
  remaining step, and hasn't itself been exercised.
- **Org-wide policy management** — push a shared custom Rego policy set
  (see the OSS `--policy-dir` mechanism) to every team's CLI invocations
  centrally, instead of each repo vendoring its own.
- **Audit trail** — an immutable log of scan runs and who/what triggered
  them, for compliance evidence. **Built** — see `portal/store.go`'s
  `audit_events` table and the `GET /api/audit` endpoint (`portal/web`'s
  "Audit log" page): every `POST /api/scans` ingestion (actor = the
  Basic Auth username, or `anonymous` if auth is disabled) and every SSO
  login/logout (actor = the session's email) is recorded. Policy-change
  events aren't recorded yet, since there's no server-side policy
  management to log changes to (see "Org-wide policy management" below,
  still unbuilt).
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

`--upload` POSTs `{org, project, findings, sbom?, provenance?}` to
`<url>/api/scans` (see `portal/handlers.go`) — the last two only present
if the same `policyforge scan` invocation also passed `--sbom`/
`--provenance` (see `uploadFindings` in `cmd/policyforge/main.go`) —
authenticating with HTTP Basic Auth if the URL carries `user:pass@`
userinfo (matching `portal`'s own auth gate — see `portal/auth.go`). This
mirrors how the GitHub Action/Azure DevOps task already run the CLI and
act on its output; `--upload` is one more consumer of the same JSON
shape, not a new code path through the scanner.

**Still not real:** compliance mapping (see "Open questions" below).
`/api/scans` itself stays Basic-Auth-gated even with SSO configured
(that's still the CLI/CI-pipeline path, not a human at a browser).

## Sketch data model

```
Organization
  └─ Project (maps to a repo/pipeline)
       └─ ScanRun (one `policyforge scan` invocation)
            ├─ Finding[]        (RuleID, Severity, Resource, File, Line — same shape as engine.Finding)
            ├─ SBOM             (opaque JSON, if --sbom was used — built)
            ├─ ProvenancePredicate (opaque JSON, if --provenance was used — built)
            └─ AttestationRef   (if the artifact was cosign-attested; store the bundle location, not re-verify it server-side unless asked — not built)
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
2. ~~**Licensing mechanics**~~ — network-gated (shared Basic Auth credential for API/machine access, no license-key logic).
3. **Tech stack** — Go + `database/sql` + `modernc.org/sqlite` (pure-Go, no CGO, so the API's Docker image stays a single static binary) for the API, and Next.js for the dashboard (`portal/web`, a separate Node project/container — the API itself has no frontend templating anymore). The API's Go choice is for consistency with the OSS CLI's own stack; the dashboard moved to Next.js for a real design system instead of `html/template`'s hand-rolled CSS.
4. ~~**Entra ID SSO vs. staying Basic-Auth-only**~~ — built, as real per-user OIDC login (`portal/sso.go`), additive to (not a replacement for) the Basic Auth gate on `/api/scans`. Entra app registration ownership (multi-tenant vs. customer-registered) doesn't need a PolicyForge-side decision at all: since hosting is self-hosted, each customer registers their own app in their own tenant and points their own portal instance at it — there's no shared registration to own.

## Open questions (block the next real increment)

1. **Retention/data residency** — how long are ingested findings (and now sessions, audit events, and any attached SBOM/provenance documents) kept, and does data residency (e.g. EU-only) need to be a per-org setting? Not urgent while this is a single self-hosted SQLite file the customer already controls, but worth deciding before growing past that.
2. **Attestation verification** — the dashboard shows *that* an SBOM/provenance predicate was attached, but never verifies a cosign signature/attestation against it (see the "AttestationRef" line in the sketch data model, still unbuilt) — it's a raw-JSON viewer, not a trust decision.
3. **Multi-tenancy within one deployment** — today `org`/`project` are just free-text tags on a scan row, not real isolation (any logged-in user or Basic-Auth-holder sees every org's data). Worth a real access-control model (e.g. mapping OIDC group/role claims to org access) once more than one org shares a single self-hosted instance.

## Next step

Compliance framework mapping is the last unbuilt item in Scope — rolling
up rule-level findings (already tagged with e.g. "CIS Azure Foundations
3.6") into SOC2/PCI control coverage reports.
