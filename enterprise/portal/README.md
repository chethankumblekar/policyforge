# PolicyForge portal

A self-hosted PolicyForge enterprise dashboard: an ingestion API
(`POST /api/scans`) plus a small dashboard UI, backed by a local SQLite
file. See [`../DESIGN.md`](../DESIGN.md) for full scope. Two decisions
this v1 makes concrete:

- **Self-hosted.** You run this yourself — there is no PolicyForge-operated
  SaaS.
- **Network-gated API access.** No license-key logic anywhere; `/api/scans`
  (the CLI/CI-pipeline ingestion path) is gated by a shared HTTP Basic Auth
  credential. The dashboard itself can additionally require real per-user
  login via OIDC SSO (Entra ID or any other compliant IdP) — see below —
  falling back to that same Basic Auth credential when SSO isn't
  configured.

It's a separate Go module (its own `go.mod`) so it never adds to the OSS
CLI's own dependency graph — `go build ./...` at the repo root does not
build or depend on this at all.

## Run it with Docker Compose (recommended)

```bash
cd enterprise/portal
PORTAL_AUTH_USER=admin PORTAL_AUTH_PASS=<a-real-secret> docker compose up -d
```

Data persists in a named Docker volume across restarts. **Set both
`PORTAL_AUTH_USER`/`PORTAL_AUTH_PASS` before exposing this beyond
localhost** — if either is empty, auth is disabled entirely.

## Run it locally without Docker

```bash
cd enterprise/portal
PORTAL_AUTH_USER=admin PORTAL_AUTH_PASS=secret go run . --addr :8090
```

## Point the CLI at it

```bash
policyforge scan --path . --upload http://admin:secret@localhost:8090 --org acme --project infra-repo
```

Embed Basic Auth credentials in the `--upload` URL as `user:pass@host`;
omit them (`http://localhost:8090`) if you're running with auth disabled
for local dev. Open `http://localhost:8090` to see the scan list; click a
scan to see its findings, with a severity summary and a per-finding table.

## Dashboard SSO (Entra ID or any OIDC provider)

Set all four of these to require real per-user login for the dashboard
(`/api/scans` keeps using Basic Auth regardless):

```bash
OIDC_ISSUER_URL=https://login.microsoftonline.com/<tenant-id>/v2.0   # Entra ID; any OIDC issuer works
OIDC_CLIENT_ID=<application (client) ID>
OIDC_CLIENT_SECRET=<a client secret>
OIDC_REDIRECT_URL=https://<this portal's public URL>/auth/callback
```

For Entra ID specifically: register an app in **Azure AD → App
registrations**, set its redirect URI to `<OIDC_REDIRECT_URL>`, and create
a client secret under **Certificates & secrets**. Each self-hosted
deployment registers its own app in its own tenant — there's no shared
PolicyForge-side app registration to consent to.

Visiting the dashboard without a session redirects to `/login`, which
redirects to your IdP; a successful login lands back on the scan list
showing who's logged in, with a **Logout** link. Sessions are stored in
the same SQLite file as scans, so they survive a portal restart.

## API

`POST /api/scans` — body:

```json
{
  "org": "acme",
  "project": "infra-repo",
  "findings": [ /* the same array internal/engine.ToJSON produces */ ]
}
```

Response: `{"id": 1, "url": "/scans/1"}`.

## Configuration

| Flag | Env var | Default | Purpose |
|---|---|---|---|
| `--addr` | — | `:8090` | Address to listen on |
| `--db` | `PORTAL_DB_PATH` | `portal.db` | SQLite database file path |
| `--auth-user` | `PORTAL_AUTH_USER` | *(empty)* | Basic Auth username for `/api/scans` (and the dashboard, if SSO isn't configured); empty disables auth |
| `--auth-pass` | `PORTAL_AUTH_PASS` | *(empty)* | Basic Auth password; empty disables auth |
| `--oidc-issuer-url` | `OIDC_ISSUER_URL` | *(empty)* | OIDC issuer URL for dashboard SSO |
| `--oidc-client-id` | `OIDC_CLIENT_ID` | *(empty)* | OIDC client ID |
| `--oidc-client-secret` | `OIDC_CLIENT_SECRET` | *(empty)* | OIDC client secret |
| `--oidc-redirect-url` | `OIDC_REDIRECT_URL` | *(empty)* | OIDC redirect URL, e.g. `http://localhost:8090/auth/callback` |

## Tests

```bash
cd enterprise/portal
go test ./...
```
