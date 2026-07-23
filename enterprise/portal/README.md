# PolicyForge portal

A self-hosted PolicyForge enterprise dashboard, split into two pieces:

- **This directory** (`enterprise/portal`, Go): the API — ingestion
  (`POST /api/scans`), read endpoints, auth, and SQLite persistence.
  Nothing here renders HTML.
- **[`web/`](web)** (Next.js): the dashboard UI. A pure frontend that
  calls this API for everything — see `web/README.md` for the design and
  how the two connect.

See [`../DESIGN.md`](../DESIGN.md) for full scope. Two decisions this v1
makes concrete:

- **Self-hosted.** You run this yourself — there is no PolicyForge-operated
  SaaS.
- **Network-gated API access.** No license-key logic anywhere; `/api/scans`
  (the CLI/CI-pipeline ingestion path) is gated by a shared HTTP Basic Auth
  credential. The dashboard itself can additionally require real per-user
  login via OIDC SSO (Entra ID or any other compliant IdP) — see below —
  falling back to that same Basic Auth credential when SSO isn't
  configured.

Both are separate modules (this one its own Go module, `web/` its own
Node project) so neither ever adds to the OSS CLI's own dependency graph —
`go build ./...` at the repo root does not build or depend on either.

## Run both services with Docker Compose (recommended)

```bash
cd enterprise/portal
PORTAL_AUTH_USER=admin PORTAL_AUTH_PASS=<a-real-secret> docker compose up -d
```

This starts the API (port 8090) and the dashboard (port 3000, proxying to
the API over Compose's internal network). Data persists in a named Docker
volume across restarts. **Set both `PORTAL_AUTH_USER`/`PORTAL_AUTH_PASS`
before exposing this beyond localhost** — if either is empty, auth is
disabled entirely.

## Run the API locally without Docker

```bash
cd enterprise/portal
PORTAL_AUTH_USER=admin PORTAL_AUTH_PASS=secret go run . --addr :8090
```

Then run `web/` separately — see `web/README.md`.

## Point the CLI at it

```bash
policyforge scan --path . --upload http://admin:secret@localhost:8090 --org acme --project infra-repo
```

Embed Basic Auth credentials in the `--upload` URL as `user:pass@host`;
omit them (`http://localhost:8090`) if you're running with auth disabled
for local dev. Open the dashboard (`http://localhost:3000` under Docker
Compose) to see the scan list; click a scan to see its findings, with a
severity summary and a per-finding table.

## Dashboard SSO (Entra ID or any OIDC provider)

Set all four of these on the API service to require real per-user login
for the dashboard (`/api/scans` keeps using Basic Auth regardless), **and**
set `AUTH_MODE=sso` on the `web` service (docker-compose.yml already wires
this through):

```bash
OIDC_ISSUER_URL=https://login.microsoftonline.com/<tenant-id>/v2.0   # Entra ID; any OIDC issuer works
OIDC_CLIENT_ID=<application (client) ID>
OIDC_CLIENT_SECRET=<a client secret>
OIDC_REDIRECT_URL=https://<dashboard's public URL>/auth/callback
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

`POST /api/scans` — ingest (Basic Auth):

```json
{
  "org": "acme",
  "project": "infra-repo",
  "findings": [ /* the same array internal/engine.ToJSON produces */ ]
}
```

Response: `{"id": 1, "url": "/scans/1"}`.

`GET /api/scans` — list (Basic Auth or SSO session): an array of scan
summaries (`id`, `org`, `project`, `createdAt`, `severityCounts`, `total`).

`GET /api/scans/{id}` — detail (same auth): a summary plus the full
`findings` array.

`GET /api/session` — `{"authenticated": true, "email": "...", "name": "..."}`
if the caller is authenticated (email/name only present under SSO); used
by `web/`'s proxy and header to know who's logged in.

## Configuration

| Flag | Env var | Default | Purpose |
|---|---|---|---|
| `--addr` | — | `:8090` | Address to listen on |
| `--db` | `PORTAL_DB_PATH` | `portal.db` | SQLite database file path |
| `--auth-user` | `PORTAL_AUTH_USER` | *(empty)* | Basic Auth username for `/api/scans` (and the dashboard read API, if SSO isn't configured); empty disables auth |
| `--auth-pass` | `PORTAL_AUTH_PASS` | *(empty)* | Basic Auth password; empty disables auth |
| `--oidc-issuer-url` | `OIDC_ISSUER_URL` | *(empty)* | OIDC issuer URL for dashboard SSO |
| `--oidc-client-id` | `OIDC_CLIENT_ID` | *(empty)* | OIDC client ID |
| `--oidc-client-secret` | `OIDC_CLIENT_SECRET` | *(empty)* | OIDC client secret |
| `--oidc-redirect-url` | `OIDC_REDIRECT_URL` | *(empty)* | OIDC redirect URL, e.g. `http://localhost:3000/auth/callback` (the dashboard's URL, not the API's — see `web/README.md`) |

`web/`'s own configuration (`BACKEND_INTERNAL_URL`, `AUTH_MODE`) is
documented in `web/README.md`.

## Tests

```bash
cd enterprise/portal
go test ./...

cd web
npm run build   # includes the TypeScript check
npm run lint
```
