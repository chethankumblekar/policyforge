# PolicyForge portal

A self-hosted PolicyForge enterprise dashboard: an ingestion API
(`POST /api/scans`) plus a small dashboard UI, backed by a local SQLite
file. See [`../DESIGN.md`](../DESIGN.md) for full scope. Two decisions
this v1 makes concrete:

- **Self-hosted.** You run this yourself — there is no PolicyForge-operated
  SaaS.
- **Network-gated access.** No license-key logic anywhere; access is
  whoever has the URL and the shared HTTP Basic Auth credential below.
  Per-user accounts (Entra ID SSO) are a planned fast-follow, not built.

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
| `--auth-user` | `PORTAL_AUTH_USER` | *(empty)* | Basic Auth username; empty disables auth |
| `--auth-pass` | `PORTAL_AUTH_PASS` | *(empty)* | Basic Auth password; empty disables auth |

## Tests

```bash
cd enterprise/portal
go test ./...
```
