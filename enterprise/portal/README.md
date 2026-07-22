# PolicyForge portal (local prototype)

A runnable, in-memory prototype of the ingestion API + dashboard sketched
in [`../DESIGN.md`](../DESIGN.md). **This is not the real enterprise
product** — no auth, no persistence (data is lost on restart), no
multi-tenant isolation, no license gating. It exists so the `/api/scans`
ingestion shape and dashboard UX can be seen running end to end before the
open architecture questions in `DESIGN.md` (hosting model, licensing
mechanics, tech stack) are settled.

It's a separate Go module (its own `go.mod`) so it never adds to the OSS
CLI's own dependency graph — `go build ./...` at the repo root does not
build or depend on this at all.

## Run it

```bash
cd enterprise/portal
go run . --addr :8090
```

Then, from another terminal, point the CLI at it:

```bash
policyforge scan --path ./examples --upload http://localhost:8090 --org acme --project infra-repo
```

Open `http://localhost:8090` to see the scan list; click a scan to see its
findings, with a severity summary and a per-finding table.

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

## Tests

```bash
cd enterprise/portal
go test ./...
```
