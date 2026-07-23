# PolicyForge portal — dashboard (Next.js)

The dashboard UI for the [self-hosted portal](../README.md). This is a
pure frontend: every piece of data (scans, findings, who's logged in) and
every auth decision comes from the Go API in `..` (`enterprise/portal`) —
this app never talks to a database or an IdP directly. See
`src/proxy.ts` for exactly how the two connect.

## Design

A "temper colors" system — the interference-color film that forms on
steel as it's heated during tempering (straw, gold, purple, blue), the
same physical process the product's name ("Forge") points at. Severity is
the one place saturated color does real work (critical → low escalates
like steel visibly getting hotter); nothing else borrows that
saturation, so severity stays legible as signal rather than decoration.
The signature element is the segmented severity-spectrum bar (see
`src/components/SeverityBar.tsx`), which encodes a scan's real severity
distribution rather than just decorating a stat-tile grid.

## Run it

Point it at a running `enterprise/portal` API (see its README):

```bash
cd enterprise/portal/web
BACKEND_INTERNAL_URL=http://localhost:8090 npm run dev
```

Or via Docker Compose from `enterprise/portal/` (runs both services
together — see that directory's `docker-compose.yml`):

```bash
cd enterprise/portal
PORTAL_AUTH_USER=admin PORTAL_AUTH_PASS=<a-real-secret> docker compose up -d
```

## How the two services connect

`src/proxy.ts` reverse-proxies `/api/*`, `/login`, `/auth/callback`, and
`/logout` to the Go backend (`BACKEND_INTERNAL_URL` — Docker Compose's
internal service address in production), so the **browser only ever
talks to this Next.js server** — cookies and Basic Auth challenges stay
same-origin, and nothing about auth is reimplemented here.

This lives in `proxy.ts` rather than `next.config.ts`'s `rewrites()`
deliberately: `next.config.ts` is evaluated once at Docker build time, so
an env var read there would get frozen into the built image instead of
reflecting the container's actual runtime environment. `proxy.ts` reads
`BACKEND_INTERNAL_URL` fresh on every request — this was a real bug
caught while verifying the Docker Compose deployment (the build had
baked in the `localhost` fallback instead of the runtime
`http://portal:8090`), not a hypothetical concern.

Set `AUTH_MODE=sso` (alongside the Go backend's `OIDC_*` config) to have
`proxy.ts` also redirect unauthenticated page loads straight to `/login`.
Leave it unset for Basic-Auth-only deployments: Basic Auth isn't
cookie-based, so there's nothing for a server-side check to do — the
browser's own native credential prompt (triggered by the 401 +
`WWW-Authenticate` the Go backend sends, forwarded through the same
reverse proxy) handles that case on its own, with no help needed from
this app.

## Tests / checks

```bash
npm run build   # also runs the TypeScript check
npm run lint
```
