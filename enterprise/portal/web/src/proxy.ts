import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Reverse-proxies /api/*, /login, /auth/callback, and /logout to the Go
// backend, and (in SSO mode) redirects unauthenticated page loads to
// /login. This lives in proxy.ts rather than next.config.ts's
// `rewrites()` deliberately: next.config.ts is evaluated once at Docker
// build time, so BACKEND_INTERNAL_URL read there would get frozen into
// the image instead of reflecting the actual container's runtime
// environment (Docker Compose's internal service hostname, which isn't
// known at build time). Proxy re-reads env vars on every request, so it
// sees the real runtime value.
function backendURL(): string {
  return process.env.BACKEND_INTERNAL_URL || "http://localhost:8090";
}

// AUTH_MODE=sso is the only case this does anything beyond proxying: it
// asks the Go backend (via /api/session, forwarding the session cookie)
// whether the request is logged in, and redirects to /login if not — so
// a page navigation bounces straight to the IdP instead of rendering an
// empty shell first. It's a deliberate no-op for Basic Auth (or no-auth)
// deployments: Basic Auth isn't cookie-based, so there's nothing
// meaningful to check server-side here — the browser's own native
// credential prompt (fired by the 401 + WWW-Authenticate the Go backend
// sends, forwarded through the rewrite below) handles that case on its
// own. Replicating Basic Auth's check here would mean duplicating
// credential comparison in two languages for no real benefit; the Go
// backend is already the actual enforcement point for both modes.
const AUTH_MODE = process.env.AUTH_MODE || "none";

const BACKEND_PATH_PREFIXES = ["/api/", "/login", "/auth/callback", "/logout"];

export async function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;

  if (BACKEND_PATH_PREFIXES.some((p) => pathname === p || pathname.startsWith(p))) {
    return NextResponse.rewrite(new URL(pathname + search, backendURL()));
  }

  if (AUTH_MODE === "sso") {
    let sessionCheck: Response;
    try {
      sessionCheck = await fetch(new URL("/api/session", backendURL()), {
        headers: { cookie: request.headers.get("cookie") ?? "" },
      });
    } catch {
      // Backend unreachable — let the page render and surface the error
      // client-side rather than failing the whole navigation here.
      return NextResponse.next();
    }

    if (sessionCheck.status === 401) {
      return NextResponse.redirect(new URL("/login", request.url));
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon\\.ico).*)"],
};
