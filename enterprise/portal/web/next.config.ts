import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Lets the Dockerfile copy just .next/standalone + static assets
  // instead of the whole node_modules tree into the runtime image.
  output: "standalone",
  // Proxying to the Go backend happens in src/proxy.ts, NOT here via
  // `rewrites()`: next.config.ts is evaluated once at build time, so an
  // env var read here (BACKEND_INTERNAL_URL, which only means anything
  // at container runtime — it's Docker Compose's internal service
  // hostname) gets frozen into the built image instead of reflecting
  // the actual running container's environment. proxy.ts reads it fresh
  // on every request instead.
};

export default nextConfig;
